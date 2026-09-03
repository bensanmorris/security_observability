"""
fleet_fips_rollout.py -- Fleet-wide FIPS 140-2/140-3 rollout view, bundled
into the test-server console alongside fleet_blast_radius.py /
fleet_chain_explorer.py.

cert-analyzer's own `tls_certificate_fips_compliant` gauge already judges
each certificate's own key/signature algorithms against FIPS 140-2/140-3
(see agent/fips_compliance_checker.py), and `tls_certificate_negotiated_protocol`
already records the TLS protocol/cipher actually negotiated during a
bind-probe or connect-probe handshake. Both are scraped per node with no
agent changes needed -- this module only aggregates and cross-checks data
cert-analyzer is already publishing.

The cross-check this module adds that neither existing metric answers alone:
a certificate can be FIPS-compliant on its own (approved key type/size/curve/
hash) while the *live TLS session* still negotiates a non-approved cipher --
e.g. an OpenSSL 3 provider silently falling back to a non-FIPS cipher when no
approved one is available, rather than failing the handshake outright. This
is exactly the "silent fallback" failure mode described in the FIPS 140-3
migration literature: undetectable by a build-time or CI check, since it only
manifests on a live connection. `_negotiation_is_approved` below flags it as
"cipher drift" -- distinct from, and independent of, each certificate's own
fips_compliant judgement.

Groups by `node_name` -- the best available migration-cohort axis from
existing labels (no per-runtime/per-language data is captured today) --
giving a live version of the "which hosts have finished migrating" rollout
view that FIPS migrations otherwise track by hand.

Reuses fleet_blast_radius._fetch_fleet_certs / _fetch_fleet_process_pairings
(via `import fleet_blast_radius`) for the base cert inventory and process
attribution, and blast_radius's PAGE_CSS / _esc / _prom_query, rather than
re-fetching or re-styling from scratch -- see fleet_blast_radius.py's own
docstring for why importing beats copy-pasting a third time. Keeps the same
`generate(prometheus_url) -> str` contract as the other generated pages so
server.py wires this in with nothing more than a new import + elif branch.
"""
import blast_radius
import fleet_blast_radius

# NIST SP 800-52 Rev. 2 approved TLS 1.3 cipher suites. ChaCha20-Poly1305 is
# deliberately excluded -- not FIPS-approved regardless of TLS version.
_APPROVED_TLS13_CIPHERS = frozenset({
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_CCM_SHA256",
})

# OpenSSL cipher-suite names (as returned by ssl.SSLSocket.cipher()) for the
# AES-GCM/AES-CBC + SHA256/384 combinations NIST SP 800-52 Rev. 2 approves
# for TLS 1.2, with ECDHE/DHE/RSA key exchange only. Deliberately an
# allowlist, not a denylist of known-bad ciphers (3DES/RC4/MD5/EXPORT/NULL/
# CBC-SHA1/PSK/CHACHA20) -- an unrecognized cipher name is treated as
# unapproved rather than silently passed, since a security tool's default
# posture should be to flag the unfamiliar case, not wave it through.
_APPROVED_TLS12_CIPHERS = frozenset({
    "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES128-SHA256", "ECDHE-ECDSA-AES256-SHA384",
    "AES128-GCM-SHA256", "AES256-GCM-SHA384",
    "AES128-SHA256", "AES256-SHA256",
})

_APPROVED_PROTOCOLS = frozenset({"TLSv1.2", "TLSv1.3"})

EXTRA_CSS = """
.overview-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 12px; max-width: 1100px;
}
.drift-badge {
  display: inline-block; margin-left: 6px; padding: 1px 6px; border-radius: 4px;
  border: 1px solid var(--critical); color: var(--critical);
  font-size: 0.7rem; font-weight: 600; vertical-align: middle;
}
.ok-badge {
  display: inline-block; margin-left: 6px; padding: 1px 6px; border-radius: 4px;
  border: 1px solid var(--good); color: var(--good);
  font-size: 0.7rem; font-weight: 600; vertical-align: middle;
}
.unknown-badge {
  display: inline-block; margin-left: 6px; padding: 1px 6px; border-radius: 4px;
  border: 1px solid var(--muted); color: var(--muted);
  font-size: 0.7rem; font-weight: 600; vertical-align: middle;
}
.member-table { border-collapse: collapse; margin: 0.5rem 0 1.25rem; font-size: 0.82rem; }
.member-table th, .member-table td {
  border-bottom: 1px solid var(--border); padding: 4px 10px; text-align: left;
}
.member-table th { color: var(--secondary); font-weight: 600; }
.summary-bar { color: var(--secondary); font-size: 0.85rem; margin: 0 0 1.5rem; }
"""

SCRIPT = """
function showDetail(idx) {
  document.getElementById('overview').style.display = 'none';
  document.getElementById('detail-header').style.display = 'flex';
  document.querySelectorAll('.detail').forEach(function (d) { d.style.display = 'none'; });
  document.getElementById('detail-' + idx).style.display = 'block';
}
function showOverview() {
  document.getElementById('overview').style.display = 'grid';
  document.getElementById('detail-header').style.display = 'none';
  document.querySelectorAll('.detail').forEach(function (d) { d.style.display = 'none'; });
}
showOverview();
"""


def _negotiation_is_approved(protocol, cipher):
    """True only for a protocol/cipher combination NIST SP 800-52 Rev. 2
    approves for FIPS 140-2/140-3 use. An unrecognized cipher name is
    treated as unapproved (see _APPROVED_TLS12_CIPHERS docstring above)."""
    if protocol not in _APPROVED_PROTOCOLS:
        return False
    if protocol == "TLSv1.3":
        return cipher in _APPROVED_TLS13_CIPHERS
    return cipher in _APPROVED_TLS12_CIPHERS


def _fetch_fleet_fips(base_url, certs):
    """Populates each cert entry (keyed as in fleet_blast_radius._fetch_fleet_certs)
    with its own FIPS judgement. A cert with no matching series here had
    fips_checked=False on its node (fips_compliance_enabled=false there) --
    left as fips_compliant=None (unknown), distinct from a False judgement,
    so a node with FIPS checking disabled doesn't read as "compliant" by
    the absence of any violation."""
    results = blast_radius._prom_query(base_url, "tls_certificate_fips_compliant")
    for r in results:
        m = r["metric"]
        key = (m.get("cert_path", ""), m.get("cert_index", "0"), m.get("node_name", ""), m.get("serial", ""))
        if key not in certs:
            continue
        certs[key]["fips_compliant"] = float(r["value"][1]) == 1.0
        certs[key]["key_algorithm"] = m.get("key_algorithm", "")
        certs[key]["signature_hash"] = m.get("signature_hash", "")
        certs[key]["key_size"] = m.get("key_size", "")
        certs[key]["curve_name"] = m.get("curve_name", "")


def _fetch_fleet_negotiated(base_url, certs):
    """Populates each cert entry with the list of distinct (protocol, cipher,
    process) combinations observed live on that node -- only ever
    non-empty for TLS-probed endpoints (bind_probe_enabled/connect_probe_enabled),
    since file-discovered certificates have no live connection to negotiate."""
    results = blast_radius._prom_query(base_url, "tls_certificate_negotiated_protocol")
    for r in results:
        m = r["metric"]
        key = (m.get("cert_path", ""), m.get("cert_index", "0"), m.get("node_name", ""), m.get("serial", ""))
        if key not in certs:
            continue
        protocol = m.get("protocol", "")
        cipher = m.get("cipher", "")
        certs[key]["negotiations"].append({
            "protocol": protocol,
            "cipher": cipher,
            "process": m.get("process", "?"),
            "approved": _negotiation_is_approved(protocol, cipher),
        })


def _build_node_stats(all_certs):
    """Groups certs by node_name -- the migration-cohort axis -- and rolls
    up compliance/drift counts per node."""
    nodes = {}
    for cert in all_certs.values():
        node = nodes.setdefault(cert["node_name"], {
            "certs": [], "compliant": 0, "non_compliant": 0, "unknown": 0,
            "negotiations_total": 0, "negotiations_drift": 0,
        })
        node["certs"].append(cert)
        if cert["fips_compliant"] is True:
            node["compliant"] += 1
        elif cert["fips_compliant"] is False:
            node["non_compliant"] += 1
        else:
            node["unknown"] += 1
        for neg in cert["negotiations"]:
            node["negotiations_total"] += 1
            if not neg["approved"]:
                node["negotiations_drift"] += 1
    return nodes


def _node_status(node):
    """critical: at least one non-compliant cert or one drifted negotiation
    (a drifted negotiation is arguably worse -- it's live non-FIPS traffic
    hiding behind a compliant certificate, the "silent fallback" case this
    view exists to catch). warning: nothing failed outright, but some certs
    have no FIPS judgement (checking disabled on this node) so the node's
    true compliance is unknown, not confirmed good. good: otherwise."""
    if node["non_compliant"] or node["negotiations_drift"]:
        return "critical"
    if node["unknown"]:
        return "warning"
    return "good"


def _render_cert_row(cert):
    if cert["fips_compliant"] is True:
        status = '<span class="ok-badge">compliant</span>'
    elif cert["fips_compliant"] is False:
        status = '<span class="drift-badge">non-compliant</span>'
    else:
        status = '<span class="unknown-badge">unchecked</span>'
    return (
        f'<tr><td>{blast_radius._esc(cert["common_name"])}</td>'
        f'<td>{blast_radius._esc(cert["cert_path"])}</td>'
        f'<td>{status}</td>'
        f'<td>{blast_radius._esc(cert.get("key_algorithm", ""))}</td>'
        f'<td>{blast_radius._esc(cert.get("key_size", ""))}</td>'
        f'<td>{blast_radius._esc(cert.get("curve_name", ""))}</td>'
        f'<td>{blast_radius._esc(cert.get("signature_hash", ""))}</td></tr>'
    )


def _render_negotiation_row(cert, neg):
    badge = '<span class="ok-badge">approved</span>' if neg["approved"] else '<span class="drift-badge">non-FIPS</span>'
    return (
        f'<tr><td>{blast_radius._esc(cert["common_name"])}</td>'
        f'<td>{blast_radius._esc(neg["process"])}</td>'
        f'<td>{blast_radius._esc(neg["protocol"])}</td>'
        f'<td>{blast_radius._esc(neg["cipher"])}</td>'
        f'<td>{badge}</td></tr>'
    )


def _render_node_card(node_name, node, idx):
    status = _node_status(node)
    total_judged = node["compliant"] + node["non_compliant"]
    ratio = f'{node["compliant"]}/{total_judged}' if total_judged else "no data"
    bits = [f'{ratio} certs compliant']
    if node["unknown"]:
        bits.append(f'{node["unknown"]} unchecked')
    if node["negotiations_drift"]:
        bits.append(f'{node["negotiations_drift"]}/{node["negotiations_total"]} sessions non-FIPS')
    elif node["negotiations_total"]:
        bits.append(f'{node["negotiations_total"]} session(s) all approved')
    return (
        f'<div class="cert-card" onclick="showDetail({idx})">'
        f'<span class="cert-dot" style="background: var(--{status})"></span>'
        f'<div><div class="cert-name">{blast_radius._esc(node_name)}</div>'
        f'<div class="cert-meta">{blast_radius._esc(" &middot; ".join(bits))}</div>'
        f'</div></div>'
    )


def _render_node_detail(node_name, node, idx):
    cert_rows = "".join(_render_cert_row(c) for c in sorted(node["certs"], key=lambda c: c["cert_path"]))
    cert_table = (
        '<table class="member-table"><thead><tr><th>Common name</th><th>Path</th>'
        '<th>FIPS status</th><th>Key alg</th><th>Key size</th><th>Curve</th>'
        '<th>Sig hash</th></tr></thead>'
        f'<tbody>{cert_rows}</tbody></table>'
    )

    neg_rows = "".join(
        _render_negotiation_row(c, n) for c in node["certs"] for n in c["negotiations"]
    )
    neg_section = ""
    if neg_rows:
        neg_section = (
            '<h3>Negotiated TLS sessions</h3>'
            '<table class="member-table"><thead><tr><th>Common name</th><th>Process</th>'
            '<th>Protocol</th><th>Cipher</th><th>Status</th></tr></thead>'
            f'<tbody>{neg_rows}</tbody></table>'
        )
    else:
        neg_section = (
            '<p class="note">No live TLS negotiations observed on this node -- enable '
            '<code>bind_probe_enabled</code> / <code>connect_probe_enabled</code> to capture '
            'the actual negotiated protocol/cipher, not just each certificate\'s own algorithm.</p>'
        )

    return (
        f'<div class="detail" id="detail-{idx}">'
        f'<div class="detail-title">{blast_radius._esc(node_name)}</div>'
        f'<div class="detail-subtitle">{len(node["certs"])} certificate(s) &middot; '
        f'{node["compliant"]} compliant &middot; {node["non_compliant"]} non-compliant &middot; '
        f'{node["unknown"]} unchecked</div>'
        f'<h3>Certificates</h3>'
        f'{cert_table}'
        f'{neg_section}'
        f'</div>'
    )


def _render_page(all_certs, nodes):
    total_certs = len(all_certs)
    total_compliant = sum(n["compliant"] for n in nodes.values())
    total_non_compliant = sum(n["non_compliant"] for n in nodes.values())
    total_drift = sum(n["negotiations_drift"] for n in nodes.values())
    total_negotiations = sum(n["negotiations_total"] for n in nodes.values())

    ordered = sorted(
        nodes.items(),
        key=lambda kv: (0 if _node_status(kv[1]) == "critical" else 1 if _node_status(kv[1]) == "warning" else 2, kv[0]),
    )
    cards = []
    details = []
    for idx, (node_name, node) in enumerate(ordered):
        cards.append(_render_node_card(node_name, node, idx))
        details.append(_render_node_detail(node_name, node, idx))

    summary = (
        f'{len(nodes)} node(s) &middot; {total_certs} certificate(s) &middot; '
        f'{total_compliant} compliant &middot; {total_non_compliant} non-compliant &middot; '
        f'{total_negotiations} negotiated session(s) observed'
        + (f' &middot; {total_drift} negotiated a non-FIPS cipher' if total_negotiations else '')
    )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Fleet FIPS Rollout</title>
<style>{blast_radius.PAGE_CSS}{EXTRA_CSS}</style>
</head>
<body>
<p><a href="/">&larr; Back to test console</a></p>
<h1>Fleet FIPS Rollout</h1>
<p class="subtitle">Grouped by node &mdash; click a node to see every certificate's FIPS judgement and, where captured, the actual negotiated TLS protocol/cipher</p>
<p class="summary-bar">{summary}</p>
<p class="note">A certificate can be individually FIPS-compliant while a live session on the same node still negotiates a non-approved cipher (e.g. a provider silently falling back when no approved cipher is available) &mdash; that combination is flagged here as a critical node even when every certificate passes on its own. Negotiated protocol/cipher data only exists for nodes with <code>bind_probe_enabled</code> / <code>connect_probe_enabled</code> on.</p>

<div id="overview" class="overview-grid">{"".join(cards)}</div>

<div id="detail-header">
  <button id="back-btn" onclick="showOverview()">&larr; All nodes</button>
</div>
{"".join(details)}

<script>{SCRIPT}</script>
</body>
</html>
"""


def generate(prometheus_url):
    """Query Prometheus and return the rendered fleet FIPS-rollout HTML page
    as a str. Same contract as the other fleet_*.generate functions: raises
    RuntimeError if no certificates are currently exposed, and propagates any
    underlying urllib/JSON error from a bad or unreachable Prometheus URL --
    callers (server.py) turn both into a clean HTTP error."""
    all_certs = fleet_blast_radius._fetch_fleet_certs(prometheus_url)
    if not all_certs:
        raise RuntimeError(
            "No tls_certificate_expiry_days series found at "
            f"{prometheus_url} -- is cert-analyzer running and scraped?"
        )
    for cert in all_certs.values():
        cert["fips_compliant"] = None
        cert["negotiations"] = []
    fleet_blast_radius._fetch_fleet_process_pairings(prometheus_url, all_certs)
    _fetch_fleet_fips(prometheus_url, all_certs)
    _fetch_fleet_negotiated(prometheus_url, all_certs)
    nodes = _build_node_stats(all_certs)
    return _render_page(all_certs, nodes)
