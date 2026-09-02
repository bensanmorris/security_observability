"""
fleet_blast_radius.py -- Fleet-wide (multi-node) certificate blast-radius
explorer, bundled into the test-server console alongside blast_radius.py.

blast_radius.py groups by (cert_path, cert_index), which only makes sense
for one host: the same physical certificate deployed on many nodes would
fragment into one "blast radius" per node instead of showing the true
fleet-wide impact of rotating it. This module groups by certificate
*identity* instead -- `checksum` (SHA-256 of the DER cert; identical only
for byte-for-byte the same cert) or `spki_hash` (SHA-256 of the public key
alone; identical across a renewal that reuses the same key pair) -- so the
same cert/key deployed across the fleet collapses into one group. Both
labels are already exposed by cert-analyzer's own metrics (see
extras/FIELDS-README.md); no new instrumentation is needed.

Reuses blast_radius.py's private helpers (_prom_query, PAGE_CSS,
_status_bucket, _days_label, _esc, _assign_namespace_colors,
_render_detail_svg) via `import blast_radius` rather than copy-pasting them
a third time -- blast_radius.py is already a hand-synced copy of
extras/cert_blast_radius.py, and copying its primitives again here would
add a third place to keep in sync by hand.

Deliberately keeps the same `generate(prometheus_url) -> str` contract as
blast_radius.generate, so server.py wires this in with nothing more than a
new import + elif branch (see _serve_generated_page in server.py). The
"jump to a specific checksum/spki_hash" lookup is implemented entirely in
client-side JS against the already-rendered page rather than as a server
query param -- that keeps the one-arg contract intact and means a pasted
hash value never reaches Prometheus as a query, so there's no PromQL-
injection surface to validate against in the first place.
"""
import blast_radius

# checksum is disabled by default (CERT_CHECKSUM_ENABLED=false); spki_hash
# is enabled by default. A fleet can easily have inconsistent coverage
# (staggered rollout, mixed config) -- certs missing the selected label are
# excluded from that dimension's grouping rather than lumped into one false
# "shared" bucket under the empty string, and the exclusion count is
# surfaced in the page rather than silently understating the blast radius.
GROUPING_DIMENSIONS = ("spki_hash", "checksum")

# A checksum/key shared across hundreds of nodes (a company-wide root, or a
# widely-deployed wildcard cert) is exactly the headline case this tool
# exists to surface -- and exactly the case where an uncapped radial layout
# of one spoke per leaf becomes an unreadable hairball. Cap the diagram and
# fall back to the full member table underneath it.
SVG_LEAF_CAP = 50

EXTRA_CSS = """
.overview-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 12px; max-width: 1100px;
}
#mode-toggle { display: flex; gap: 8px; margin: 0 0 1rem; }
.mode-btn {
  background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
  padding: 6px 14px; font-size: 0.85rem; cursor: pointer; color: var(--secondary);
}
.mode-btn.active { color: var(--primary); border-color: var(--primary); font-weight: 600; }
.mode-btn:hover { border-color: var(--muted); }
.checksum-badge {
  display: inline-block; margin-left: 6px; padding: 1px 6px; border-radius: 4px;
  border: 1px solid var(--warning); color: var(--warning);
  font-size: 0.7rem; font-weight: 600; vertical-align: middle;
}
#lookup { display: flex; gap: 8px; align-items: center; margin: 0 0 1.5rem; }
#lookup input {
  flex: 1; max-width: 420px; padding: 6px 10px; border: 1px solid var(--border);
  border-radius: 6px; background: var(--surface); color: var(--primary); font-size: 0.85rem;
}
#lookup button {
  background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
  padding: 6px 12px; font-size: 0.85rem; cursor: pointer; color: var(--primary);
}
.member-table { border-collapse: collapse; margin: 0.5rem 0 1.25rem; font-size: 0.82rem; }
.member-table th, .member-table td {
  border-bottom: 1px solid var(--border); padding: 4px 10px; text-align: left;
}
.member-table th { color: var(--secondary); font-weight: 600; }
"""

# %s -> the default grouping dimension, so the page opens on whichever
# dimension actually has data rather than a hardcoded choice.
SCRIPT_TEMPLATE = """
var currentMode = '%s';

function setMode(mode) {
  currentMode = mode;
  ['checksum', 'spki_hash'].forEach(function (m) {
    document.getElementById('overview-' + m).style.display = (m === mode) ? 'block' : 'none';
    document.getElementById('mode-btn-' + m).classList.toggle('active', m === mode);
  });
  document.getElementById('detail-header').style.display = 'none';
  document.getElementById('legend').style.display = 'none';
  document.querySelectorAll('.detail').forEach(function (d) { d.style.display = 'none'; });
}

function showDetail(mode, idx) {
  currentMode = mode;
  ['checksum', 'spki_hash'].forEach(function (m) {
    document.getElementById('overview-' + m).style.display = 'none';
  });
  document.getElementById('detail-header').style.display = 'flex';
  document.getElementById('legend').style.display = 'flex';
  document.querySelectorAll('.detail').forEach(function (d) { d.style.display = 'none'; });
  var el = document.getElementById('detail-' + mode + '-' + idx);
  if (el) { el.style.display = 'block'; }
}

function showOverview() {
  setMode(currentMode);
}

function jumpToValue(mode, value) {
  var cards = document.querySelectorAll('.cert-card[data-mode="' + mode + '"]');
  for (var i = 0; i < cards.length; i++) {
    var v = cards[i].getAttribute('data-value');
    if (v === value || v.indexOf(value) === 0) {
      showDetail(mode, cards[i].getAttribute('data-idx'));
      return true;
    }
  }
  return false;
}

function lookup() {
  var raw = document.getElementById('lookup-input').value.trim().toLowerCase();
  if (!raw) { return; }
  var other = currentMode === 'checksum' ? 'spki_hash' : 'checksum';
  if (!jumpToValue(currentMode, raw) && !jumpToValue(other, raw)) {
    alert('No group matching "' + raw + '" found on this page.');
  }
}

function handleHash() {
  var h = location.hash.replace(/^#/, '');
  var m = h.match(/^(checksum|spki_hash)=([0-9a-f]+)$/i);
  if (m) {
    setMode(m[1]);
    jumpToValue(m[1], m[2].toLowerCase());
  } else {
    setMode(currentMode);
  }
}

handleHash();
"""


def _fetch_fleet_certs(base_url):
    """One entry per (cert_path, cert_index, node_name, serial).

    Unlike blast_radius._fetch_all_certs's (cert_path, cert_index) key,
    node_name and serial are included here: the same cert_path is expected
    to recur across many nodes fleet-wide, and the 2-tuple key would
    silently collide across nodes and drop data.
    """
    results = blast_radius._prom_query(base_url, "tls_certificate_expiry_days")
    certs = {}
    for r in results:
        m = r["metric"]
        key = (m.get("cert_path", ""), m.get("cert_index", "0"), m.get("node_name", ""), m.get("serial", ""))
        certs[key] = {
            "common_name": m.get("common_name") or m.get("subject") or m.get("cert_path") or "certificate",
            "serial": m.get("serial", ""),
            "cert_path": m.get("cert_path", ""),
            "cert_index": m.get("cert_index", "0"),
            "node_name": m.get("node_name", "?"),
            "days_left": float(r["value"][1]),
            "checksum": m.get("checksum", ""),
            "spki_hash": m.get("spki_hash", ""),
            "leaves": [],
        }
    return certs


def _fetch_fleet_process_pairings(base_url, certs):
    results = blast_radius._prom_query(base_url, "tls_certificate_process_info")
    for r in results:
        m = r["metric"]
        key = (m.get("cert_path", ""), m.get("cert_index", "0"), m.get("node_name", ""), m.get("serial", ""))
        if key not in certs:
            continue  # process-info series with no matching expiry series -- shouldn't normally happen
        certs[key]["leaves"].append({
            "process": m.get("process", "?"),
            "node_name": m.get("node_name", "?"),
            "pod_name": m.get("pod_name", ""),
            "namespace": m.get("namespace", ""),
        })


def _coverage_counts(all_certs):
    return {
        "checksum": sum(1 for c in all_certs.values() if c["checksum"]),
        "spki_hash": sum(1 for c in all_certs.values() if c["spki_hash"]),
    }


def _group_by(all_certs, dimension):
    """Buckets certs sharing the same checksum/spki_hash value into one
    blast-radius group. Certs with an empty value for `dimension` (that
    flag disabled on their node) are skipped -- see the `excluded` count
    returned, surfaced in the page rather than silently dropped.

    Leaves merged from multiple contributing certs are deduped by
    (process, node_name, pod_name, namespace): a key-preserving renewal
    briefly leaves both the old and new cert_index's series alive in
    Prometheus at once, which would otherwise show the same process/pod
    twice in the same group purely due to rotation timing.
    """
    groups = {}
    excluded = 0
    for cert in all_certs.values():
        value = cert[dimension]
        if not value:
            excluded += 1
            continue
        group = groups.setdefault(value, {"members": [], "leaves": [], "days_left": None, "_leaf_keys": set()})
        group["members"].append(cert)
        if group["days_left"] is None or cert["days_left"] < group["days_left"]:
            group["days_left"] = cert["days_left"]
        for leaf in cert["leaves"]:
            leaf_key = (leaf["process"], leaf["node_name"], leaf["pod_name"], leaf["namespace"])
            if leaf_key in group["_leaf_keys"]:
                continue
            group["_leaf_keys"].add(leaf_key)
            group["leaves"].append(leaf)
    for group in groups.values():
        del group["_leaf_keys"]
        group["distinct_checksums"] = len({m["checksum"] for m in group["members"] if m["checksum"]})
    return groups, excluded


def _cap_leaves_for_svg(leaves, cap):
    """Selects up to `cap` leaves for the radial SVG, round-robining across
    namespaces so a handful of crowded namespaces don't push everything
    else off the diagram. Returns (selected_leaves, number_dropped)."""
    if len(leaves) <= cap:
        return leaves, 0
    buckets = {}
    for leaf in leaves:
        buckets.setdefault(leaf["namespace"] or "(none)", []).append(leaf)
    bucket_list = list(buckets.values())
    picked = []
    i = 0
    while len(picked) < cap and any(bucket_list):
        bucket = bucket_list[i % len(bucket_list)]
        if bucket:
            picked.append(bucket.pop(0))
        i += 1
    return picked, len(leaves) - len(picked)


def _short_hash(value):
    """Truncates a checksum/spki_hash for table display; an em dash when the
    flag was disabled on that node and the value is empty."""
    if not value:
        return "—"
    return value[:12] + "…" if len(value) > 12 else value


def _render_group_card(dimension, value, group, idx, node_count):
    status = blast_radius._status_bucket(group["days_left"])
    short_value = value[:12] + "…" if len(value) > 12 else value
    if dimension == "checksum":
        name = group["members"][0]["common_name"]
    else:
        name = f'{len(group["members"])} certificate(s) sharing a key'
    badge = (
        f'<span class="checksum-badge">{group["distinct_checksums"]} checksums</span>'
        if dimension == "spki_hash" and group["distinct_checksums"] > 1 else ""
    )
    return (
        f'<div class="cert-card" data-mode="{dimension}" data-idx="{idx}" data-value="{blast_radius._esc(value)}" '
        f'onclick="showDetail(\'{dimension}\', {idx})">'
        f'<span class="cert-dot" style="background: var(--{status})"></span>'
        f'<div><div class="cert-name">{blast_radius._esc(name)}{badge}</div>'
        f'<div class="cert-meta">{blast_radius._esc(blast_radius._days_label(group["days_left"]))} '
        f'&middot; {len(group["members"])} cert(s) &middot; {node_count} node(s) &middot; {blast_radius._esc(short_value)}</div>'
        f'</div></div>'
    )


def _render_group_detail(dimension, value, group, ns_color, idx, node_count):
    svg_leaves, dropped = _cap_leaves_for_svg(group["leaves"], SVG_LEAF_CAP)
    cap_note = (
        f'<p class="note">Showing {len(svg_leaves)} of {len(group["leaves"])} process pairing(s) in the '
        f'diagram below, spread across namespaces for readability &mdash; see the table for the full list.</p>'
        if dropped else ""
    )
    subtitle_bits = [
        f'{len(group["members"])} certificate(s)',
        f'{node_count} node(s)',
        f'{len(group["leaves"])} process pairing(s)',
    ]
    members = sorted(group["members"], key=lambda m: (m["node_name"], m["cert_path"]))

    if dimension == "checksum":
        # checksum hashes the whole DER cert, so every member here is
        # byte-identical -- common_name/serial are guaranteed shared.
        member0 = members[0]
        title = member0["common_name"]
        if member0["serial"]:
            subtitle_bits.append(f'serial {member0["serial"][:16]}')
        rows = "".join(
            f'<tr><td>{blast_radius._esc(m["cert_path"])}</td><td>{blast_radius._esc(m["node_name"])}</td>'
            f'<td>{blast_radius._esc(_short_hash(m["checksum"]))}</td>'
            f'<td>{blast_radius._esc(_short_hash(m["spki_hash"]))}</td></tr>'
            for m in members
        )
        table = (
            '<table class="member-table"><thead><tr><th>Path</th><th>Node</th>'
            '<th>Checksum</th><th>SPKI hash</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
    else:
        # spki_hash only hashes the public key -- members can legitimately
        # be different logical certs/renewals, so there's no single shared
        # identity to headline; list them all instead. Use the actual
        # ellipsis character (not the &hellip; entity) here -- the whole
        # title string is HTML-escaped once more below, which would
        # otherwise turn a literal "&hellip;" into visible "&amp;hellip;".
        title = f'Shared key ({value[:16]}…)'
        rows = "".join(
            f'<tr><td>{blast_radius._esc(m["cert_path"])}</td><td>{blast_radius._esc(m["node_name"])}</td>'
            f'<td>{blast_radius._esc(m["common_name"])}</td><td>{blast_radius._esc(m["serial"][:16])}</td>'
            f'<td>{blast_radius._esc(blast_radius._days_label(m["days_left"]))}</td>'
            f'<td>{blast_radius._esc(_short_hash(m["checksum"]))}</td>'
            f'<td>{blast_radius._esc(_short_hash(m["spki_hash"]))}</td></tr>'
            for m in members
        )
        table = (
            '<table class="member-table"><thead><tr><th>Path</th><th>Node</th><th>Common name</th>'
            '<th>Serial</th><th>Expiry</th><th>Checksum</th><th>SPKI hash</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    return (
        f'<div class="detail" id="detail-{dimension}-{idx}">'
        f'<div class="detail-title">{blast_radius._esc(title)}</div>'
        f'<div class="detail-subtitle">{blast_radius._esc(" · ".join(subtitle_bits))}</div>'
        f'{table}'
        f'{cap_note}'
        f'{blast_radius._render_detail_svg({"leaves": svg_leaves}, ns_color)}'
        f'</div>'
    )


def _render_dimension_section(dimension, groups, excluded, ns_color, display):
    if groups:
        ordered = sorted(groups.items(), key=lambda kv: (kv[1]["days_left"], -len(kv[1]["leaves"])))
        cards = []
        details = []
        for idx, (value, group) in enumerate(ordered):
            node_count = len({m["node_name"] for m in group["members"]})
            cards.append(_render_group_card(dimension, value, group, idx, node_count))
            details.append(_render_group_detail(dimension, value, group, ns_color, idx, node_count))
        grid_html = "".join(cards)
        detail_html = "".join(details)
        empty_note = ""
    else:
        flag = "checksum_enabled" if dimension == "checksum" else "spki_hash_enabled"
        grid_html = ""
        detail_html = ""
        empty_note = (
            f'<p class="note">No certificates report a {dimension} value &mdash; {flag} is false '
            f'on every scraped node.</p>'
        )

    excluded_note = (
        f'<p class="note">{excluded} certificate(s) excluded from this view &mdash; no {dimension} '
        f'reported by their node ({"checksum_enabled" if dimension == "checksum" else "spki_hash_enabled"}=false there).</p>'
        if excluded else ""
    )

    section = (
        f'<div id="overview-{dimension}" style="display: {display}">'
        f'{empty_note}{excluded_note}'
        f'<div class="overview-grid">{grid_html}</div>'
        f'</div>'
    )
    return section, detail_html


def _render_page(all_certs, coverage):
    ns_color = blast_radius._assign_namespace_colors(all_certs)
    default_mode = "checksum" if coverage["checksum"] > coverage["spki_hash"] else "spki_hash"

    sections = []
    detail_blocks = []
    for dimension in GROUPING_DIMENSIONS:
        groups, excluded = _group_by(all_certs, dimension)
        display = "block" if dimension == default_mode else "none"
        section, detail_html = _render_dimension_section(dimension, groups, excluded, ns_color, display)
        sections.append(section)
        detail_blocks.append(detail_html)

    legend_items = sorted((ns, c) for ns, c in ns_color.items() if c != "var(--other)")
    if any(c == "var(--other)" for c in ns_color.values()):
        legend_items.append(("Other", "var(--other)"))
    legend_html = "".join(
        f'<div class="legend-item"><span class="legend-swatch" style="background:{color}"></span>{blast_radius._esc(ns)}</div>'
        for ns, color in legend_items
    )

    checksum_label = (
        f'Checksum ({coverage["checksum"]} certs)' if coverage["checksum"]
        else 'Checksum (0 certs — disabled fleet-wide)'
    )
    spki_label = f'SPKI hash ({coverage["spki_hash"]} certs)' if coverage["spki_hash"] else 'SPKI hash (0 certs)'
    script_js = SCRIPT_TEMPLATE % default_mode

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Fleet Certificate Blast Radius</title>
<style>{blast_radius.PAGE_CSS}{EXTRA_CSS}</style>
</head>
<body>
<p><a href="/">&larr; Back to test console</a></p>
<h1>Fleet Certificate Blast Radius</h1>
<p class="subtitle">{len(all_certs)} certificate instance(s) monitored fleet-wide &middot; grouped by shared certificate identity, not file path &mdash; click a group to see every node, process, and pod affected</p>
<p class="note">Data comes from Prometheus's last scrape of every scraped node's cert-analyzer metrics -- a newly-discovered certificate or process can take up to one scrape interval to show up here.</p>

<div id="mode-toggle">
  <button class="mode-btn" id="mode-btn-spki_hash" onclick="setMode('spki_hash')">{blast_radius._esc(spki_label)}</button>
  <button class="mode-btn" id="mode-btn-checksum" onclick="setMode('checksum')">{blast_radius._esc(checksum_label)}</button>
</div>
<div id="lookup">
  <input type="text" id="lookup-input" placeholder="Paste a checksum or spki_hash to jump to it">
  <button onclick="lookup()">Find</button>
</div>

{"".join(sections)}

<div id="detail-header">
  <button id="back-btn" onclick="showOverview()">&larr; All certificates</button>
</div>
{"".join(detail_blocks)}
<div id="legend">{legend_html}</div>

<script>{script_js}</script>
</body>
</html>
"""


def generate(prometheus_url):
    """Query Prometheus and return the rendered fleet blast-radius HTML page
    as a str. Same contract as blast_radius.generate: raises RuntimeError if
    no certificates are currently exposed, and propagates any underlying
    urllib/JSON error from a bad or unreachable Prometheus URL -- callers
    (server.py) turn both into a clean HTTP error.
    """
    all_certs = _fetch_fleet_certs(prometheus_url)
    _fetch_fleet_process_pairings(prometheus_url, all_certs)
    if not all_certs:
        raise RuntimeError(
            "No tls_certificate_expiry_days series found at "
            f"{prometheus_url} -- is cert-analyzer running and scraped?"
        )
    coverage = _coverage_counts(all_certs)
    return _render_page(all_certs, coverage)
