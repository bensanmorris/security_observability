"""
chain_explorer.py -- Certificate chain explorer, bundled into the test-server
console alongside blast_radius.py.

Groups cert-analyzer's own `tls_certificate_expiry_days` /
`tls_certificate_self_signed` Prometheus metrics by `cert_path`, orders each
bundle by `cert_index` (0 = leaf, per cert-analyzer's own convention), and
renders an interactive, click-through view of every certificate bundle's
chain length and role structure (leaf / intermediate CA / root).

Separately flags a real chain-of-trust misconfiguration: any non-self-signed
cert in a bundle whose issuer doesn't match any other cert's subject. This
check is cross-file: an issuer is first looked for within the same bundle,
then across every other bundle cert-analyzer currently knows about (e.g. a
leaf cert in its own file, with the intermediate/root living separately in
a system CA bundle) -- only an issuer absent from every bundle counts as
genuinely MISSING. A cross-file match is rendered as its own "found
elsewhere" state (clickable through to the bundle that has it), distinct
from a true gap. This mirrors extras/kafka/list_cert_chains.py's detection
logic for the within-file case, but sources from Prometheus's current live
state instead of replaying Kafka's first-time-discovery history, so it
reflects every bundle cert-analyzer currently knows about rather than only
what's been seen since Kafka was enabled.

Stdlib only -- no third-party packages required.
"""
import json
import urllib.parse
import urllib.request

# Shares its visual language (CSS vars, palette, dark/light auto-switching)
# with blast_radius.py -- see that file's PAGE_CSS comment for the palette
# source. Status colors (good/critical) are reserved for chain completeness;
# role (leaf/intermediate/root) is conveyed by label text, not color, since
# role isn't a "categorical identity" in the dataviz-skill sense here.
PAGE_CSS = """
:root {
  color-scheme: light;
  --surface: #fcfcfb; --page: #f9f9f7;
  --primary: #0b0b0b; --secondary: #52514e; --muted: #898781;
  --spoke: #c3c2b7; --border: rgba(11,11,11,0.10);
  --good: #0ca30c; --critical: #d03b3b; --info: #2a78d6;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --surface: #1a1a19; --page: #0d0d0d;
    --primary: #ffffff; --secondary: #c3c2b7; --muted: #898781;
    --spoke: #383835; --border: rgba(255,255,255,0.10);
    --good: #0ca30c; --critical: #d03b3b; --info: #3987e5;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem; background: var(--page); color: var(--primary);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
}
h1 { font-size: 1.4rem; margin: 0 0 0.25rem; }
.subtitle { color: var(--secondary); font-size: 0.9rem; margin: 0 0 0.5rem; }
.note { color: var(--critical); font-size: 0.78rem; font-style: italic; margin: 0 0 1.5rem; }
#overview {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 12px; max-width: 1200px;
}
.chain-card {
  display: flex; align-items: center; gap: 10px; padding: 12px 14px;
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  cursor: pointer;
}
.chain-card:hover { border-color: var(--muted); }
.chain-dot { width: 12px; height: 12px; border-radius: 50%; flex: none; }
.chain-path { font-weight: 600; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, monospace; }
.chain-meta { color: var(--secondary); font-size: 0.78rem; }
.chain-meta.critical { color: var(--critical); font-weight: 600; }
.chain-meta.info { color: var(--info); font-weight: 600; }
#detail-header {
  display: none; align-items: center; gap: 12px; margin-bottom: 1rem;
}
#back-btn {
  background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
  padding: 6px 12px; font-size: 0.85rem; cursor: pointer; color: var(--primary);
}
#back-btn:hover { border-color: var(--muted); }
.detail { display: none; max-width: 1100px; }
.detail-title { font-size: 1.05rem; font-weight: 600; margin: 0 0 0.25rem; font-family: ui-monospace, monospace; }
.detail-subtitle { color: var(--secondary); font-size: 0.85rem; margin: 0 0 1rem; }
.detail-subtitle.critical { color: var(--critical); font-weight: 600; }
.detail-subtitle.info { color: var(--info); font-weight: 600; }
.chain-row { display: flex; flex-wrap: wrap; align-items: center; gap: 0; margin-bottom: 0.5rem; }
.chain-box {
  width: 170px; min-height: 76px; padding: 8px 10px; border-radius: 8px;
  border: 1.5px solid var(--border); background: var(--surface);
  display: flex; flex-direction: column; justify-content: center; gap: 2px;
}
.chain-box.root { border-color: var(--good); border-width: 2px; }
.chain-box.missing {
  border: 1.5px dashed var(--critical); background: transparent;
  color: var(--critical); align-items: center; justify-content: center; text-align: center;
}
.chain-box.resolved {
  border: 1.5px dashed var(--info); background: transparent;
  color: var(--info); align-items: center; justify-content: center; text-align: center;
  cursor: pointer;
}
.chain-box.resolved:hover { background: rgba(42,120,214,0.08); }
.chain-resolved-path {
  font-size: 0.62rem; opacity: 0.85; font-family: ui-monospace, monospace;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 150px;
}
.chain-role { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
.chain-cn { font-size: 0.82rem; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chain-issuer { font-size: 0.72rem; color: var(--secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chain-arrow { width: 28px; text-align: center; color: var(--muted); font-size: 1rem; flex: none; }
"""


def _prom_query(base_url, promql):
    url = f"{base_url.rstrip('/')}/api/v1/query?{urllib.parse.urlencode({'query': promql})}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        payload = json.load(resp)
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus query failed: {payload}")
    return payload["data"]["result"]


def _fetch_bundles(base_url):
    """One bundle per cert_path, one entry per cert_index within it."""
    bundles = {}
    for r in _prom_query(base_url, "tls_certificate_expiry_days"):
        m = r["metric"]
        path = m.get("cert_path", "")
        idx = int(m.get("cert_index", "0"))
        bundles.setdefault(path, {})[idx] = {
            "subject": m.get("subject", ""),
            "issuer": m.get("issuer", ""),
            "common_name": m.get("common_name") or m.get("subject") or "(no subject)",
            "is_self_signed": False,
            "is_ca": "unknown",
        }

    for r in _prom_query(base_url, "tls_certificate_self_signed"):
        m = r["metric"]
        path = m.get("cert_path", "")
        idx = int(m.get("cert_index", "0"))
        entry = bundles.get(path, {}).get(idx)
        if entry is None:
            continue  # self-signed series with no matching expiry series -- shouldn't normally happen
        entry["is_self_signed"] = r["value"][1] == "1"
        entry["is_ca"] = m.get("is_ca", "unknown")

    return bundles


def _find_chain_gaps(path, by_index, subject_index):
    """
    For every non-self-signed cert in this bundle, resolves its issuer
    first against this same bundle, then against every other bundle
    cert-analyzer currently knows about (subject_index). Returns a list of
    (idx, entry, issuer, other_path) -- other_path is None for a genuinely
    unresolvable issuer (MISSING), or the path of the other bundle that
    has it (resolved cross-file).

    Single-cert bundles are only ever reported as cross-file *resolved*,
    never as MISSING: an ordinary leaf cert living in its own file with no
    bundled chain is extremely common, so treating an unresolved issuer as
    MISSING here would flag nearly every standalone leaf cert on the host.
    Cross-file matching only ever adds new resolved (good-news) entries for
    those bundles, never new MISSING (bad-news) ones -- it can only shrink
    the MISSING set (for multi-cert bundles), never grow it.
    """
    within_file_subjects = {entry["subject"] for entry in by_index.values()}
    single_cert_bundle = len(by_index) <= 1
    gaps = []
    for idx in sorted(by_index):
        entry = by_index[idx]
        if entry["is_self_signed"]:
            continue
        issuer = entry["issuer"]
        if not issuer or issuer in within_file_subjects:
            continue
        other_paths = sorted(p for p in subject_index.get(issuer, ()) if p != path)
        if other_paths:
            gaps.append((idx, entry, issuer, other_paths[0]))
        elif not single_cert_bundle:
            gaps.append((idx, entry, issuer, None))
    return gaps


def _role(entry):
    if entry["is_self_signed"]:
        return "root"
    if entry["is_ca"] == "true":
        return "intermediate ca"
    return "leaf"


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _render_chain_row(by_index, missing_by_idx, resolved_by_idx, path_to_row_idx):
    indices = sorted(by_index)
    boxes = []
    for pos, idx in enumerate(indices):
        entry = by_index[idx]
        role = _role(entry)
        cls = "root" if role == "root" else ""
        boxes.append(
            f'<div class="chain-box {cls}">'
            f'<div class="chain-role">{_esc(role)}</div>'
            f'<div class="chain-cn">{_esc(entry["common_name"])}</div>'
            f'<div class="chain-issuer">{_esc(entry["issuer"] or "(no issuer)")}</div>'
            f'</div>'
        )
        if idx in missing_by_idx:
            issuer = missing_by_idx[idx]
            boxes.append('<div class="chain-arrow">&rarr;</div>')
            boxes.append(
                f'<div class="chain-box missing">MISSING<br>{_esc(issuer)}</div>'
            )
        elif idx in resolved_by_idx:
            issuer, other_path = resolved_by_idx[idx]
            other_idx = path_to_row_idx.get(other_path)
            onclick = f' onclick="showDetail({other_idx})"' if other_idx is not None else ""
            boxes.append('<div class="chain-arrow">&rarr;</div>')
            boxes.append(
                f'<div class="chain-box resolved"{onclick}>FOUND ELSEWHERE<br>{_esc(issuer)}'
                f'<div class="chain-resolved-path">{_esc(other_path)}</div></div>'
            )
        if pos < len(indices) - 1:
            boxes.append('<div class="chain-arrow">&rarr;</div>')

    # wrap every 5 boxes+arrows-worth onto a new visual row so long bundles
    # (e.g. a flat CA trust store with dozens of unrelated roots) don't
    # produce one unreadably wide strip
    rows, current = [], []
    box_count = 0
    for chunk in boxes:
        current.append(chunk)
        if 'chain-box' in chunk and 'missing' not in chunk or 'chain-box missing' in chunk:
            box_count += 1
        if box_count >= 5 and chunk.startswith('<div class="chain-arrow"'):
            rows.append(current)
            current = []
            box_count = 0
    if current:
        rows.append(current)

    return "".join(f'<div class="chain-row">{"".join(row)}</div>' for row in rows)


def generate(prometheus_url):
    """Query Prometheus and return the rendered chain-explorer HTML page as a str.

    Raises RuntimeError if no certificates are currently exposed, and
    propagates any underlying urllib/JSON error from a bad or unreachable
    Prometheus URL -- callers (server.py) turn both into a clean HTTP error.
    """
    bundles = _fetch_bundles(prometheus_url)
    if not bundles:
        raise RuntimeError(
            "No tls_certificate_expiry_days series found at "
            f"{prometheus_url} -- is cert-analyzer running and scraped?"
        )

    # Global index of every subject cert-analyzer currently knows about,
    # across every bundle -- lets a gap in one file be resolved by a cert
    # that only exists in a completely different file.
    subject_index = {}
    for path, by_index in bundles.items():
        for entry in by_index.values():
            if entry["subject"]:
                subject_index.setdefault(entry["subject"], set()).add(path)

    rows = []
    for path, by_index in bundles.items():
        gaps = _find_chain_gaps(path, by_index, subject_index)
        missing_by_idx = {idx: issuer for idx, _entry, issuer, other in gaps if other is None}
        resolved_by_idx = {idx: (issuer, other) for idx, _entry, issuer, other in gaps if other is not None}
        rows.append({
            "path": path,
            "by_index": by_index,
            "chain_length": len(by_index),
            "missing_by_idx": missing_by_idx,
            "resolved_by_idx": resolved_by_idx,
            "has_missing": bool(missing_by_idx),
            "has_resolved": bool(resolved_by_idx),
        })

    # broken chains first, then cross-file-resolved, then longest chains
    # first, then alphabetical
    rows.sort(key=lambda r: (not r["has_missing"], not r["has_resolved"], -r["chain_length"], r["path"]))

    path_to_row_idx = {row["path"]: i for i, row in enumerate(rows)}

    broken_count = sum(1 for r in rows if r["has_missing"])
    resolved_count = sum(1 for r in rows if r["has_resolved"])

    overview_cards = []
    detail_blocks = []
    for idx, row in enumerate(rows):
        if row["has_missing"]:
            status, meta_cls = "critical", " critical"
        elif row["has_resolved"]:
            status, meta_cls = "info", " info"
        else:
            status, meta_cls = "good", ""
        meta_text = f'{row["chain_length"]} cert(s) in chain'
        if row["has_missing"]:
            meta_text += " &middot; MISSING INTERMEDIATE"
        elif row["has_resolved"]:
            meta_text += " &middot; completes via another file"
        overview_cards.append(
            f'<div class="chain-card" onclick="showDetail({idx})">'
            f'<span class="chain-dot" style="background: var(--{status})"></span>'
            f'<div><div class="chain-path">{_esc(row["path"])}</div>'
            f'<div class="chain-meta{meta_cls}">{meta_text}</div></div></div>'
        )

        subtitle = f'{row["chain_length"]} cert(s) in chain'
        subtitle_cls = ""
        if row["has_missing"]:
            subtitle += " &middot; missing intermediate detected"
            subtitle_cls = " critical"
        elif row["has_resolved"]:
            subtitle += " &middot; chain completes via another file -- click the linked box to jump there"
            subtitle_cls = " info"

        detail_blocks.append(
            f'<div class="detail" id="detail-{idx}">'
            f'<div class="detail-title">{_esc(row["path"])}</div>'
            f'<div class="detail-subtitle{subtitle_cls}">{subtitle}</div>'
            f'{_render_chain_row(row["by_index"], row["missing_by_idx"], row["resolved_by_idx"], path_to_row_idx)}'
            f'</div>'
        )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Certificate Chain Explorer</title>
<style>{PAGE_CSS}</style>
</head>
<body>
<p><a href="/">&larr; Back to test console</a></p>
<h1>Certificate Chain Explorer</h1>
<p class="subtitle">{len(rows)} bundle(s) monitored &middot; {broken_count} with a missing intermediate &middot; {resolved_count} completed via another file &middot; click one to see its chain</p>
<p class="note">Data comes from Prometheus's last scrape of cert-analyzer's metrics, not a live query -- a newly-discovered or newly-broken chain can take up to one Prometheus scrape interval to show up here.</p>

<div id="overview">{"".join(overview_cards)}</div>

<div id="detail-header">
  <button id="back-btn" onclick="showOverview()">&larr; All chains</button>
</div>
{"".join(detail_blocks)}

<script>
function showDetail(idx) {{
  document.getElementById('overview').style.display = 'none';
  document.getElementById('detail-header').style.display = 'flex';
  document.querySelectorAll('.detail').forEach(function (d) {{ d.style.display = 'none'; }});
  document.getElementById('detail-' + idx).style.display = 'block';
}}
function showOverview() {{
  document.getElementById('overview').style.display = 'grid';
  document.getElementById('detail-header').style.display = 'none';
  document.querySelectorAll('.detail').forEach(function (d) {{ d.style.display = 'none'; }});
}}
showOverview();
</script>
</body>
</html>
"""
