"""
fleet_chain_explorer.py -- Fleet-wide (multi-node) certificate chain
explorer, bundled into the test-server console alongside chain_explorer.py.

chain_explorer.py groups by cert_path alone and builds one *global*
subject_index spanning every bundle Prometheus knows about. Pointing it at
a fleet-wide Prometheus unmodified would be actively wrong, not just
incomplete: (1) two nodes' copies of the same path would collide into one
garbled bundle, and (2) a genuinely missing intermediate on node A could
get marked "FOUND ELSEWHERE" just because node B happens to have a copy of
it in some unrelated file -- even though node A's process can never load a
file that only exists on node B's filesystem.

This module fixes both by scoping everything per node: _fetch_fleet_bundles
keys by (node_name, cert_path, cert_index), and _analyze_node builds a
subject_index from *only one node's own* bundles before calling
chain_explorer._find_chain_gaps -- which is otherwise reused completely
unmodified, since its logic is correct as long as what's fed into it is
correctly scoped. Do not "simplify" _analyze_node's subject_index back into
one shared across nodes -- that reintroduces the false "FOUND ELSEWHERE"
bug this module exists to avoid.

The fleet aggregation then re-groups these per-node results *by path*,
since the actual value of a fleet view here is surfacing drift: is the
same logical bundle path consistently correct across the fleet, or broken
on some nodes and fine on others? This also surfaces a second, more subtle
signal that's invisible in the single-node tool: chain_explorer's "a
single-cert bundle is never flagged MISSING" rule is right for a lone host
(no way to know if a standalone leaf is supposed to have a chain), but
fleet-wide, if most nodes carry a multi-cert bundle at a path and a few
carry only the leaf, that's a plausible rollout gap -- see
_chain_length_note.

Stdlib only -- no third-party packages required.
"""
from collections import Counter

import chain_explorer

DIAGRAM_CAP = 8
STATUS_PRIORITY = {"critical": 0, "warn": 1, "info": 2, "good": 3}

# Layered after chain_explorer.PAGE_CSS -- adds a --warn color (chain
# explorer's palette only has good/critical/info), neutralizes the
# "resolved" box's clickable affordance now that its onclick target is
# always dropped (see _render_path_detail), and styles the new
# filter/table/diagram elements.
EXTRA_CSS = """
:root { --warn: #fab219; }
@media (prefers-color-scheme: dark) {
  :root { --warn: #fab219; }
}
.chain-meta.warn { color: var(--warn); font-weight: 600; }
.detail-subtitle.warn { color: var(--warn); font-weight: 600; }
.chain-box.resolved { cursor: default; }
.chain-box.resolved:hover { background: transparent; }
#filter-box { margin: 0 0 1.5rem; }
#filter-box input {
  width: 100%; max-width: 420px; padding: 6px 10px; border: 1px solid var(--border);
  border-radius: 6px; background: var(--surface); color: var(--primary); font-size: 0.85rem;
}
.member-table { border-collapse: collapse; margin: 0.5rem 0 1.25rem; font-size: 0.82rem; }
.member-table th, .member-table td {
  border-bottom: 1px solid var(--border); padding: 4px 10px; text-align: left;
}
.member-table th { color: var(--secondary); font-weight: 600; }
.status-critical { color: var(--critical); font-weight: 600; }
.status-warn { color: var(--warn); font-weight: 600; }
.status-info { color: var(--info); font-weight: 600; }
.status-good { color: var(--good); }
.node-diagram { margin: 0.5rem 0 1rem; }
.node-diagram-header {
  font-size: 0.78rem; font-weight: 600; color: var(--secondary);
  margin-bottom: 0.25rem; font-family: ui-monospace, monospace;
}
.note.variance { color: var(--secondary); font-style: normal; }
.note.variance.warn { color: var(--warn); font-weight: 600; }
"""


def _fetch_fleet_bundles(base_url):
    """{node: {path: {idx: entry}}} -- both query loops keyed by node_name
    first, so a self-signed/is_ca flag never gets silently attached to a
    different node's cert that happens to share a path+index."""
    by_node = {}
    for r in chain_explorer._prom_query(base_url, "tls_certificate_expiry_days"):
        m = r["metric"]
        node = m.get("node_name", "?")
        path = m.get("cert_path", "")
        idx = int(m.get("cert_index", "0"))
        by_node.setdefault(node, {}).setdefault(path, {})[idx] = {
            "subject": m.get("subject", ""),
            "issuer": m.get("issuer", ""),
            "common_name": m.get("common_name") or m.get("subject") or "(no subject)",
            "is_self_signed": False,
            "is_ca": "unknown",
        }

    for r in chain_explorer._prom_query(base_url, "tls_certificate_self_signed"):
        m = r["metric"]
        node = m.get("node_name", "?")
        path = m.get("cert_path", "")
        idx = int(m.get("cert_index", "0"))
        entry = by_node.get(node, {}).get(path, {}).get(idx)
        if entry is None:
            continue  # self-signed series with no matching expiry series -- shouldn't normally happen
        entry["is_self_signed"] = r["value"][1] == "1"
        entry["is_ca"] = m.get("is_ca", "unknown")

    return by_node


def _analyze_node(path_bundles):
    """path_bundles: {path: {idx: entry}} for ONE node. Builds a
    subject_index from only this node's own bundles -- see module
    docstring -- then reuses chain_explorer._find_chain_gaps unmodified."""
    subject_index = {}
    for path, by_index in path_bundles.items():
        for entry in by_index.values():
            if entry["subject"]:
                subject_index.setdefault(entry["subject"], set()).add(path)

    rows = {}
    for path, by_index in path_bundles.items():
        gaps = chain_explorer._find_chain_gaps(path, by_index, subject_index)
        missing_by_idx = {idx: issuer for idx, _entry, issuer, other in gaps if other is None}
        resolved_by_idx = {idx: (issuer, other) for idx, _entry, issuer, other in gaps if other is not None}
        rows[path] = {
            "by_index": by_index,
            "chain_length": len(by_index),
            "missing_by_idx": missing_by_idx,
            "resolved_by_idx": resolved_by_idx,
            "has_missing": bool(missing_by_idx),
            "has_resolved": bool(resolved_by_idx),
        }
    return rows


def _aggregate_by_path(by_node):
    by_path = {}
    for node, path_bundles in by_node.items():
        for path, row in _analyze_node(path_bundles).items():
            by_path.setdefault(path, {})[node] = row
    return by_path


def _chain_length_note(node_rows):
    """Returns (note_text_or_None, elevated). Elevated when the variance
    specifically mixes single-cert and multi-cert nodes at the same path --
    the fleet-only false-negative chain_explorer's per-node "never flag a
    single-cert bundle MISSING" rule can't catch on its own."""
    lengths = Counter(row["chain_length"] for row in node_rows.values())
    if len(lengths) <= 1:
        return None, False
    has_single = any(n == 1 for n in lengths)
    has_multi = any(n > 1 for n in lengths)
    elevated = has_single and has_multi
    parts = " · ".join(f"{n} cert(s): {count} node(s)" for n, count in sorted(lengths.items()))
    text = f"Chain length varies across nodes at this path -- {parts}."
    if elevated:
        text += (
            " Some node(s) have only the standalone leaf while others have the full bundle "
            "here -- this may be a fleet rollout gap rather than an intentional per-node difference."
        )
    return text, elevated


def _path_status(node_rows, elevated_variance):
    if any(row["has_missing"] for row in node_rows.values()):
        return "critical"
    if elevated_variance:
        return "warn"
    if any(row["has_resolved"] for row in node_rows.values()):
        return "info"
    return "good"


def _node_status_label(row, elevated_variance):
    if row["has_missing"]:
        return "MISSING INTERMEDIATE", "critical"
    if elevated_variance and row["chain_length"] == 1:
        return "possible missing chain (standalone leaf)", "warn"
    if row["has_resolved"]:
        return "resolved via another file", "info"
    return "OK", "good"


def _select_diagram_nodes(node_rows, cap):
    """MISSING nodes first (most severe/actionable), then FOUND-ELSEWHERE,
    both alphabetical -- deterministic so a re-render doesn't shuffle which
    nodes get shown. Returns (selected_nodes, overflow_missing, overflow_resolved)."""
    missing_nodes = sorted(n for n, r in node_rows.items() if r["has_missing"])
    resolved_nodes = sorted(n for n, r in node_rows.items() if r["has_resolved"] and not r["has_missing"])
    selected = (missing_nodes + resolved_nodes)[:cap]
    selected_set = set(selected)
    overflow_missing = len([n for n in missing_nodes if n not in selected_set])
    overflow_resolved = len([n for n in resolved_nodes if n not in selected_set])
    return selected, overflow_missing, overflow_resolved


def _render_path_overview_card(path, node_rows, idx, status):
    node_count = len(node_rows)
    missing_count = sum(1 for r in node_rows.values() if r["has_missing"])
    resolved_count = sum(1 for r in node_rows.values() if r["has_resolved"] and not r["has_missing"])
    meta_bits = [f"{node_count} node(s)"]
    meta_cls = ""
    if missing_count:
        meta_bits.append(f"{missing_count} MISSING INTERMEDIATE")
        meta_cls = " critical"
    elif status == "warn":
        meta_bits.append("chain length varies")
        meta_cls = " warn"
    elif resolved_count:
        meta_bits.append(f"{resolved_count} resolved elsewhere")
        meta_cls = " info"
    return (
        f'<div class="chain-card" data-path="{chain_explorer._esc(path)}" onclick="showDetail({idx})">'
        f'<span class="chain-dot" style="background: var(--{status})"></span>'
        f'<div><div class="chain-path">{chain_explorer._esc(path)}</div>'
        f'<div class="chain-meta{meta_cls}">{" &middot; ".join(meta_bits)}</div></div></div>'
    )


def _render_path_detail(path, node_rows, idx, status):
    variance_note, elevated = _chain_length_note(node_rows)
    labels = {n: _node_status_label(r, elevated) for n, r in node_rows.items()}

    table_rows = []
    for node in sorted(node_rows, key=lambda n: (STATUS_PRIORITY[labels[n][1]], n)):
        row = node_rows[node]
        label, cls = labels[node]
        table_rows.append(
            f'<tr><td>{chain_explorer._esc(node)}</td><td>{row["chain_length"]}</td>'
            f'<td class="status-{cls}">{chain_explorer._esc(label)}</td></tr>'
        )
    table = (
        '<table class="member-table"><thead><tr><th>Node</th><th>Chain length</th>'
        '<th>Status</th></tr></thead>'
        f'<tbody>{"".join(table_rows)}</tbody></table>'
    )

    selected, overflow_missing, overflow_resolved = _select_diagram_nodes(node_rows, DIAGRAM_CAP)
    diagrams = []
    for node in selected:
        row = node_rows[node]
        # path_to_row_idx={} -- the "resolved elsewhere" jump target is
        # always a different path on this same node (see module docstring),
        # which has no stable cross-group id in a by-path fleet view; an
        # empty dict makes the reused renderer fall back to plain,
        # non-clickable text (still showing the resolving path) rather than
        # needing any change to _render_chain_row itself.
        diagrams.append(
            f'<div class="node-diagram">'
            f'<div class="node-diagram-header">{chain_explorer._esc(node)}</div>'
            f'{chain_explorer._render_chain_row(row["by_index"], row["missing_by_idx"], row["resolved_by_idx"], {})}'
            f'</div>'
        )
    overflow_bits = []
    if overflow_missing:
        overflow_bits.append(f"{overflow_missing} more missing")
    if overflow_resolved:
        overflow_bits.append(f"{overflow_resolved} more resolved elsewhere")
    cap_note = f'<p class="note">+{" and ".join(overflow_bits)} &mdash; see table above.</p>' if overflow_bits else ""
    variance_html = (
        f'<p class="note variance{" warn" if elevated else ""}">{chain_explorer._esc(variance_note)}</p>'
        if variance_note else ""
    )

    node_count = len(node_rows)
    missing_count = sum(1 for r in node_rows.values() if r["has_missing"])
    resolved_count = sum(1 for r in node_rows.values() if r["has_resolved"] and not r["has_missing"])
    subtitle = f"{node_count} node(s)"
    if missing_count:
        subtitle += f" &middot; {missing_count} missing intermediate"
    if resolved_count:
        subtitle += f" &middot; {resolved_count} resolved elsewhere"
    subtitle_cls = f" {status}" if status != "good" else ""

    return (
        f'<div class="detail" id="detail-{idx}">'
        f'<div class="detail-title">{chain_explorer._esc(path)}</div>'
        f'<div class="detail-subtitle{subtitle_cls}">{subtitle}</div>'
        f'{variance_html}'
        f'{table}'
        f'{"".join(diagrams)}'
        f'{cap_note}'
        f'</div>'
    )


def generate(prometheus_url):
    """Query Prometheus and return the rendered fleet chain-explorer HTML
    page as a str. Same contract as chain_explorer.generate: raises
    RuntimeError if no certificates are currently exposed, and propagates
    any underlying urllib/JSON error from a bad or unreachable Prometheus
    URL -- callers (server.py) turn both into a clean HTTP error.
    """
    by_node = _fetch_fleet_bundles(prometheus_url)
    if not by_node:
        raise RuntimeError(
            "No tls_certificate_expiry_days series found at "
            f"{prometheus_url} -- is cert-analyzer running and scraped?"
        )
    by_path = _aggregate_by_path(by_node)

    entries = []
    for path, node_rows in by_path.items():
        _note, elevated = _chain_length_note(node_rows)
        entries.append((path, node_rows, _path_status(node_rows, elevated)))
    entries.sort(key=lambda e: (STATUS_PRIORITY[e[2]], -len(e[1]), e[0]))

    overview_cards = [
        _render_path_overview_card(path, node_rows, idx, status)
        for idx, (path, node_rows, status) in enumerate(entries)
    ]
    detail_blocks = [
        _render_path_detail(path, node_rows, idx, status)
        for idx, (path, node_rows, status) in enumerate(entries)
    ]

    critical_count = sum(1 for _p, _r, s in entries if s == "critical")
    warn_count = sum(1 for _p, _r, s in entries if s == "warn")
    info_count = sum(1 for _p, _r, s in entries if s == "info")

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Fleet Certificate Chain Explorer</title>
<style>{chain_explorer.PAGE_CSS}{EXTRA_CSS}</style>
</head>
<body>
<p><a href="/">&larr; Back to test console</a></p>
<h1>Fleet Certificate Chain Explorer</h1>
<p class="subtitle">{len(entries)} distinct path(s) across the fleet &middot; {critical_count} with a missing intermediate somewhere &middot; {warn_count} with chain-length drift &middot; {info_count} resolved via another file somewhere &middot; click one to see the per-node breakdown</p>
<p class="note">Data comes from Prometheus's last scrape of every scraped node's cert-analyzer metrics -- a newly-discovered or newly-broken chain can take up to one scrape interval to show up here. Cross-file issuer resolution only ever searches other bundles on the *same* node -- a fix that only exists on a different host is never counted as resolving a gap here.</p>

<div id="filter-box"><input type="text" id="path-filter" placeholder="Filter by path" oninput="filterCards()"></div>

<div id="overview">{"".join(overview_cards)}</div>

<div id="detail-header">
  <button id="back-btn" onclick="showOverview()">&larr; All chains</button>
</div>
{"".join(detail_blocks)}

<script>
function filterCards() {{
  var q = document.getElementById('path-filter').value.trim().toLowerCase();
  document.querySelectorAll('.chain-card').forEach(function (card) {{
    var path = card.getAttribute('data-path').toLowerCase();
    card.style.display = path.indexOf(q) === -1 ? 'none' : 'flex';
  }});
}}
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
