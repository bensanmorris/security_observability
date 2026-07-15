"""
blast_radius.py -- Certificate blast-radius explorer, bundled into the
test-server console so its "Blast radius explorer" link can generate it live
against a running Prometheus.

This is a bundled copy of extras/cert_blast_radius.py, trimmed to a library
(no CLI/argparse -- server.py calls generate() directly) so the RPM package
stays self-contained without reaching outside extras/test-server/ (see
build-rpm.sh, which tars up this directory file-by-file). Keep the two in
sync by hand if you change the rendering logic in one.

Queries cert-analyzer's own `tls_certificate_expiry_days` /
`tls_certificate_process_info` Prometheus metrics -- no separate inventory to
keep in sync. Stdlib only -- no third-party packages required.
"""
import json
import math
import urllib.parse
import urllib.request

CATEGORICAL_SLOTS = 8
# Matches the thresholds cert-analyzer's own tls_certificate_expiring_soon
# metric buckets on (see extras/examples/grafana-dashboard.json).
EXPIRY_THRESHOLDS = (0, 7, 30)  # expired / <7d critical / <30d warning / else good

# Palette values (dataviz skill reference/palette.md), wired as CSS custom
# properties in PAGE_CSS below so the page follows the OS/browser light-dark
# preference automatically -- SVG marks reference them via fill="var(--...)"
# rather than baking in one theme's hex values.
PAGE_CSS = """
:root {
  color-scheme: light;
  --surface: #fcfcfb; --page: #f9f9f7;
  --primary: #0b0b0b; --secondary: #52514e; --muted: #898781;
  --spoke: #c3c2b7; --border: rgba(11,11,11,0.10);
  --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
  --cat-1: #2a78d6; --cat-2: #008300; --cat-3: #e87ba4; --cat-4: #eda100;
  --cat-5: #1baf7a; --cat-6: #eb6834; --cat-7: #4a3aa7; --cat-8: #e34948;
  --other: #898781;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --surface: #1a1a19; --page: #0d0d0d;
    --primary: #ffffff; --secondary: #c3c2b7; --muted: #898781;
    --spoke: #383835; --border: rgba(255,255,255,0.10);
    --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
    --cat-1: #3987e5; --cat-2: #008300; --cat-3: #d55181; --cat-4: #c98500;
    --cat-5: #199e70; --cat-6: #d95926; --cat-7: #9085e9; --cat-8: #e66767;
    --other: #898781;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem; background: var(--page); color: var(--primary);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
}
h1 { font-size: 1.4rem; margin: 0 0 0.25rem; }
.subtitle { color: var(--secondary); font-size: 0.9rem; margin: 0 0 1.5rem; }
#overview {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 12px; max-width: 1100px;
}
.cert-card {
  display: flex; align-items: center; gap: 10px; padding: 12px 14px;
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  cursor: pointer;
}
.cert-card:hover { border-color: var(--muted); }
.cert-dot { width: 12px; height: 12px; border-radius: 50%; flex: none; }
.cert-name { font-weight: 600; font-size: 0.92rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cert-meta { color: var(--secondary); font-size: 0.78rem; }
#detail-header {
  display: none; align-items: center; gap: 12px; margin-bottom: 1rem;
}
#back-btn {
  background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
  padding: 6px 12px; font-size: 0.85rem; cursor: pointer; color: var(--primary);
}
#back-btn:hover { border-color: var(--muted); }
.detail { display: none; max-width: 900px; }
.detail-title { font-size: 1.1rem; font-weight: 600; margin: 0 0 0.25rem; }
.detail-subtitle { color: var(--secondary); font-size: 0.85rem; margin: 0 0 1rem; }
#legend { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 1rem; }
.legend-item { display: flex; align-items: center; gap: 6px; font-size: 0.8rem; color: var(--secondary); }
.legend-swatch { width: 11px; height: 11px; border-radius: 2px; flex: none; }
"""


def _prom_query(base_url, promql):
    url = f"{base_url.rstrip('/')}/api/v1/query?{urllib.parse.urlencode({'query': promql})}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        payload = json.load(resp)
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus query failed: {payload}")
    return payload["data"]["result"]


def _fetch_all_certs(base_url):
    """One entry per (cert_path, cert_index) -- cert-analyzer's own cert identity key."""
    results = _prom_query(base_url, "tls_certificate_expiry_days")
    certs = {}
    for r in results:
        m = r["metric"]
        key = (m.get("cert_path", ""), m.get("cert_index", "0"))
        certs[key] = {
            "common_name": m.get("common_name") or m.get("subject") or m.get("cert_path") or "certificate",
            "serial": m.get("serial", ""),
            "days_left": float(r["value"][1]),
            "leaves": [],
        }
    return certs


def _fetch_all_process_pairings(base_url, certs):
    results = _prom_query(base_url, "tls_certificate_process_info")
    for r in results:
        m = r["metric"]
        key = (m.get("cert_path", ""), m.get("cert_index", "0"))
        if key not in certs:
            continue  # process-info series with no matching expiry series -- shouldn't normally happen
        certs[key]["leaves"].append({
            "process": m.get("process", "?"),
            "node_name": m.get("node_name", "?"),
            "pod_name": m.get("pod_name", ""),
            "namespace": m.get("namespace", ""),
        })


def _status_bucket(days_left):
    if days_left < EXPIRY_THRESHOLDS[0]:
        return "critical"
    if days_left < EXPIRY_THRESHOLDS[1]:
        return "serious"
    if days_left < EXPIRY_THRESHOLDS[2]:
        return "warning"
    return "good"


def _days_label(days_left):
    if days_left < 0:
        return f"expired {abs(days_left):.0f}d ago"
    return f"{days_left:.0f}d left"


def _assign_namespace_colors(all_certs):
    namespaces = sorted({
        leaf["namespace"] or "(none)"
        for cert in all_certs.values() for leaf in cert["leaves"]
    })
    color_var = {}
    for i, ns in enumerate(namespaces):
        color_var[ns] = f"var(--cat-{i + 1})" if i < CATEGORICAL_SLOTS else "var(--other)"
    return color_var


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _render_detail_svg(cert, ns_color):
    leaves = cert["leaves"]
    w = h = 640
    cx, cy = w / 2, h / 2
    radius = min(w, h) / 2 - 130
    n = max(len(leaves), 1)

    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">']

    positions = []
    for i in range(n):
        angle = (2 * math.pi * i / n) - math.pi / 2
        x = cx + radius * math.cos(angle)
        y = cy + radius * math.sin(angle)
        positions.append((x, y, angle))
        parts.append(f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{x:.1f}" y2="{y:.1f}" '
                      f'stroke="var(--spoke)" stroke-width="1.5"/>')

    for leaf, (x, y, angle) in zip(leaves, positions):
        ns = leaf["namespace"] or "(none)"
        color = ns_color.get(ns, "var(--other)")
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8" fill="{color}" '
                      f'stroke="var(--surface)" stroke-width="2"/>')
        deg = math.degrees(angle) % 360
        right_half = deg < 90 or deg > 270
        anchor = "start" if right_half else "end"
        label_x = x + (12 if right_half else -12)
        detail_bits = [b for b in (leaf["pod_name"], leaf["namespace"]) if b] or [leaf["node_name"]]
        detail = " / ".join(detail_bits[:2])
        parts.append(f'<text x="{label_x:.1f}" y="{y - 3:.1f}" text-anchor="{anchor}" '
                      f'font-size="11" font-weight="600" fill="var(--primary)">{_esc(leaf["process"])}</text>')
        parts.append(f'<text x="{label_x:.1f}" y="{y + 10:.1f}" text-anchor="{anchor}" '
                      f'font-size="9.5" fill="var(--secondary)">{_esc(detail)}</text>')

    parts.append('<circle cx="{0}" cy="{1}" r="22" fill="var(--surface)" '
                  'stroke="var(--primary)" stroke-width="2.5"/>'.format(cx, cy))
    body_x, body_y = cx - 7, cy - 2
    parts.append(f'<rect x="{body_x:.1f}" y="{body_y:.1f}" width="14" height="10" rx="2" fill="var(--primary)"/>')
    parts.append(f'<path d="M {cx - 5:.1f} {body_y:.1f} v -5 a 5 5 0 0 1 10 0 v 5" '
                  f'fill="none" stroke="var(--primary)" stroke-width="2.2"/>')

    parts.append("</svg>")
    return "\n".join(parts)


def _render_page(all_certs):
    ns_color = _assign_namespace_colors(all_certs)
    ordered = sorted(all_certs.items(), key=lambda kv: kv[1]["days_left"])

    overview_cards = []
    detail_blocks = []
    for idx, (_key, cert) in enumerate(ordered):
        status = _status_bucket(cert["days_left"])
        overview_cards.append(
            f'<div class="cert-card" onclick="showDetail({idx})">'
            f'<span class="cert-dot" style="background: var(--{status})"></span>'
            f'<div><div class="cert-name">{_esc(cert["common_name"])}</div>'
            f'<div class="cert-meta">{_esc(_days_label(cert["days_left"]))} '
            f'&middot; {len(cert["leaves"])} process pairing(s)</div></div></div>'
        )

        pod_count = len({leaf["pod_name"] for leaf in cert["leaves"] if leaf["pod_name"]})
        ns_count = len({leaf["namespace"] for leaf in cert["leaves"] if leaf["namespace"]})
        node_count = len({leaf["node_name"] for leaf in cert["leaves"]})
        subtitle_bits = [f'{len(cert["leaves"])} process(es)']
        if pod_count:
            subtitle_bits.append(f"{pod_count} pod(s)")
        if ns_count:
            subtitle_bits.append(f"{ns_count} namespace(s)")
        subtitle_bits.append(f"{node_count} node(s)")

        detail_blocks.append(
            f'<div class="detail" id="detail-{idx}">'
            f'<div class="detail-title">{_esc(cert["common_name"])}</div>'
            f'<div class="detail-subtitle">{_esc(" · ".join(subtitle_bits))}'
            f'{" &middot; serial " + _esc(cert["serial"][:16]) if cert["serial"] else ""}</div>'
            f'{_render_detail_svg(cert, ns_color)}'
            f'</div>'
        )

    legend_items = sorted((ns, c) for ns, c in ns_color.items() if c != "var(--other)")
    if any(c == "var(--other)" for c in ns_color.values()):
        legend_items.append(("Other", "var(--other)"))
    legend_html = "".join(
        f'<div class="legend-item"><span class="legend-swatch" style="background:{color}"></span>{_esc(ns)}</div>'
        for ns, color in legend_items
    )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Certificate Blast Radius</title>
<style>{PAGE_CSS}</style>
</head>
<body>
<p><a href="/">&larr; Back to test console</a></p>
<h1>Certificate Blast Radius</h1>
<p class="subtitle">{len(all_certs)} certificate(s) monitored &middot; click one to see every process, pod, and node that loads it</p>

<div id="overview">{"".join(overview_cards)}</div>

<div id="detail-header">
  <button id="back-btn" onclick="showOverview()">&larr; All certificates</button>
</div>
{"".join(detail_blocks)}
<div id="legend">{legend_html}</div>

<script>
function showDetail(idx) {{
  document.getElementById('overview').style.display = 'none';
  document.getElementById('detail-header').style.display = 'flex';
  document.getElementById('legend').style.display = 'flex';
  document.querySelectorAll('.detail').forEach(function (d) {{ d.style.display = 'none'; }});
  document.getElementById('detail-' + idx).style.display = 'block';
}}
function showOverview() {{
  document.getElementById('overview').style.display = 'grid';
  document.getElementById('detail-header').style.display = 'none';
  document.getElementById('legend').style.display = 'none';
  document.querySelectorAll('.detail').forEach(function (d) {{ d.style.display = 'none'; }});
}}
showOverview();
</script>
</body>
</html>
"""


def generate(prometheus_url):
    """Query Prometheus and return the rendered blast-radius HTML page as a str.

    Raises RuntimeError if no certificates are currently exposed, and
    propagates any underlying urllib/JSON error from a bad or unreachable
    Prometheus URL -- callers (server.py) turn both into a clean HTTP error.
    """
    all_certs = _fetch_all_certs(prometheus_url)
    _fetch_all_process_pairings(prometheus_url, all_certs)
    if not all_certs:
        raise RuntimeError(
            "No tls_certificate_expiry_days series found at "
            f"{prometheus_url} -- is cert-analyzer running and scraped?"
        )
    return _render_page(all_certs)
