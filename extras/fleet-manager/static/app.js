/* CertSight fleet manager -- console logic. Vanilla JS, no build step.
 *
 * Every state-changing request carries X-Requested-With: fetch, which the
 * server requires alongside the SameSite=Strict session cookie as its CSRF
 * guard. Never assume a toggle succeeded: the matrix is re-read from the
 * server after every write so what's shown is what the nodes reported.
 */
(function () {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const views = ["login", "nodes", "policies", "explorers", "audit"];
  const EXPLORER_LABELS = {
    "/fleet-blast-radius": "Blast radius",
    "/fleet-chain-explorer": "Chain explorer",
    "/fleet-fips-rollout": "FIPS rollout",
  };
  let me = null;
  const isViewer = () => !!(me && me.role !== "admin");
  // What the landing page may offer besides the administrator form:
  // fetched once from /api/login-options (unauthenticated by design).
  let loginOptions = null;
  // "admin" (username + password) or "viewer" (the viewer account's access
  // code, username implied). Anonymous viewers don't use the form at all.
  let loginMode = "admin";
  // Deep-linkable views: #policies opens straight on the matrix, and a
  // refresh stays on the tab you were on.
  let currentView = (location.hash || "#nodes").slice(1);

  // ── HTTP ──────────────────────────────────────────────────────────────

  async function api(method, path, body) {
    const opts = { method, headers: { "X-Requested-With": "fetch" } };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(path, opts);
    let data = null;
    try { data = await resp.json(); } catch (e) { data = null; }
    if (resp.status === 401 && path !== "/api/login") {
      showLogin(false);
      throw new Error("login required");
    }
    return { status: resp.status, ok: resp.ok, data };
  }

  function setStatus(text, isError) {
    const el = $("#status");
    el.textContent = text || "";
    el.classList.toggle("error", !!isError);
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function badge(text, kind) {
    return `<span class="badge badge-${kind}">${esc(text)}</span>`;
  }

  // One honest description of a node's control state, shared by the Nodes
  // table and the matrix header. `c` is the node's control summary from
  // the server: reachable/role/error/configured (the node's own
  // cert_analyzer_config_info{fleet_control} from Prometheus, so a node
  // that never answered can still say *why*).
  function controlBadge(c) {
    const wrap = (label, kind, why) => `<span title="${esc(why)}">${badge(label, kind)}</span>`;
    if (c.reachable) {
      if (c.role === "viewer") {
        return wrap("read-only client", "warn",
          "The node answers reads but lists this console's client certificate CN in [control] readonly_clients; every change would be refused.");
      }
      return wrap(c.platform || "reachable", "ok", "Control listener reachable; this console may change policies here.");
    }
    switch (c.error) {
      case "unauthorized":
        return wrap("unauthorized", "error", "The node rejected this console's token (401): FLEET_MANAGER_NODE_TOKEN doesn't match its [control] token.");
      case "forbidden":
        return wrap("refused", "error", "The node refused this console (403): its [control] allowed_sources doesn't include this host, or our client certificate CN is in neither of its lists.");
      case "not_control":
        return wrap("not a control port", "error", "Something answered at the control URL but it has no /control routes -- check FLEET_MANAGER_CONTROL_PORT / the overrides file.");
      case "bad_response":
        return wrap("bad response", "error", "The control URL answered, but not with what a cert-analyzer control listener returns.");
      default:
        break;
    }
    switch (c.configured) {
      case "unavailable":
        return wrap("no control (not installed)", "muted", "This node has no fleet-control code: the cert-analyzer-control package isn't installed (or it runs the default image, not the -control variant). There is no listener to enable; read-only by construction.");
      case "disabled":
        return wrap("control off", "muted", "This node has [control] enabled = false (the default). Read-only until an operator turns it on in cert-analyzer.conf.");
      case "enabled":
        return wrap("unreachable", "warn", `The node says its control listener is on, but this console can't reach it${c.detail ? ": " + c.detail : ""}. Loopback listener without a tunnel, firewall, or a wrong port/override.`);
      default:
        return wrap(c.error || "unreachable", "warn", `Control not reachable${c.detail ? ": " + c.detail : ""}; the node doesn't report whether it has a listener (older cert-analyzer?).`);
    }
  }

  // Why a cell can't be toggled, most relevant reason first: the viewer's
  // own account, then the node's relationship with this console.
  function cellReason(c, n) {
    if (isViewer()) return "read-only account: shown for illustration, the server refuses every change";
    if (!n.reachable) {
      if (n.configured === "unavailable") return "this node has no fleet-control code (cert-analyzer-control not installed / default image): nothing can toggle it remotely";
      if (n.configured === "disabled") return "this node has [control] disabled; enable it in cert-analyzer.conf first";
      if (n.error === "unauthorized") return "this console's node token isn't accepted by this node";
      if (n.error === "forbidden") return "this node refuses this console (allowed_sources / client CN)";
      return "control unreachable on this node";
    }
    if (n.role === "viewer") return "this console is a read-only client of this node (readonly_clients)";
    return `state ${c.state}: nothing to toggle`;
  }

  function ago(seconds) {
    if (seconds == null) return "never";
    if (seconds < 90) return `${seconds}s ago`;
    if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
    if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`;
    return `${Math.round(seconds / 86400)}d ago`;
  }

  function confirmDialog(text) {
    return new Promise((resolve) => {
      $("#confirm-text").textContent = text;
      $("#confirm").hidden = false;
      const done = (v) => { $("#confirm").hidden = true; yes.onclick = no.onclick = null; resolve(v); };
      const yes = $("#confirm-yes"), no = $("#confirm-no");
      yes.onclick = () => done(true);
      no.onclick = () => done(false);
    });
  }

  // ── views ─────────────────────────────────────────────────────────────

  function showView(name) {
    if (!views.includes(name) || name === "login") name = "nodes";
    currentView = name;
    if (location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
    views.forEach((v) => { $(`#view-${v}`).hidden = v !== name; });
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
    if (name === "nodes") loadNodes();
    else if (name === "policies") loadPolicies();
    else if (name === "explorers") loadExplorers();
    else if (name === "audit") loadAudit();
  }

  async function showLogin(cancellable) {
    // cancellable: an anonymous viewer chose "Sign in"; keep their session
    // (and the nav) so they can back out to the read-only view.
    if (!cancellable) me = null;
    $("#nav").hidden = true;
    $("#whoami").hidden = true;
    $("#signin-btn").hidden = true;
    $("#logout-btn").hidden = true;
    $("#viewer-banner").hidden = true;
    $("#login-cancel").hidden = !cancellable;
    views.forEach((v) => { $(`#view-${v}`).hidden = v !== "login"; });
    if (!loginOptions) {
      try { loginOptions = (await api("GET", "/api/login-options")).data || {}; } catch (e) { loginOptions = {}; }
    }
    setLoginMode("admin");
  }

  // The form is the administrators'. A read-only entry, when this
  // deployment has one, is a separate link beneath it -- never a role
  // picker in the form itself.
  function setLoginMode(mode) {
    loginMode = mode;
    const o = loginOptions || {};
    const viewerMode = mode === "viewer";
    $("#login-title").textContent = viewerMode ? "Read-only viewer" : "Administrator sign in";
    $("#login-username-label").hidden = viewerMode;
    $("#login-form").username.required = !viewerMode;
    $("#login-password-label").textContent = viewerMode ? "Viewer access code" : "Password";
    $("#login-submit").textContent = viewerMode ? "View" : "Sign in";
    $("#login-hint").hidden = viewerMode;
    $("#login-error").hidden = true;
    const entry = $("#viewer-entry"), link = $("#viewer-link"), note = $("#viewer-entry-note");
    if (viewerMode) {
      entry.hidden = !o.admin;
      link.textContent = "Administrator sign in instead";
      note.textContent = "";
    } else if (o.anonymous_viewer) {
      entry.hidden = false;
      link.textContent = "Continue as read-only viewer →";
      note.textContent = (o.read_only_note ? o.read_only_note + " " : "")
        + "No account needed: nodes, the policy matrix, explorers and the audit log, with every control disabled.";
    } else if (o.viewer_account) {
      entry.hidden = false;
      link.textContent = "Read-only viewer access →";
      note.textContent = (o.read_only_note ? o.read_only_note + " " : "")
        + "Enter the viewer access code to see everything without being able to change anything.";
    } else {
      entry.hidden = true;
    }
    if (!viewerMode && !o.admin && (o.anonymous_viewer || o.viewer_account)) {
      // Nothing to sign in *as*: say so rather than show a dead form.
      $("#login-hint").textContent = "This console has no administrator account: it is read-only for everyone.";
    }
  }

  $("#viewer-link").addEventListener("click", async (ev) => {
    ev.preventDefault();
    const o = loginOptions || {};
    if (loginMode === "viewer") { setLoginMode("admin"); return; }
    if (o.anonymous_viewer) {
      let r;
      try { r = await api("POST", "/api/viewer"); } catch (e) { return; }
      if (!r.ok) {
        const err = $("#login-error");
        err.textContent = r.status === 429 ? "Too many attempts — wait a minute." : "Read-only entry is not available right now.";
        err.hidden = false;
        return;
      }
      await bootstrap();
    } else if (o.viewer_account) {
      setLoginMode("viewer");
      $("#login-form").password.focus();
    }
  });

  function showApp() {
    const viewer = isViewer();
    $("#nav").hidden = false;
    $("#whoami").hidden = false;
    $("#whoami").textContent = me.anonymous ? "Viewer (read-only)" : `Signed in as ${me.user} (${me.role})`;
    // An anonymous viewer entered by choice, so "Leave" returns them to the
    // landing page; "Sign in" jumps to the administrator form when one exists.
    $("#logout-btn").textContent = me.anonymous ? "Leave read-only view" : "Log out";
    $("#logout-btn").hidden = false;
    $("#signin-btn").hidden = !(me.anonymous && me.admin_login_available);
    // Say plainly what this session -- and this console -- can do, rather
    // than letting anyone find out one refused click at a time.
    const banner = $("#viewer-banner"), text = $("#viewer-banner-text");
    banner.classList.toggle("banner-warn", false);
    if (viewer) {
      banner.hidden = false;
      banner.firstElementChild.textContent = "Read-only view.";
      text.textContent = (me.read_only_note ? me.read_only_note + " " : "")
        + "Policy controls are shown but disabled for this account; every change is refused by the server."
        + (me.admin_login_available ? "" : " No admin account is configured on this console, so nothing can be changed from here by anyone.");
    } else if (!(me.node_auth || []).length) {
      banner.hidden = false;
      banner.classList.add("banner-warn");
      banner.firstElementChild.textContent = "No node credentials.";
      text.textContent = "This console has neither FLEET_MANAGER_NODE_TOKEN nor a client certificate, so every node will refuse it: you can look, but no toggle will succeed until one is configured to match the nodes' [control] settings.";
    } else {
      banner.hidden = true;
    }
    showView(currentView === "login" ? "nodes" : currentView);
  }

  // ── nodes ─────────────────────────────────────────────────────────────

  async function loadNodes() {
    setStatus("Loading nodes…");
    const table = $("#nodes-table");
    let r;
    try { r = await api("GET", "/api/nodes"); } catch (e) { return; }
    if (!r.ok) { setStatus(`Nodes: ${r.data && r.data.detail || r.status}`, true); return; }
    const nodes = r.data.nodes;
    const rows = nodes.map((n) => {
      const health = n.healthy === null ? badge("unknown", "muted")
        : n.healthy ? badge("healthy", "ok") : badge("unhealthy", "error");
      const tet = n.tetragon_connected === null ? badge("unknown", "muted")
        : n.tetragon_connected ? badge("connected", "ok") : badge("disconnected", "error");
      const ctl = controlBadge(n.control);
      const pol = n.policies_broken > 0
        ? badge(`${n.policies_enabled}/${n.policies_total} (${n.policies_broken} broken)`, "error")
        : badge(`${n.policies_enabled}/${n.policies_total} enabled`, n.policies_enabled === n.policies_total ? "ok" : "warn");
      return `<tr>
        <td><strong>${esc(n.node_name)}</strong></td>
        <td>${esc(n.version)}</td>
        <td>${esc(n.tetragon_version)}</td>
        <td>${health}</td>
        <td>${tet}</td>
        <td>${esc(ago(n.last_event_age_seconds))}</td>
        <td>${pol}</td>
        <td>${ctl}<br><span class="control-url">${esc(n.control_url)}</span></td>
      </tr>`;
    });
    table.innerHTML = `<thead><tr>
      <th>Node</th><th>Analyzer</th><th>Tetragon</th><th>Health</th><th>Tetragon link</th>
      <th>Last event</th><th>Policies</th><th>Control</th></tr></thead>
      <tbody>${rows.join("") || '<tr class="empty"><td colspan="8">No cert-analyzer nodes found in Prometheus.</td></tr>'}</tbody>`;
    const writable = nodes.filter((n) => n.control.writable).length;
    setStatus(`${nodes.length} node${nodes.length === 1 ? "" : "s"}, ${isViewer() ? "read-only view" : `${writable} controllable from here`}`);
  }

  // ── policies ──────────────────────────────────────────────────────────

  async function loadPolicies() {
    setStatus("Loading policies…");
    const table = $("#policies-table");
    let r;
    try { r = await api("GET", "/api/policies"); } catch (e) { return; }
    if (!r.ok) { setStatus(`Policies: ${r.data && r.data.detail || r.status}`, true); return; }
    const { nodes, policies } = r.data;
    const head = nodes.map((n) => `<th class="node-col">${esc(n.node_name)}<br>${controlBadge(n)}</th>`).join("");
    const rows = policies.map((p) => {
      const cells = nodes.map((n) => {
        const c = p.cells[n.node_name] || { state: "absent" };
        // The per-node action: enable a disabled policy, disable an enabled
        // one. Any other state (absent, load_error, loading, ...) has no
        // sensible action, and an unreachable node can't be asked.
        const next = c.state === "enabled" ? false : c.state === "disabled" ? true : null;
        const canToggle = c.controllable && next !== null && !isViewer();
        const drift = c.drift ? `<span class="drift" title="node recorded ${c.desired ? "enabled" : "disabled"}, Tetragon reports ${esc(c.state)}">drift</span>` : "";
        const why = cellReason(c, n);
        const action = canToggle
          ? `<button class="btn btn-sm cell-toggle ${next ? "toggle-enable" : "toggle-disable"}" title="${esc(`${next ? "Enable" : "Disable"} ${p.name} on ${n.node_name} only`)}"
               data-node="${esc(n.node_name)}" data-policy="${esc(p.name)}" data-ns="${esc(p.namespace)}" data-next="${next}">${next ? "Enable" : "Disable"}</button>`
          : (c.state === "absent" ? "" : `<button class="btn btn-sm cell-toggle" disabled title="${esc(why)}">${next === null ? "—" : (next ? "Enable" : "Disable")}</button>`);
        return `<td><div class="cell-wrap">
          <span class="cell state-${esc(c.state)}"><span class="dot"></span>${esc(c.state)}</span>${drift}
          ${action}
        </div></td>`;
      }).join("");
      // "All nodes" really means: every node whose cell this console could
      // toggle itself. Say the number, and disable the buttons when it's 0.
      const targets = nodes.filter((n) => (p.cells[n.node_name] || {}).controllable).map((n) => n.node_name);
      const bulkOff = isViewer() ? 'disabled title="read-only account"'
        : !targets.length ? 'disabled title="no node in this row accepts a change from this console"' : "";
      const bulkTitle = targets.length ? `title="${esc(`${targets.length} node${targets.length === 1 ? "" : "s"}: ${targets.join(", ")}`)}"` : "";
      const bulkBtn = (enabled, label) => `<button class="btn btn-sm bulk" data-policy="${esc(p.name)}" data-ns="${esc(p.namespace)}"
          data-enabled="${enabled}" data-targets="${esc(targets.join(","))}" ${bulkOff || bulkTitle}>${label}</button>`;
      return `<tr>
        <td class="policy-name">${esc(p.name)}${p.namespace ? `<br><span class="policy-ns">${esc(p.namespace)}</span>` : ""}</td>
        ${cells}
        <td><span class="row-actions">
          ${bulkBtn(true, `Enable all${targets.length ? ` (${targets.length})` : ""}`)}
          ${bulkBtn(false, `Disable all${targets.length ? ` (${targets.length})` : ""}`)}
        </span></td>
      </tr>`;
    });
    table.innerHTML = `<thead><tr><th>Policy</th>${head}<th>All nodes</th></tr></thead>
      <tbody>${rows.join("") || `<tr class="empty"><td colspan="${nodes.length + 2}">No tracing policies reported.</td></tr>`}</tbody>`;
    table.querySelectorAll("button.cell-toggle:not([disabled])").forEach((b) => b.addEventListener("click", onCellClick));
    table.querySelectorAll("button.bulk:not([disabled])").forEach((b) => b.addEventListener("click", onBulkClick));
    const writable = nodes.filter((n) => n.writable).length;
    setStatus(`${policies.length} polic${policies.length === 1 ? "y" : "ies"} across ${nodes.length} node${nodes.length === 1 ? "" : "s"} (${
      isViewer() ? "read-only view" : `${writable} controllable from here`})`);
  }

  async function onCellClick(ev) {
    const b = ev.currentTarget;
    const enabled = b.dataset.next === "true";
    const node = b.dataset.node, policy = b.dataset.policy, ns = b.dataset.ns;
    if (!enabled) {
      const ok = await confirmDialog(`Disable ${policy} on ${node}? That node stops detecting everything this policy covers until it is re-enabled.`);
      if (!ok) return;
    }
    b.disabled = true;
    b.textContent = "…";
    setStatus(`${enabled ? "Enabling" : "Disabling"} ${policy} on ${node}…`);
    const path = `/api/nodes/${encodeURIComponent(node)}/policies/${encodeURIComponent(policy)}${ns ? `?namespace=${encodeURIComponent(ns)}` : ""}`;
    let r;
    try { r = await api("PUT", path, { enabled }); } catch (e) { return; }
    if (!r.ok) {
      setStatus(`${policy} on ${node}: ${r.data && (r.data.error || r.data.detail) || r.status}`, true);
    } else {
      setStatus(`${policy} on ${node}: now ${r.data.state}`);
    }
    await loadPolicies();
  }

  async function onBulkClick(ev) {
    const b = ev.currentTarget;
    const enabled = b.dataset.enabled === "true";
    const policy = b.dataset.policy, ns = b.dataset.ns;
    const targets = (b.dataset.targets || "").split(",").filter(Boolean);
    const ok = await confirmDialog(`${enabled ? "Enable" : "Disable"} ${policy} on ${targets.length} node${targets.length === 1 ? "" : "s"} (${targets.join(", ")})?${
      enabled ? "" : " Every one of them stops detecting what this policy covers."} Nodes this console can't change are skipped and listed afterwards.`);
    if (!ok) return;
    setStatus(`${enabled ? "Enabling" : "Disabling"} ${policy} fleet-wide…`);
    let r;
    try { r = await api("POST", `/api/policies/${encodeURIComponent(policy)}${ns ? `?namespace=${encodeURIComponent(ns)}` : ""}`, { enabled }); } catch (e) { return; }
    if (!r.ok) {
      setStatus(`${policy}: ${r.data && (r.data.error || r.data.detail) || r.status}`, true);
    } else {
      const d = r.data;
      const failed = d.results.filter((x) => !x.ok && !x.skipped).map((x) => `${x.node_name} (${x.error || x.status})`);
      const skipped = d.results.filter((x) => x.skipped).map((x) => `${x.node_name} (${x.error})`);
      setStatus(`${policy}: applied on ${d.applied}, failed on ${d.failed}, skipped ${d.skipped}${
        failed.length ? " — failed: " + failed.join(", ") : ""}${skipped.length ? " — skipped: " + skipped.join(", ") : ""}`, d.failed > 0);
    }
    await loadPolicies();
  }

  // ── explorers ─────────────────────────────────────────────────────────

  function loadExplorers() {
    const tabs = $("#explorer-tabs");
    const frame = $("#explorer-frame");
    const paths = (me && me.explorers) || [];
    if (!paths.length) {
      tabs.innerHTML = '<span class="muted">Fleet explorers are not available on this install (certsight-test-server not found).</span>';
      frame.hidden = true;
      return;
    }
    frame.hidden = false;
    tabs.innerHTML = paths.map((p) => `<button class="nav-btn explorer-tab" data-path="${esc(p)}">${esc(EXPLORER_LABELS[p] || p)}</button>
      <a class="btn btn-quiet btn-sm" href="${esc(p)}" target="_blank" rel="noopener" title="Open in a new tab">&#8599;</a>`).join("");
    const select = (p) => {
      tabs.querySelectorAll(".explorer-tab").forEach((b) => b.classList.toggle("active", b.dataset.path === p));
      frame.src = p;
      setStatus(`${EXPLORER_LABELS[p] || p} — generated fresh from Prometheus on each load`);
    };
    tabs.querySelectorAll(".explorer-tab").forEach((b) => b.addEventListener("click", () => select(b.dataset.path)));
    select(paths[0]);
  }

  // ── audit ─────────────────────────────────────────────────────────────

  async function loadAudit() {
    setStatus("Loading audit log…");
    const table = $("#audit-table");
    let r;
    try { r = await api("GET", "/api/audit?limit=300"); } catch (e) { return; }
    if (!r.ok) { setStatus(`Audit: ${r.status}`, true); return; }
    const rows = r.data.entries.map((e) => `<tr>
      <td>${esc(e.ts)}</td><td>${esc(e.user)}</td><td>${esc(e.address)}</td>
      <td>${esc(e.action)}</td><td>${esc(e.node)}</td>
      <td>${esc(e.policy)}${e.namespace ? ` <span class="policy-ns">${esc(e.namespace)}</span>` : ""}</td>
      <td>${e.enabled === null || e.enabled === undefined ? "" : e.enabled ? "enable" : "disable"}</td>
      <td>${e.ok ? badge("ok", "ok") : badge("failed", "error")} ${esc(e.detail)}</td>
    </tr>`);
    table.innerHTML = `<thead><tr><th>Time (UTC)</th><th>User</th><th>From</th><th>Action</th><th>Node</th><th>Policy</th><th>Change</th><th>Result</th></tr></thead>
      <tbody>${rows.join("") || '<tr class="empty"><td colspan="8">Nothing recorded yet.</td></tr>'}</tbody>`;
    setStatus(`${r.data.entries.length} audit entr${r.data.entries.length === 1 ? "y" : "ies"}`);
  }

  // ── wiring ────────────────────────────────────────────────────────────

  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const form = ev.currentTarget;
    const err = $("#login-error");
    err.hidden = true;
    const r = await api("POST", "/api/login", {
      username: loginMode === "viewer" ? (loginOptions || {}).viewer_user || "viewer" : form.username.value,
      password: form.password.value,
    });
    if (!r.ok) {
      err.textContent = r.status === 429 ? "Too many attempts — wait a minute."
        : loginMode === "viewer" ? "That access code isn't right." : "Invalid username or password.";
      err.hidden = false;
      return;
    }
    form.password.value = "";
    await bootstrap();
  });

  $("#logout-btn").addEventListener("click", async () => {
    try { await api("POST", "/api/logout"); } catch (e) { /* already out */ }
    await bootstrap();          // no session now -> the landing page
  });
  $("#signin-btn").addEventListener("click", () => showLogin(true));
  $("#login-cancel").addEventListener("click", () => bootstrap());

  $("#refresh-btn").addEventListener("click", () => showView(currentView));
  window.addEventListener("hashchange", () => { if (me) showView((location.hash || "#nodes").slice(1)); });
  document.querySelectorAll(".nav-btn[data-view]").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));

  async function bootstrap() {
    let r;
    try { r = await api("GET", "/api/me"); } catch (e) { return; }
    if (!r.ok) { showLogin(false); return; }
    me = r.data;
    showApp();
  }

  bootstrap();
})();
