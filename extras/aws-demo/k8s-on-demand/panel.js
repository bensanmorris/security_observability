// Injected by nginx into the demo's console and fleet pages. Shows a Start
// panel on the test console, and a standby note on the fleet pages so a
// stopped k8s node doesn't read as a broken one.
(function () {
  "use strict";

  var onConsole = !!document.getElementById("use-cases-pane");
  var box = document.createElement("div");
  box.id = "k8s-demo-panel";
  box.setAttribute("aria-live", "polite");
  box.style.cssText = "border:1px solid #8888;border-radius:6px;padding:.6rem .9rem;margin:.75rem 0;" +
    "display:flex;flex-wrap:wrap;align-items:center;gap:.5rem .9rem;font:14px/1.4 system-ui,sans-serif;";
  var text = document.createElement("span");
  text.style.flex = "1 1 18em";
  var action = document.createElement("span");
  box.appendChild(text);
  box.appendChild(action);

  var placed = false;
  function place() {
    if (placed) return;
    placed = true;
    var main = onConsole && document.querySelector("main");
    if (main) main.parentNode.insertBefore(box, main);
    else document.body.insertBefore(box, document.body.firstChild);
  }

  var timer = null;
  function schedule(ms) {
    clearTimeout(timer);
    timer = setTimeout(refresh, ms);
  }

  function setAction(node) {
    action.textContent = "";
    if (node) action.appendChild(node);
  }

  function startButton() {
    var button = document.createElement("button");
    button.textContent = "Start k8s demo";
    button.style.cssText = "font:inherit;padding:.3rem .8rem;cursor:pointer;";
    button.addEventListener("click", function () {
      button.disabled = true;
      button.textContent = "Starting…";
      fetch("/k8s-demo/start", { method: "POST", headers: { "X-K8s-Demo": "1" } })
        .then(function (response) {
          if (response.status === 429 && !response.headers.get("content-type").match(/json/)) {
            throw new Error("rate limited");
          }
          return response.json();
        })
        .then(render)
        .catch(function () {
          text.textContent = "Couldn't start the Kubernetes demo. Please try again in a minute.";
          schedule(15000);
        });
    });
    return button;
  }

  function render(s) {
    var delay = 5000;
    if (s.phase === "ready" && !onConsole) {
      box.remove();
      placed = false;
      schedule(30000);
      return;
    }
    place();
    if (!onConsole) {
      text.textContent = "Kubernetes node: " + (s.phase === "starting" ? "starting" : "on standby") +
        ". It runs on demand, so until it's started this view covers the main node only" +
        " and may list the Kubernetes node as unreachable.";
      setAction(null);
      schedule(30000);
      return;
    }
    if (s.phase === "ready") {
      var minutes = Math.ceil(s.remaining_seconds / 60);
      text.textContent = "Kubernetes pod attribution demo is running. It stops automatically in about " +
        minutes + (minutes === 1 ? " minute." : " minutes.");
      var link = document.createElement("a");
      link.href = s.console_url;
      link.target = "_blank";
      link.rel = "noopener";
      link.textContent = "Open k8s console →";
      setAction(link);
    } else if (s.phase === "starting") {
      text.textContent = "Kubernetes pod attribution demo is starting. This usually takes about two minutes.";
      setAction(null);
    } else if (s.phase === "stopping") {
      text.textContent = "Kubernetes pod attribution demo is shutting down. You can start it again in a couple of minutes.";
      setAction(null);
    } else if (s.phase === "off" && s.can_start) {
      text.textContent = "Kubernetes pod attribution demo is off to save costs. Start it for a " +
        s.session_minutes + "-minute session.";
      setAction(startButton());
      delay = 20000;
    } else if (s.phase === "off") {
      text.textContent = "Kubernetes pod attribution demo has reached today's session limit. It resets at midnight UTC.";
      setAction(null);
      delay = 60000;
    } else {
      text.textContent = "Kubernetes pod attribution demo is unavailable right now.";
      setAction(null);
      delay = 30000;
    }
    schedule(delay);
  }

  function refresh() {
    fetch("/k8s-demo/status")
      .then(function (response) { return response.json(); })
      .then(render)
      .catch(function () { schedule(30000); });
  }

  refresh();
})();
