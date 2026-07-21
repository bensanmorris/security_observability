const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);
}

// Server-supplied text is static/trusted (authored in use_cases.py, not
// user input), so rendering it as HTML is safe -- escape first anyway as
// defense in depth, then apply a small set of markdown-lite conventions:
// CertSight gets bolded, fenced ```lang code``` blocks become <pre><code>,
// and [text](url) becomes a link. Fenced blocks are pulled out before the
// other substitutions run, so code content is never itself bolded/linkified.
function setRichText(el, text) {
  let escaped = escapeHtml(text);

  const codeBlocks = [];
  escaped = escaped.replace(/```[a-zA-Z]*\n([\s\S]*?)```/g, (_match, code) => {
    codeBlocks.push(`<pre><code>${code.trim()}</code></pre>`);
    return ` CODEBLOCK${codeBlocks.length - 1} `;
  });

  let html = escaped
    .replace(/CertSight/g, '<strong>CertSight</strong>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

  html = html.replace(/ CODEBLOCK(\d+) /g, (_match, i) => codeBlocks[Number(i)]);

  el.innerHTML = html;
}

async function loadUseCases() {
  const res = await fetch('/api/use-cases');
  const useCases = await res.json();
  const list = document.getElementById('use-case-list');
  list.innerHTML = '';
  for (const uc of useCases) {
    const li = document.createElement('li');

    const button = document.createElement('button');
    button.textContent = uc.label;
    button.addEventListener('click', () => runUseCase(uc.id, button, li));

    const desc = document.createElement('p');
    desc.className = 'use-case-description';
    setRichText(desc, uc.description);

    if (uc.params && uc.params.length > 0) {
      const paramsDiv = document.createElement('div');
      paramsDiv.className = 'use-case-params';
      for (const param of uc.params) {
        const label = document.createElement('label');
        label.textContent = param.label;
        let control;
        if (param.type === 'checkbox') {
          control = document.createElement('input');
          control.type = 'checkbox';
          control.checked = param.default === 'true';
        } else if (param.type === 'number') {
          control = document.createElement('input');
          control.type = 'number';
          control.value = param.default;
          if (param.min != null) control.min = param.min;
          if (param.max != null) control.max = param.max;
        } else {
          control = document.createElement('select');
          for (const option of param.options) {
            const opt = document.createElement('option');
            opt.value = option;
            opt.textContent = option;
            if (option === param.default) opt.selected = true;
            control.appendChild(opt);
          }
        }
        control.dataset.paramName = param.name;
        label.appendChild(control);
        paramsDiv.appendChild(label);
      }
      li.appendChild(paramsDiv);
    }

    li.appendChild(button);
    li.appendChild(desc);

    if (uc.pipeline && uc.pipeline.length > 0) {
      const details = document.createElement('details');
      details.className = 'use-case-pipeline';

      const summary = document.createElement('summary');
      summary.textContent = 'How this works';
      details.appendChild(summary);

      const steps = document.createElement('ol');
      for (const step of uc.pipeline) {
        const item = document.createElement('li');
        setRichText(item, step);
        steps.appendChild(item);
      }
      details.appendChild(steps);

      li.appendChild(details);
    }

    list.appendChild(li);
  }
}

// Tracks the CN tokens this browser tab's own use-case runs have generated
// (see use_cases.py's _resolve_token(), folded into every CN it produces)
// so the Kafka pane can show only this visitor's activity instead of
// everyone's on a shared/public test-server instance. Backed by
// sessionStorage so a reload doesn't lose it, but scoped to the tab -- a
// fresh tab is a fresh "session" with no prior activity to filter in.
const MY_TOKENS_KEY = 'certsight-my-tokens';

// Generated here, client-side, rather than left to use_cases.py -- the
// Kafka pane's SSE filter (connectEventStream() below) can only show an
// event once its token is in `myTokens`, and the detection pipeline
// (Tetragon kprobe -> cert-analyzer -> Kafka -> this page's SSE stream)
// can complete faster than /api/run/<id>'s own HTTP response reaches this
// tab -- a server-generated token, only known after that response, was
// consistently losing that race for fast/bundled detections (e.g. the
// multi-cert chain use cases publish several events within milliseconds),
// silently dropping every event for the run with no way to recover it
// after the fact. Generating and remembering the token before the request
// is even sent closes the race instead of just narrowing it. Uses
// getRandomValues() rather than crypto.randomUUID(), which MDN documents
// as secure-context-only -- this page is plain HTTP on a non-localhost
// origin (e.g. the AWS demo), not a secure context.
function generateClientToken() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function loadMyTokens() {
  try {
    return new Set(JSON.parse(sessionStorage.getItem(MY_TOKENS_KEY) || '[]'));
  } catch (err) {
    return new Set();
  }
}

function rememberMyToken(token) {
  if (!token) return;
  myTokens.add(token);
  try {
    sessionStorage.setItem(MY_TOKENS_KEY, JSON.stringify([...myTokens]));
  } catch (err) {
    // sessionStorage unavailable (e.g. private browsing) -- filtering still
    // works for the rest of this page load via the in-memory Set alone
  }
}

const myTokens = loadMyTokens();

async function runUseCase(id, button, li) {
  const status = document.getElementById('run-status');
  button.disabled = true;
  status.className = '';
  status.textContent = `Running '${id}'...`;
  const params = {};
  for (const el of li.querySelectorAll('[data-param-name]')) {
    params[el.dataset.paramName] = el.type === 'checkbox' ? String(el.checked) : el.value;
  }
  // Remembered *before* the request is sent -- see generateClientToken()'s
  // comment above for why that ordering is what actually closes the race.
  const clientToken = generateClientToken();
  rememberMyToken(clientToken);
  params.token = clientToken;
  try {
    const res = await fetch(`/api/run/${encodeURIComponent(id)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    if (!res.ok) {
      // A proxy in front of this server (e.g. the AWS demo's nginx rate
      // limiter) can reject the request before it ever reaches here,
      // returning an HTML error page instead of JSON -- report that
      // clearly rather than letting res.json() throw a cryptic
      // "unexpected character" SyntaxError.
      status.textContent = res.status === 429
        ? 'Rate limited -- wait a few seconds and try again.'
        : `Request failed: HTTP ${res.status} ${res.statusText}`;
      status.className = 'error';
      return;
    }
    const result = await res.json();
    // Normally a no-op (result.token already equals clientToken) -- catches
    // the fallback path if the server ever ends up minting its own token.
    rememberMyToken(result.token);
    setRichText(status, result.detail);
    status.className = result.ok ? 'ok' : 'error';
  } catch (err) {
    status.textContent = `Request failed: ${err}`;
    status.className = 'error';
  } finally {
    button.disabled = false;
  }
}

function connectEventStream() {
  const log = document.getElementById('event-log');
  const source = new EventSource('/api/events');
  source.onmessage = (evt) => {
    let parsed;
    try {
      parsed = JSON.parse(evt.data);
    } catch (err) {
      // not JSON -- cert-analyzer's schema is always JSON in practice, but
      // there's no CN to attribute this to, so drop it rather than risk
      // showing another visitor's activity
      return;
    }
    const commonName = parsed && typeof parsed.common_name === 'string' ? parsed.common_name : '';
    const isMine = [...myTokens].some((token) => commonName.includes(token));
    if (!isMine) return;

    const entry = document.createElement('pre');
    entry.textContent = `[${new Date().toLocaleTimeString()}]\n${JSON.stringify(parsed, null, 2)}`;
    log.prepend(entry);
  };
}

loadUseCases();
connectEventStream();
