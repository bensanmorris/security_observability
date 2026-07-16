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

async function runUseCase(id, button, li) {
  const status = document.getElementById('run-status');
  button.disabled = true;
  status.className = '';
  status.textContent = `Running '${id}'...`;
  const params = {};
  for (const el of li.querySelectorAll('[data-param-name]')) {
    params[el.dataset.paramName] = el.type === 'checkbox' ? String(el.checked) : el.value;
  }
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
    let text = evt.data;
    try {
      text = JSON.stringify(JSON.parse(evt.data), null, 2);
    } catch (err) {
      // not JSON -- show the raw payload as-is
    }
    const entry = document.createElement('pre');
    entry.textContent = `[${new Date().toLocaleTimeString()}]\n${text}`;
    log.prepend(entry);
  };
}

loadUseCases();
connectEventStream();
