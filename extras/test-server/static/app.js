async function loadUseCases() {
  const res = await fetch('/api/use-cases');
  const useCases = await res.json();
  const list = document.getElementById('use-case-list');
  list.innerHTML = '';
  for (const uc of useCases) {
    const li = document.createElement('li');

    const button = document.createElement('button');
    button.textContent = uc.label;
    button.addEventListener('click', () => runUseCase(uc.id, button));

    const desc = document.createElement('p');
    desc.className = 'use-case-description';
    desc.textContent = uc.description;

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
        item.textContent = step;
        steps.appendChild(item);
      }
      details.appendChild(steps);

      li.appendChild(details);
    }

    list.appendChild(li);
  }
}

async function runUseCase(id, button) {
  const status = document.getElementById('run-status');
  button.disabled = true;
  status.className = '';
  status.textContent = `Running '${id}'...`;
  try {
    const res = await fetch(`/api/run/${encodeURIComponent(id)}`, { method: 'POST' });
    const result = await res.json();
    status.textContent = result.detail;
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
