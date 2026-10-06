const state = { events: [], alerts: [], scenarios: [] };
const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));

async function request(url, options) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function setData(data, message = '') {
  state.events = data.events || [];
  state.alerts = data.alerts || [];
  $('#message').textContent = message;
  render();
}

function render() {
  $('#event-count').textContent = state.events.length;
  $('#alert-count').textContent = state.alerts.length;
  $('#alerts-pill').textContent = state.alerts.length;
  $('#nav-alert-count').textContent = state.alerts.length;
  $('#urgent-count').textContent = state.alerts.filter((a) => ['high','critical'].includes(a.severity)).length;

  const alerts = $('#alert-list');
  alerts.innerHTML = state.alerts.length ? state.alerts.map((item) => `
    <article class="alert-card ${escapeHtml(item.severity)}">
      <div class="alert-title-row"><span class="alert-title">${escapeHtml(item.title)}</span><span class="severity">${escapeHtml(item.severity.toUpperCase())}</span></div>
      <p>${escapeHtml(item.description)}</p>
      <div class="alert-meta"><span class="tag">${escapeHtml(item.id)}</span><span class="tag">${escapeHtml(item.technique_id)} · ${escapeHtml(item.technique_name)}</span><span class="tag">${item.event_ids.length} event${item.event_ids.length === 1 ? '' : 's'}</span></div>
      <div class="recommendation"><strong>Suggested review:</strong> ${escapeHtml(item.recommendation)}</div>
    </article>`).join('') : '<div class="empty">No alerts in this dataset. Try one of the safe scenarios above.</div>';

  const filter = $('#search-input').value.trim().toLowerCase();
  const shownEvents = state.events.filter((event) => JSON.stringify(event).toLowerCase().includes(filter));
  $('#event-rows').innerHTML = shownEvents.length ? shownEvents.map((event) => `<tr>
    <td>${escapeHtml(event.timestamp.replace('T',' ').replace('Z',' UTC'))}</td><td>${escapeHtml(event.event_type)}</td>
    <td>${escapeHtml(event.username)}</td><td>${escapeHtml(event.src_ip)}</td><td>${escapeHtml(event.host)}</td>
    <td>${escapeHtml(event.command_line || event.target || event.source)}</td></tr>`).join('') : '<tr><td colspan="6" class="empty">No matching events.</td></tr>';
}

async function loadScenarios() {
  state.scenarios = await request('/api/scenarios');
  $('#scenario-list').innerHTML = state.scenarios.map((scenario) => `<button class="scenario-card" data-scenario="${escapeHtml(scenario.id)}">
    <strong>${escapeHtml(scenario.name)}</strong><small>${escapeHtml(scenario.summary)}</small><span>RUN SCENARIO ↗</span></button>`).join('');
  document.querySelectorAll('[data-scenario]').forEach((button) => button.addEventListener('click', async () => {
    button.disabled = true;
    try { const result = await request('/api/scenario', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:button.dataset.scenario})}); setData(result, `Loaded scenario: ${result.scenario}`); }
    catch (error) { $('#message').textContent = error.message; }
    finally { button.disabled = false; }
  }));
}

$('#file-input').addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  $('#message').textContent = '';
  try {
    if (file.size > 1_000_000) throw new Error('The file is larger than 1 MB.');
    const events = JSON.parse(await file.text());
    const result = await request('/api/analyze', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(events)});
    setData(result, `Analyzed ${result.events.length} events from ${file.name}.`);
  } catch (error) { $('#message').textContent = error.message; }
  event.target.value = '';
});

$('#search-input').addEventListener('input', render);
$('#reset-button').addEventListener('click', async () => {
  try { setData(await request('/api/events'), 'Demo data restored.'); }
  catch (error) { $('#message').textContent = error.message; }
});
$('#export-button').addEventListener('click', () => {
  const report = {generated_at: new Date().toISOString(), note:'TraceGuard local demo; sample events are synthetic.', summary:{events:state.events.length,alerts:state.alerts.length},alerts:state.alerts,events:state.events};
  const blob = new Blob([JSON.stringify(report,null,2)], {type:'application/json'});
  const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'traceguard-incident-report.json'; link.click(); URL.revokeObjectURL(link.href);
});

(async function start() {
  try { await loadScenarios(); setData(await request('/api/events')); }
  catch (error) { $('#message').textContent = `Could not load TraceGuard: ${error.message}. Check that the local server is running.`; }
})();
