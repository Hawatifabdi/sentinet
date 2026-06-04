requireSignedInUser();

let SECURITY_DATA = { devices: [] };

const MODULES = {
  '/recommendations': {
    key: 'recommendations',
    title: 'Security Recommendations Center',
    documentTitle: 'SentiNet - Recommendations',
  },
  '/sentinet-ai': {
    key: 'sentinet-ai',
    title: 'SentiNet AI',
    documentTitle: 'SentiNet - AI Assistant',
  },
  '/incidents': {
    key: 'incidents',
    title: 'Security Incident Center',
    documentTitle: 'SentiNet - Incidents',
  },
  '/awareness': {
    key: 'awareness',
    title: 'User Awareness Center',
    documentTitle: 'SentiNet - Awareness',
  },
};

const CURRENT_MODULE = MODULES[window.location.pathname] || MODULES['/recommendations'];

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function scopedUrl(path) {
  const profile = getSavedProfile() || {};
  const currentUser = window.sentinetAuth ? window.sentinetAuth.currentUser : null;
  const params = new URLSearchParams();
  if (currentUser && currentUser.uid) params.set('firebaseUid', currentUser.uid);
  if (currentUser && currentUser.email) params.set('userEmail', currentUser.email);
  if (!params.has('userEmail') && profile.email) params.set('userEmail', profile.email);
  if (!params.has('firebaseUid') && profile.uid) params.set('firebaseUid', profile.uid);
  if (profile.organization) params.set('organization', profile.organization);
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

function emptyBlock(message) {
  return `<div class="report-empty">${escapeHtml(message)}</div>`;
}

function renderRecommendations(items) {
  const body = document.getElementById('recommendation-body');
  if (!body) return;
  document.getElementById('recommendation-count').textContent = `${items.length} action${items.length === 1 ? '' : 's'}`;
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="4" class="mono table-empty">No remediation actions yet. Run a scan first.</td></tr>';
    return;
  }

  body.innerHTML = items.slice(0, 18).map(item => `
    <tr>
      <td>
        <strong>${escapeHtml(item.device)}</strong>
        <div class="mono muted-line">${escapeHtml(item.ip)}</div>
      </td>
      <td><span class="risk-badge ${escapeHtml(item.severity)}">${escapeHtml(item.issue)}</span></td>
      <td><strong>${escapeHtml(item.fix)}</strong></td>
      <td>
        <div>${escapeHtml(item.why)}</div>
        <details>
          <summary>Step-by-step fix</summary>
          <ol>${(item.steps || []).map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ol>
        </details>
      </td>
    </tr>
  `).join('');
}

function renderIncidents(incidents) {
  if (!document.getElementById('incident-list')) return;
  document.getElementById('incident-count').textContent = `${incidents.length} incident${incidents.length === 1 ? '' : 's'}`;
  document.getElementById('incident-list').innerHTML = incidents.length
    ? incidents.slice(0, 10).map(incident => `
      <div class="incident-card">
        <div>
          <strong>Incident #${incident.id}</strong>
          <span class="risk-badge ${escapeHtml(incident.severity)}">${escapeHtml(incident.severity)}</span>
        </div>
        <p>${escapeHtml(incident.device)} &middot; ${escapeHtml(incident.issue)}</p>
        <div class="incident-actions">
          <span>${escapeHtml(incident.assignedAction)}</span>
          <select>
            <option>Open</option>
            <option>In Progress</option>
            <option>Resolved</option>
          </select>
        </div>
      </div>
    `).join('')
    : emptyBlock('No incidents generated from the latest scan.');
}

function renderAwareness(items) {
  if (!document.getElementById('awareness-list')) return;
  const count = document.getElementById('awareness-count');
  if (count) count.textContent = `${items.length} lessons`;
  document.getElementById('awareness-list').innerHTML = items.length
    ? items.map(item => `
      <article class="awareness-item">
        <div class="awareness-meta">
          <span>${escapeHtml(item.category || 'Best practice')}</span>
          <span>${escapeHtml(item.level || 'Short lesson')}</span>
        </div>
        <strong>${escapeHtml(item.title)}</strong>
        <p>${escapeHtml(item.body)}</p>
        <ul>${(item.points || []).slice(0, 3).map(point => `<li>${escapeHtml(point)}</li>`).join('')}</ul>
        <div class="awareness-links">
          ${(item.links || []).slice(0, 3).map(link => `
            <a href="${escapeHtml(link.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(link.label)}</a>
          `).join('')}
        </div>
      </article>
    `).join('')
    : emptyBlock('Awareness content will appear after loading.');
}

function renderSecurity(data) {
  SECURITY_DATA = data;
  renderRecommendations(data.recommendations || []);
  renderIncidents(data.incidents || []);
  renderAwareness(data.awareness || []);
}

function loadSecurityCenter() {
  fetch(scopedUrl('/api/security-center'))
    .then(r => r.json())
    .then(renderSecurity)
    .catch(() => {
      renderSecurity({
        devices: [],
        recommendations: [],
        incidents: [],
        awareness: [],
      });
    });
}

function loadAiStatus() {
  const source = document.getElementById('ai-source');
  if (!source) return;

  fetch('/api/ai/status')
    .then(r => r.json())
    .then(data => {
      source.textContent = data.configured
        ? `OpenAI connected: ${data.model}`
        : 'Local fallback: add OPENAI_API_KEY';
    })
    .catch(() => {
      source.textContent = 'AI status unavailable';
    });
}

function addAiMessage(kind, text) {
  const chat = document.getElementById('ai-chat');
  if (!chat) return;
  const div = document.createElement('div');
  div.className = `ai-message ${kind}`;
  div.textContent = text;
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function askAssistant(question) {
  if (!question.trim()) return;
  addAiMessage('question', question);
  addAiMessage('answer loading', 'Thinking...');
  fetch('/api/ai/assistant', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question, devices: SECURITY_DATA.devices || [] }),
  })
    .then(r => r.json())
    .then(data => {
      const loading = document.querySelector('.ai-message.loading');
      if (loading) loading.remove();
      document.getElementById('ai-source').textContent = data.source === 'openai' ? 'OpenAI response' : 'Local response';
      addAiMessage('answer', data.answer || 'No answer returned.');
    })
    .catch(() => {
      const loading = document.querySelector('.ai-message.loading');
      if (loading) loading.remove();
      addAiMessage('answer', 'Could not contact the assistant endpoint.');
    });
}

function setupModuleView() {
  document.title = CURRENT_MODULE.documentTitle;
  const title = document.getElementById('security-title');
  if (title) title.textContent = CURRENT_MODULE.title;

  document.querySelectorAll('.security-section').forEach(section => {
    section.classList.toggle('active', section.dataset.section === CURRENT_MODULE.key);
  });

  document.querySelectorAll('.security-nav').forEach(link => {
    link.classList.toggle('active', link.dataset.module === CURRENT_MODULE.key);
  });

  const aiForm = document.getElementById('ai-form');
  if (aiForm) {
    loadAiStatus();
    aiForm.addEventListener('submit', event => {
      event.preventDefault();
      const input = document.getElementById('ai-question');
      askAssistant(input.value);
      input.value = '';
    });
  }

  document.querySelectorAll('.quick-questions button').forEach(button => {
    button.addEventListener('click', () => askAssistant(button.dataset.question));
  });
}

window.addEventListener('sentinet-profile-ready', () => {
  loadSecurityCenter();
});

renderSecurity({
  devices: [],
  recommendations: [],
  incidents: [],
  awareness: [],
});

setupModuleView();
