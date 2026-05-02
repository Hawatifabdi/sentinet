/* ─────────────────────────────────────────
   SENTINET DASHBOARD — dashboard.js
   ───────────────────────────────────────── */

let DEVICES = [];

// ─────────────────────────────────────────
//  STATE
// ─────────────────────────────────────────
let currentFilter = 'all';
let scanDone = false;

// ─────────────────────────────────────────
//  ICON SVG MAP
// ─────────────────────────────────────────
const ICON_SVG = {
  camera:    '<svg viewBox="0 0 24 24"><path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>',
  printer:   '<svg viewBox="0 0 24 24"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>',
  wap:       '<svg viewBox="0 0 24 24"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>',
  'non-iot': '<svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
};

// ─────────────────────────────────────────
//  SCAN SIMULATION
// ─────────────────────────────────────────
async function startScan() {
  const btn      = document.getElementById('btn-scan');
  const icon     = document.getElementById('scan-icon');
  const progress = document.getElementById('scan-progress');
  const fill     = document.getElementById('progress-fill');
  const label    = document.getElementById('progress-label');

  progress.style.display = 'block';
  document.getElementById('empty-state').style.display = 'none';

  const network = document.getElementById('ip-input').value.trim() || '172.20.0.0/24';
  const profile = await waitForOrganization();
  const currentUser = window.sentinetAuth ? window.sentinetAuth.currentUser : null;
  const organization = profile.organization;
  const userEmail = (currentUser && currentUser.email) || profile.email || '';
  const firebaseUid = (currentUser && currentUser.uid) || profile.uid || '';

  if (!organization || organization === DEFAULT_ORGANIZATION) {
    progress.style.display = 'block';
    label.textContent = 'Could not load your organization. Please sign out and sign in again.';
    return;
  }

  btn.disabled = true;
  icon.innerHTML = '<path d="M21 12a9 9 0 1 1-6.219-8.56"/>';
  btn.querySelector('svg').style.animation = 'spin 1s linear infinite';

  const steps = [
    [10,  `Pinging hosts on ${network}…`],
    [25,  "Discovering active devices…"],
    [45,  "Fingerprinting device types…"],
    [60,  "Checking open ports…"],
    [74,  "Querying firmware versions…"],
    [85,  "Checking default credentials…"],
    [93,  "Cross-referencing NVD CVE database…"],
    [100, "Finalising scan report…"],
  ];

  let i = 0;
  const interval = setInterval(() => {
    if (i >= steps.length) return;
    fill.style.width  = steps[i][0] + '%';
    label.textContent = steps[i][1];
    i++;
  }, 380);

  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ network, organization, userEmail, firebaseUid, useNvd: true })
  })
    .then(async r => {
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        throw new Error(data.detail || data.hint || data.error || 'Scan failed');
      }
      return data;
    })
    .then(data => {
      DEVICES = data.devices || [];
      fill.style.width = '100%';
      label.textContent = `Scan complete — ${DEVICES.length} devices found.`;
      renderResults();
    })
    .catch(err => {
      label.textContent = `Scan failed: ${err.message}`;
    })
    .finally(() => {
      clearInterval(interval);
      btn.disabled = false;
      icon.innerHTML = '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>';
      btn.querySelector('svg').style.animation = '';
    });
}

function waitForOrganization(timeoutMs = 2500) {
  const current = getSavedProfile() || {};
  if (current.organization && current.organization !== DEFAULT_ORGANIZATION) {
    return Promise.resolve(current);
  }

  return new Promise(resolve => {
    const timer = setTimeout(() => {
      window.removeEventListener('sentinet-profile-ready', onReady);
      resolve(getSavedProfile() || {});
    }, timeoutMs);

    function onReady(event) {
      const profile = event.detail || getSavedProfile() || {};
      if (profile.organization && profile.organization !== DEFAULT_ORGANIZATION) {
        clearTimeout(timer);
        window.removeEventListener('sentinet-profile-ready', onReady);
        resolve(profile);
      }
    }

    window.addEventListener('sentinet-profile-ready', onReady);
  });
}

// ─────────────────────────────────────────
//  RENDER RESULTS
// ─────────────────────────────────────────
function renderResults() {
  scanDone = true;

  const total     = DEVICES.length;
  const iotDevs   = DEVICES.filter(d => d.isIot);
  const highRisk  = DEVICES.filter(d => d.risk === 'high');
  const findings  = DEVICES.reduce((sum, d) => sum + d.vulnerabilities.length, 0);

  animateNum('stat-total', total);
  animateNum('stat-iot',   iotDevs.length);
  animateNum('stat-high',  highRisk.length);
  animateNum('stat-findings', findings);

  document.getElementById('cnt-all').textContent     = total;
  document.getElementById('cnt-iot').textContent     = iotDevs.length;
  document.getElementById('cnt-camera').textContent  = DEVICES.filter(d => d.type === 'camera').length;
  document.getElementById('cnt-printer').textContent = DEVICES.filter(d => d.type === 'printer').length;
  document.getElementById('cnt-wap').textContent     = DEVICES.filter(d => d.type === 'wap').length;
  document.getElementById('cnt-noniot').textContent  = DEVICES.filter(d => !d.isIot).length;

  const statsRow = document.getElementById('stats-row');
  const filterBar = document.getElementById('filter-bar');
  statsRow.style.display = 'grid';
  filterBar.style.display = 'flex';
  statsRow.classList.add('visible');
  filterBar.classList.add('visible');

  renderDeviceGrid(currentFilter);
}

function animateNum(id, target) {
  const el   = document.getElementById(id);
  let current = 0;
  const step  = Math.ceil(target / 20);
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = current;
    if (current >= target) clearInterval(timer);
  }, 40);
}

// ─────────────────────────────────────────
//  FILTER
// ─────────────────────────────────────────
function setFilter(filter, btn) {
  currentFilter = filter;
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  if (scanDone) renderDeviceGrid(filter);
}

function getFiltered(filter) {
  if (filter === 'all')     return DEVICES;
  if (filter === 'iot')     return DEVICES.filter(d => d.isIot);
  if (filter === 'non-iot') return DEVICES.filter(d => !d.isIot);
  return DEVICES.filter(d => d.type === filter);
}

// ─────────────────────────────────────────
//  RENDER DEVICE GRID
// ─────────────────────────────────────────
function renderDeviceGrid(filter) {
  const grid    = document.getElementById('device-grid');
  const devices = getFiltered(filter);
  grid.innerHTML = '';
  grid.classList.add('visible');

  if (!devices.length) {
    grid.innerHTML = `
      <div class="filter-empty">
        No ${filterLabel(filter).toLowerCase()} devices found in this scan.
      </div>
    `;
    return;
  }

  devices.forEach((d, idx) => {
    const card = buildCard(d);
    card.style.animation      = 'fadeUp 0.4s ease both';
    card.style.animationDelay = (idx * 60) + 'ms';
    grid.appendChild(card);
  });
}

function filterLabel(filter) {
  return {
    all: 'matching',
    iot: 'IoT',
    'non-iot': 'non-IoT',
    camera: 'IP camera',
    printer: 'printer',
    wap: 'WAP',
  }[filter] || filter;
}

// ─────────────────────────────────────────
//  BUILD DEVICE CARD
// ─────────────────────────────────────────
function buildCard(d) {
  const card = document.createElement('div');
  card.className  = `device-card ${d.risk}-risk`;
  card.dataset.id = d.id;

  const fwPill = d.firmwareStatus === 'current'
    ? '<span class="pill ok">Up to date</span>'
    : '<span class="pill fail">Outdated</span>';

  const pwPill = {
    default: '<span class="pill fail">Default ⚠</span>',
    weak:    '<span class="pill warn">Weak</span>',
    strong:  '<span class="pill ok">Strong ✓</span>',
    unknown: '<span class="pill warn">Unknown</span>',
  }[d.password] || '<span class="pill warn">Unknown</span>';

  const portsHtml = d.ports.map(p =>
    `<span class="port-tag ${p.safe ? 'safe' : 'unsafe'}">${p.port}/${p.service}</span>`
  ).join('');

  const cveFindings = d.vulnerabilities.filter(v => v.source === 'nvd' || String(v.title).startsWith('CVE-'));
  const localFindings = d.vulnerabilities.filter(v => !cveFindings.includes(v));
  const cvesHtml = cveFindings.length > 0
    ? `<div class="cve-list">${cveFindings.slice(0, 4).map(v => `
      <div class="cve-row">
        <span class="cve-id">${v.title}</span>
        <span class="cve-score ${v.sev}">CVSS ${v.cvss}</span>
      </div>
    `).join('')}</div>`
    : '<div class="cve-empty">No NVD CVEs found for this device.</div>';

  const explanationHtml = buildSimpleExplanation(d, cveFindings, localFindings);
  const iconKey = ICON_SVG[d.type] ? d.type : 'non-iot';

  card.innerHTML = `
    <div class="dc-header" onclick="toggleCard(${d.id})">
      <div class="dc-header-left">
        <div class="dc-icon ${d.isIot ? d.type : 'generic'}">${ICON_SVG[iconKey]}</div>
        <div class="dc-info">
          <div class="dc-name">${d.name}</div>
          <div class="dc-mac">MAC: ${d.mac} &nbsp;·&nbsp; ${d.ip}</div>
        </div>
      </div>
      <div class="dc-header-right">
        <span class="dc-type-pill">${d.typeLabel}</span>
        <span class="risk-badge ${d.risk}">${d.risk.toUpperCase()}</span>
        <div class="dc-toggle">
          <svg viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
        </div>
      </div>
    </div>

    <div class="dc-body" id="body-${d.id}">
      <div class="dc-body-inner">

        <div class="report-section">
          <div class="rs-title">
            <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Device Info
          </div>
          <div class="rs-row"><span class="rs-key">Manufacturer</span><span class="rs-val">${d.manufacturer}</span></div>
          <div class="rs-row"><span class="rs-key">IP Address</span><span class="rs-val">${d.ip}</span></div>
          <div class="rs-row"><span class="rs-key">MAC Address</span><span class="rs-val">${d.mac}</span></div>
          <div class="rs-row"><span class="rs-key">Status</span><span class="pill ok" style="font-size:0.7rem;">${d.status}</span></div>
        </div>

        <div class="report-section">
          <div class="rs-title">
            <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Security Checks
          </div>
          <div class="rs-row"><span class="rs-key">Firmware</span>${fwPill}</div>
          <div class="rs-row"><span class="rs-key">Firmware ver.</span><span class="rs-val" style="font-size:0.72rem;">${d.firmware}</span></div>
          <div class="rs-row"><span class="rs-key">Password</span>${pwPill}</div>
          <div class="rs-row"><span class="rs-key">ML Confidence</span><span class="rs-val">${d.mlConfidence || 0}%</span></div>
        </div>

        <div class="report-section">
          <div class="rs-title">
            <svg viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
            Open Ports & NVD CVEs
          </div>
          <div class="port-list">${portsHtml}</div>
          <div style="margin-top:10px; font-size:0.72rem; color:var(--muted);">
            <span style="color:var(--high); font-weight:600;">Red</span> = potentially unsafe &nbsp;
            <span style="color:var(--low);  font-weight:600;">Green</span> = secure
          </div>
          <div class="cve-block">
            <div class="mini-label">NVD matches</div>
            ${cvesHtml}
          </div>
        </div>

        <div class="report-section">
          <div class="rs-title">
            <svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Simple Explanation
          </div>
          ${explanationHtml}
        </div>

      </div>
    </div>
  `;

  return card;
}

function buildSimpleExplanation(device, cveFindings, localFindings) {
  const riskText = {
    high: 'This device should be reviewed first because it has strong risk signals.',
    med: 'This device needs attention, but it is not the most urgent item in the scan.',
    low: 'This device has no major warning signs from the checks performed.',
  }[device.risk] || 'This device needs a manual review.';

  const reasons = [];
  if (cveFindings.length) {
    reasons.push(`${cveFindings.length} NVD CVE match${cveFindings.length === 1 ? '' : 'es'} found.`);
  }
  if (localFindings.length) {
    reasons.push(localFindings.map(v => v.title).slice(0, 2).join(', '));
  }
  if (!reasons.length) {
    reasons.push('No CVEs, default credentials, or outdated firmware were found.');
  }

  return `
    <p class="simple-text">${riskText}</p>
    <p class="simple-text">${reasons.join(' ')}</p>
  `;
}

window.addEventListener('DOMContentLoaded', () => {
  requireSignedInUser();
  // Dashboard starts empty - user must click "Scan Network" to begin
  document.getElementById('empty-state').style.display = 'block';
  document.getElementById('stats-row').style.display = 'none';
  document.getElementById('filter-bar').style.display = 'none';
});

// ─────────────────────────────────────────
//  TOGGLE CARD OPEN / CLOSED
// ─────────────────────────────────────────
function toggleCard(id) {
  const card = document.querySelector(`.device-card[data-id="${id}"]`);
  card.classList.toggle('open');
}
