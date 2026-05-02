const COLORS = {
  camera: '#6c3fff',
  printer: '#1a6bff',
  wap: '#f59e0b',
  'non-iot': '#64748b',
};

requireSignedInUser();

function emptyPanel(message) {
  return `<div class="report-empty">${message}</div>`;
}

function riskRow(label, key, value, max) {
  const pct = max ? Math.round((value / max) * 100) : 0;
  return `
    <div class="bar-row">
      <div class="bar-label">${label}</div>
      <div class="bar-track"><div class="bar-fill ${key}" style="width:${pct}%"></div></div>
      <div class="bar-value">${value}</div>
    </div>
  `;
}

function renderRiskChart(counts) {
  const total = (counts.high || 0) + (counts.med || 0) + (counts.low || 0);
  if (!total) {
    document.getElementById('risk-total').textContent = 'No devices';
    document.getElementById('risk-chart').innerHTML = emptyPanel('Run a scan to see risk distribution.');
    return;
  }

  const max = Math.max(counts.high || 0, counts.med || 0, counts.low || 0, 1);
  document.getElementById('risk-total').textContent = `${total} devices`;
  document.getElementById('risk-chart').innerHTML = [
    riskRow('High', 'high', counts.high || 0, max),
    riskRow('Medium', 'med', counts.med || 0, max),
    riskRow('Low', 'low', counts.low || 0, max),
  ].join('');
}

function renderDeviceMix(counts) {
  const entries = [
    ['camera', 'IP Cameras', counts.camera || 0],
    ['printer', 'Printers', counts.printer || 0],
    ['wap', 'Wireless APs', counts.wap || 0],
    ['non-iot', 'Computers', counts['non-iot'] || 0],
  ];
  const total = entries.reduce((sum, item) => sum + item[2], 0);
  if (!total) {
    document.getElementById('type-donut').classList.add('empty');
    document.getElementById('type-donut').style.background = '';
    document.getElementById('type-legend').innerHTML = emptyPanel('No device mix yet. Scan a network first.');
    return;
  }

  document.getElementById('type-donut').classList.remove('empty');
  let start = 0;
  const stops = entries.map(([key, , value]) => {
    const end = start + (value / total) * 100;
    const segment = `${COLORS[key]} ${start}% ${end}%`;
    start = end;
    return segment;
  });
  document.getElementById('type-donut').style.background = `conic-gradient(${stops.join(',')})`;
  document.getElementById('type-legend').innerHTML = entries.map(([key, label, value]) => `
    <div class="legend-row">
      <div class="legend-left"><span class="legend-dot" style="background:${COLORS[key]}"></span>${label}</div>
      <strong>${value}</strong>
    </div>
  `).join('');
}

function renderHistory(scans) {
  const body = document.getElementById('scan-history');
  if (!scans.length) {
    body.innerHTML = '<tr><td colspan="6" class="mono table-empty">No scan data yet for this account.</td></tr>';
    return;
  }
  body.innerHTML = scans.map(scan => `
    <tr>
      <td>${scan.organization || 'Default Organization'}</td>
      <td class="mono">${scan.network_range}</td>
      <td class="mono">${scan.scanned_at}</td>
      <td>${scan.total_devices}</td>
      <td>${scan.iot_devices}</td>
      <td><span class="risk-badge ${scan.high_risk > 0 ? 'high' : 'low'}">${scan.high_risk}</span></td>
    </tr>
  `).join('');
}

function analyticsUrl(path) {
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

function setReportDownloadLink() {
  const link = document.querySelector('.report-download');
  if (link) link.href = analyticsUrl('/api/report.pdf');
}

function loadAnalytics() {
  const profile = getSavedProfile() || {};
  if (!profile.organization || profile.organization === DEFAULT_ORGANIZATION) {
    renderRiskChart({});
    renderDeviceMix({});
    renderHistory([]);
    return;
  }

  setReportDownloadLink();

  renderRiskChart({});
  renderDeviceMix({});
  renderHistory([]);

  fetch(analyticsUrl('/api/analytics'))
    .then(r => r.json())
    .then(data => {
      renderRiskChart(data.riskCounts || {});
      renderDeviceMix(data.typeCounts || {});
      renderHistory(data.scans || []);
    })
    .catch(() => {
      document.getElementById('risk-chart').innerHTML = emptyPanel('Could not load risk data.');
      document.getElementById('type-legend').innerHTML = emptyPanel('Could not load device mix.');
      renderHistory([]);
    });
}

window.addEventListener('sentinet-profile-ready', loadAnalytics);

renderRiskChart({});
renderDeviceMix({});
renderHistory([]);
