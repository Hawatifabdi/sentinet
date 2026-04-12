/* ─────────────────────────────────────────
   SENTINET DASHBOARD — dashboard.js
   ───────────────────────────────────────── */

// ─────────────────────────────────────────
//  MOCK DATA
// ─────────────────────────────────────────
const MOCK_DEVICES = [
  {
    id: 1,
    name: "Hikvision DS-2CD2143",
    mac: "A4:14:37:9B:2C:11",
    ip: "192.168.1.101",
    type: "camera",
    typeLabel: "IP Camera",
    isIot: true,
    risk: "high",
    status: "online",
    manufacturer: "Hikvision",
    firmware: "V5.4.0 build 160401",
    firmwareStatus: "outdated",
    password: "default",
    ports: [
      { port: 80,   service: "HTTP",  safe: false },
      { port: 443,  service: "HTTPS", safe: true  },
      { port: 554,  service: "RTSP",  safe: false },
      { port: 8000, service: "SDK",   safe: false },
    ],
    policyCompliant: false,
    vulnerabilities: [
      { sev: "high", title: "Default admin credentials active",        desc: "Device still uses factory default username/password." },
      { sev: "high", title: "Outdated firmware (CVE-2021-36260)",      desc: "Remote code execution vulnerability in firmware < V5.5.800." },
      { sev: "med",  title: "Unencrypted RTSP stream on port 554",     desc: "Video stream transmitted without TLS encryption." },
      { sev: "low",  title: "HTTP management interface exposed",        desc: "Admin panel accessible over unencrypted HTTP." },
    ]
  },
  {
    id: 2,
    name: "Canon imageRUNNER 2630",
    mac: "00:1E:8F:A2:3D:77",
    ip: "192.168.1.112",
    type: "printer",
    typeLabel: "Printer",
    isIot: true,
    risk: "med",
    status: "online",
    manufacturer: "Canon",
    firmware: "03.07 (2023-11-14)",
    firmwareStatus: "current",
    password: "weak",
    ports: [
      { port: 443,  service: "HTTPS", safe: true  },
      { port: 631,  service: "IPP",   safe: true  },
      { port: 9100, service: "RAW",   safe: false },
    ],
    policyCompliant: false,
    vulnerabilities: [
      { sev: "med", title: "Weak administrator password detected", desc: "Password does not meet minimum complexity requirements." },
      { sev: "med", title: "Raw print port 9100 open",             desc: "Unfiltered raw printing port allows unauthorized print jobs." },
      { sev: "low", title: "SNMP v1 enabled",                      desc: "SNMPv1 uses community strings transmitted in plaintext." },
    ]
  },
  {
    id: 3,
    name: "Cisco WAP371",
    mac: "F4:CF:E2:1A:08:4B",
    ip: "192.168.1.1",
    type: "wap",
    typeLabel: "Wireless AP",
    isIot: true,
    risk: "low",
    status: "online",
    manufacturer: "Cisco",
    firmware: "1.3.0.6 (2024-03-01)",
    firmwareStatus: "current",
    password: "strong",
    ports: [
      { port: 443, service: "HTTPS", safe: true },
      { port: 22,  service: "SSH",   safe: true },
    ],
    policyCompliant: true,
    vulnerabilities: [
      { sev: "low", title: "SSH version 1 fallback enabled", desc: "Device allows fallback to deprecated SSHv1 protocol." },
    ]
  },
  {
    id: 4,
    name: "TP-Link EAP245",
    mac: "B0:95:75:4D:E0:21",
    ip: "192.168.1.2",
    type: "wap",
    typeLabel: "Wireless AP",
    isIot: true,
    risk: "high",
    status: "online",
    manufacturer: "TP-Link",
    firmware: "2.0.0 build 20190118",
    firmwareStatus: "outdated",
    password: "default",
    ports: [
      { port: 80,  service: "HTTP",   safe: false },
      { port: 443, service: "HTTPS",  safe: true  },
      { port: 23,  service: "Telnet", safe: false },
    ],
    policyCompliant: false,
    vulnerabilities: [
      { sev: "high", title: "Telnet service active on port 23",       desc: "Telnet transmits credentials in plaintext. Disable immediately." },
      { sev: "high", title: "Default credentials unchanged",          desc: "Admin account still using factory default password." },
      { sev: "med",  title: "Firmware critically outdated (2019)",    desc: "Multiple known CVEs unpatched in this firmware version." },
    ]
  },
  {
    id: 5,
    name: "HP LaserJet Pro M404",
    mac: "3C:D9:2B:44:FA:90",
    ip: "192.168.1.118",
    type: "printer",
    typeLabel: "Printer",
    isIot: true,
    risk: "low",
    status: "online",
    manufacturer: "HP",
    firmware: "002.1931B (2024-08-10)",
    firmwareStatus: "current",
    password: "strong",
    ports: [
      { port: 443, service: "HTTPS", safe: true },
      { port: 631, service: "IPP",   safe: true },
    ],
    policyCompliant: true,
    vulnerabilities: [
      { sev: "low", title: "Web services discovery enabled", desc: "HP Smart device discovery may expose device on WAN if misconfigured." },
    ]
  },
  {
    id: 6,
    name: "Dell Latitude 5540",
    mac: "D4:BE:D9:11:2A:CC",
    ip: "192.168.1.50",
    type: "non-iot",
    typeLabel: "Laptop",
    isIot: false,
    risk: "low",
    status: "online",
    manufacturer: "Dell",
    firmware: "Windows 11 (23H2)",
    firmwareStatus: "current",
    password: "strong",
    ports: [
      { port: 443, service: "HTTPS", safe: true },
    ],
    policyCompliant: true,
    vulnerabilities: [
      { sev: "low", title: "Remote Desktop (RDP) not restricted by firewall", desc: "RDP access is open within the LAN; consider whitelisting." },
    ]
  },
  {
    id: 7,
    name: "Dahua IPC-HDW2831T",
    mac: "E0:50:8B:C3:77:12",
    ip: "192.168.1.105",
    type: "camera",
    typeLabel: "IP Camera",
    isIot: true,
    risk: "med",
    status: "online",
    manufacturer: "Dahua",
    firmware: "V2.800.0000000.34 (2022-06-08)",
    firmwareStatus: "outdated",
    password: "strong",
    ports: [
      { port: 443,   service: "HTTPS", safe: true  },
      { port: 554,   service: "RTSP",  safe: false },
      { port: 37777, service: "P2P",   safe: false },
    ],
    policyCompliant: false,
    vulnerabilities: [
      { sev: "med", title: "Firmware out of date",         desc: "Current firmware has known authentication bypass (CVE-2022-30563)." },
      { sev: "med", title: "P2P cloud service port open",  desc: "Port 37777 exposes device to Dahua cloud relay — disable if not needed." },
    ]
  },
];

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
function startScan() {
  const btn      = document.getElementById('btn-scan');
  const icon     = document.getElementById('scan-icon');
  const progress = document.getElementById('scan-progress');
  const fill     = document.getElementById('progress-fill');
  const label    = document.getElementById('progress-label');

  btn.disabled = true;
  icon.innerHTML = '<path d="M21 12a9 9 0 1 1-6.219-8.56"/>';
  btn.querySelector('svg').style.animation = 'spin 1s linear infinite';

  progress.style.display = 'block';
  document.getElementById('empty-state').style.display = 'none';

  const steps = [
    [10,  "Pinging hosts on 192.168.1.0/24…"],
    [25,  "Discovering active devices…"],
    [45,  "Fingerprinting device types…"],
    [60,  "Checking open ports…"],
    [74,  "Querying firmware versions…"],
    [85,  "Running policy compliance checks…"],
    [93,  "Cross-referencing NVD database…"],
    [100, "Scan complete — 7 devices found."],
  ];

  let i = 0;
  const interval = setInterval(() => {
    if (i >= steps.length) {
      clearInterval(interval);
      btn.disabled = false;
      icon.innerHTML = '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>';
      btn.querySelector('svg').style.animation = '';
      renderResults();
      return;
    }
    fill.style.width  = steps[i][0] + '%';
    label.textContent = steps[i][1];
    i++;
  }, 380);
}

// ─────────────────────────────────────────
//  RENDER RESULTS
// ─────────────────────────────────────────
function renderResults() {
  scanDone = true;

  const total     = MOCK_DEVICES.length;
  const iotDevs   = MOCK_DEVICES.filter(d => d.isIot);
  const highRisk  = MOCK_DEVICES.filter(d => d.risk === 'high');
  const compliant = MOCK_DEVICES.filter(d => d.policyCompliant);
  const pct       = Math.round((compliant.length / total) * 100);

  animateNum('stat-total', total);
  animateNum('stat-iot',   iotDevs.length);
  animateNum('stat-high',  highRisk.length);
  setTimeout(() => { document.getElementById('stat-compliant').textContent = pct + '%'; }, 800);

  document.getElementById('cnt-all').textContent     = total;
  document.getElementById('cnt-iot').textContent     = iotDevs.length;
  document.getElementById('cnt-camera').textContent  = MOCK_DEVICES.filter(d => d.type === 'camera').length;
  document.getElementById('cnt-printer').textContent = MOCK_DEVICES.filter(d => d.type === 'printer').length;
  document.getElementById('cnt-wap').textContent     = MOCK_DEVICES.filter(d => d.type === 'wap').length;
  document.getElementById('cnt-noniot').textContent  = MOCK_DEVICES.filter(d => !d.isIot).length;

  document.getElementById('stats-row').classList.add('visible');
  document.getElementById('filter-bar').classList.add('visible');

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
  if (filter === 'all')     return MOCK_DEVICES;
  if (filter === 'iot')     return MOCK_DEVICES.filter(d => d.isIot);
  if (filter === 'non-iot') return MOCK_DEVICES.filter(d => !d.isIot);
  return MOCK_DEVICES.filter(d => d.type === filter);
}

// ─────────────────────────────────────────
//  RENDER DEVICE GRID
// ─────────────────────────────────────────
function renderDeviceGrid(filter) {
  const grid    = document.getElementById('device-grid');
  const devices = getFiltered(filter);
  grid.innerHTML = '';
  grid.classList.add('visible');

  devices.forEach((d, idx) => {
    const card = buildCard(d);
    card.style.animation      = 'fadeUp 0.4s ease both';
    card.style.animationDelay = (idx * 60) + 'ms';
    grid.appendChild(card);
  });
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
  }[d.password];

  const policyPill = d.policyCompliant
    ? '<span class="pill ok">Compliant ✓</span>'
    : '<span class="pill fail">Non-compliant</span>';

  const portsHtml = d.ports.map(p =>
    `<span class="port-tag ${p.safe ? 'safe' : 'unsafe'}">${p.port}/${p.service}</span>`
  ).join('');

  const vulnsHtml = d.vulnerabilities.map(v => `
    <div class="vuln-item">
      <div class="vuln-dot ${v.sev}"></div>
      <div>
        <div class="vuln-text">${v.title}</div>
        <div class="vuln-sev">${v.sev.toUpperCase()} — ${v.desc}</div>
      </div>
    </div>
  `).join('');

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
          <div class="rs-row"><span class="rs-key">Policy</span>${policyPill}</div>
        </div>

        <div class="report-section">
          <div class="rs-title">
            <svg viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
            Open Ports
          </div>
          <div class="port-list">${portsHtml}</div>
          <div style="margin-top:10px; font-size:0.72rem; color:var(--muted);">
            <span style="color:var(--high); font-weight:600;">Red</span> = potentially unsafe &nbsp;
            <span style="color:var(--low);  font-weight:600;">Green</span> = secure
          </div>
        </div>

        <div class="report-section">
          <div class="rs-title">
            <svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Vulnerabilities (${d.vulnerabilities.length})
          </div>
          ${vulnsHtml}
        </div>

      </div>
    </div>
  `;

  return card;
}

// ─────────────────────────────────────────
//  TOGGLE CARD OPEN / CLOSED
// ─────────────────────────────────────────
function toggleCard(id) {
  const card = document.querySelector(`.device-card[data-id="${id}"]`);
  card.classList.toggle('open');
}