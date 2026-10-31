// NETMAP FULL — full-feature version, still NO real scanning.
// Default data is generated in-browser (synthetic). Imports are files the
// user pastes/uploads themselves, read only in this browser. Adapters return
// mock data unless a future server version is built. No packets, no probing.
(function () {
  'use strict';
  var canvas = document.getElementById('topology');
  var ctx = canvas.getContext('2d');
  var A = window.NetmapAdapters || {};

  var SUBNETS = ['10.0.1.0/24', '10.0.2.0/24', '10.0.3.0/24', '192.168.10.0/24'];
  var OS_BY_ROLE = {
    Core: ['RouterOS (simulated)', 'SwitchOS (simulated)'],
    Server: ['Ubuntu Server (simulated)', 'Windows Server (simulated)', 'Debian (simulated)'],
    Workstation: ['Windows 11 (simulated)', 'macOS (simulated)', 'Ubuntu Desktop (simulated)'],
    Network: ['SwitchOS (simulated)', 'FirewallOS (simulated)'],
    IoT: ['Embedded Linux (simulated)', 'Camera firmware (simulated)'],
    Printer: ['Printer firmware (simulated)'],
    Unknown: ['Unknown (simulated)']
  };
  var SERVICES_BY_ROLE = {
    Core: ['BGP (simulated)', 'SNMP (simulated)'],
    Server: ['HTTPS 443 (simulated)', 'SSH 22 (simulated)', 'PostgreSQL 5432 (simulated)'],
    Workstation: ['SMB 445 (simulated)', 'RDP 3389 (simulated)'],
    Network: ['SSH 22 (simulated)', 'HTTPS 443 (simulated)'],
    IoT: ['RTSP 554 (simulated)', 'HTTP 80 (simulated)'],
    Printer: ['IPP 631 (simulated)', 'HTTP 80 (simulated)'],
    Unknown: ['Telnet 23 (simulated)', 'HTTP 80 (simulated)']
  };
  var FIRST = ['core', 'srv', 'ws', 'sw', 'cam', 'prt', 'dev', 'fw', 'db', 'web'];
  var pick = function (arr) { return arr[Math.floor(Math.random() * arr.length)]; };
  var randInt = function (a, b) { return a + Math.floor(Math.random() * (b - a + 1)); };
  var daysAgo = function (d) { var t = new Date(); t.setDate(t.getDate() - d); return t.toLocaleDateString(); };
  var IP_RE = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  var esc = function (s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); };

  var DEFAULT_RULES = [
    { id: 'unknown', label: 'Unknown role', weight: 45, kind: 'role', match: 'Unknown' },
    { id: 'stale', label: 'Stale — not seen over threshold days', weight: 30, kind: 'stale', match: '' },
    { id: 'telnet', label: 'Service contains Telnet', weight: 40, kind: 'service', match: 'Telnet' },
    { id: 'rdp', label: 'Exposed RDP', weight: 30, kind: 'exposed-rdp', match: 'RDP' },
    { id: 'smb', label: 'SMB on a workstation', weight: 15, kind: 'smb-ws', match: 'SMB' },
    { id: 'patch', label: 'Outdated patch level', weight: 20, kind: 'patch', match: '' }
  ];
  var DEFAULT_STALE_DAYS = 30;

  var devices = [];
  var links = [];
  var selectedId = null;
  var groupMode = 'subnet';
  var history = [];
  var rules = [];
  var staleDays = DEFAULT_STALE_DAYS;
  var nextId = 1;
  // ---- Refinement Pass 3 state ----
  var subnetFocus = null;
  var simSnapshot = null;
  var tourStep = -1;
  var hoverId = null;
  var lastCompareKey = '';
  var reducedMotion = typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var PLAIN_ROLE = { Core: 'main router', Server: 'server computer', Workstation: 'laptop or desktop', Network: 'network switch', IoT: 'smart device', Printer: 'printer', Unknown: 'mystery device' };
  function plainReasons(d) {
    var out = [];
    if (d.role === 'Unknown') out.push('nobody knows what it actually is');
    if (d.lastSeenDays > staleDays) out.push('it has not been seen for ' + d.lastSeenDays + ' days');
    if (d.services.some(function (x) { return x.indexOf('Telnet') !== -1; })) out.push('it still uses Telnet, an old unsafe way to log in');
    if (d.services.some(function (x) { return x.indexOf('RDP') !== -1; }) && d.exposed) out.push('its remote desktop is exposed to others');
    if (d.services.some(function (x) { return x.indexOf('SMB') !== -1; }) && d.role === 'Workstation') out.push('it shares files in a way a workstation should not');
    if (d.patchLevel === 'Outdated') out.push('its software is out of date');
    return out;
  }
  function plainSentence(d) {
    var reasons = plainReasons(d);
    var plain = PLAIN_ROLE[d.role] || 'device';
    if (!reasons.length) return 'This ' + plain + ' (' + d.hostname + ') looks fine in the demo — nothing in the data flags it right now.';
    return 'This ' + plain + ' (' + d.hostname + ') needs attention because ' + reasons.join(', and ') + '.';
  }
  function fixSuggestion(d) {
    if (d.role === 'Unknown') return 'Find out what this device actually is, then give it a proper name and role.';
    if (d.services.some(function (x) { return x.indexOf('Telnet') !== -1; })) return 'Close Telnet — the simulator button below does exactly that, on demo data only.';
    if (d.services.some(function (x) { return x.indexOf('RDP') !== -1; }) && d.exposed) return 'Hide remote desktop behind the firewall, or turn it off if nobody needs it.';
    if (d.lastSeenDays > staleDays) return 'Check whether it is still plugged in. If not, remove it from the inventory.';
    if (d.patchLevel === 'Outdated') return 'Patch it — the simulator button below shows its score dropping when you do.';
    if (d.services.some(function (x) { return x.indexOf('SMB') !== -1; })) return 'Turn off file sharing on this workstation unless it truly needs it.';
    return 'Keep an eye on it and re-check after the next demo change.';
  }
  function rescoreDevice(d) { var r = computeRisk(d); d.riskScore = r.score; d.risk = r.level; d.flags = r.flags; d.breakdown = r.breakdown; }
  function renderTimeline() {
    var el = document.getElementById('timelineList'); if (!el) return;
    el.innerHTML = history.length ? history.map(function (h) { return '<li><b>' + esc(h.action) + '</b> — ' + esc(h.detail) + ' <span class="muted">' + esc(h.at) + '</span></li>'; }).join('') : '<li>No changes yet. Generate a network, import, or run an adapter to start the timeline.</li>';
  }
  function renderFixQueue() {
    var el = document.getElementById('fixQueue'); if (!el) return;
    var top = devices.filter(function (d) { return d.risk === 'Critical' || d.risk === 'High'; }).sort(function (a, b) { return b.riskScore - a.riskScore; }).slice(0, 5);
    if (!top.length) { el.innerHTML = '<p class="hint">Nothing urgent right now — no Critical or High devices in this network. Generate a new network to try again.</p>'; return; }
    el.innerHTML = top.map(function (d, i) { return '<div class="fix-card" tabindex="0" role="button" aria-label="Open ' + esc(d.hostname) + '" data-id="' + d.id + '"><b>#' + (i + 1) + ' — ' + esc(d.hostname) + ' · ' + d.risk + ' (' + d.riskScore + '/100)</b><p>' + esc(plainSentence(d)) + '</p><span class="fix-action">Fix first: ' + esc(fixSuggestion(d)) + ' → Click to open it</span></div>'; }).join('');
    el.querySelectorAll('.fix-card').forEach(function (card) {
      var go = function () { selectedId = Number(card.dataset.id); render(); };
      card.addEventListener('click', go);
      card.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
    });
  }
  function renderSubnet() {
    var chips = document.getElementById('subnetChips'); var detail = document.getElementById('subnetDetail'); var label = document.getElementById('subnetFocusLabel');
    if (!chips || !detail) return;
    var subs = [...new Set(devices.map(function (d) { return d.subnet; }))].sort();
    chips.innerHTML = subs.map(function (sn) { return '<button class="chip' + (subnetFocus === sn ? ' active' : '') + '" type="button" aria-pressed="' + (subnetFocus === sn) + '" data-subnet="' + esc(sn) + '">' + esc(sn) + '</button>'; }).join('') || '<p class="hint">No subnets yet — generate a network first.</p>';
    chips.querySelectorAll('.chip').forEach(function (b) { b.addEventListener('click', function () { subnetFocus = b.dataset.subnet; render(); }); });
    if (label) label.textContent = subnetFocus ? 'Drilled down to ' + subnetFocus + ' — map and table show only that neighbourhood. Click “Back to the whole network” to restore everything.' : 'Showing the whole network.';
    if (!subnetFocus) { detail.innerHTML = '<p class="hint">Whole network: ' + devices.length + ' devices across ' + subs.length + ' subnets. Pick a subnet above to zoom in.</p>'; return; }
    var list = devices.filter(function (d) { return d.subnet === subnetFocus; });
    var avg = list.length ? Math.round(list.reduce(function (a, d) { return a + d.riskScore; }, 0) / list.length) : 0;
    var worst = list.slice().sort(function (a, b) { return b.riskScore - a.riskScore; })[0];
    detail.innerHTML = '<p><b>' + esc(subnetFocus) + '</b> — ' + list.length + ' devices, average risk ' + avg + '/100.</p>' +
      (worst ? '<p>' + esc(plainSentence(worst)) + '</p><p class="hint">Devices here: ' + esc(list.slice(0, 10).map(function (d) { return d.hostname; }).join(', ')) + (list.length > 10 ? ' and ' + (list.length - 10) + ' more' : '') + '.</p>' : '<p class="hint">No devices in this subnet.</p>');
  }
  function renderSimulator() {
    var scoreEl = document.getElementById('simScore'); var before = document.getElementById('simBefore'); var after = document.getElementById('simAfter'); var dial = document.getElementById('simDial');
    if (!scoreEl || !before) return;
    var d = devices.find(function (x) { return x.id === selectedId; });
    if (!d) { scoreEl.textContent = '—'; if (dial) dial.className = 'dial'; before.textContent = 'No device selected yet — click a red or amber node first.'; if (after) after.textContent = ''; return; }
    scoreEl.textContent = d.riskScore;
    if (dial) dial.className = 'dial ' + (d.risk === 'Critical' ? 'crit' : (d.risk === 'High' || d.risk === 'Medium' ? 'warn' : 'ok'));
    before.textContent = 'Selected: ' + d.hostname + ' — ' + d.risk + ' (' + d.riskScore + '/100). ' + plainSentence(d);
  }
  function renderCompareOptions() {
    var a = document.getElementById('compareA'); var b = document.getElementById('compareB'); if (!a || !b) return;
    var key = devices.map(function (d) { return d.id + ':' + d.riskScore; }).join(',');
    if (key === lastCompareKey) return; lastCompareKey = key;
    var prevA = a.value, prevB = b.value;
    var opts = devices.map(function (d) { return '<option value="' + d.id + '">' + esc(d.hostname) + ' — ' + d.risk + ' (' + d.riskScore + ')</option>'; }).join('');
    a.innerHTML = opts; b.innerHTML = opts;
    if (prevA && devices.some(function (d) { return String(d.id) === prevA; })) a.value = prevA;
    if (prevB && devices.some(function (d) { return String(d.id) === prevB; })) b.value = prevB;
    else if (devices.length > 1) b.value = String(devices[1].id);
  }
  function simSnapshotOf(d) { return { patchLevel: d.patchLevel, services: d.services.slice(), exposed: d.exposed, lastSeenDays: d.lastSeenDays }; }
  function doSimPatch() {
    var d = devices.find(function (x) { return x.id === selectedId; }); var after = document.getElementById('simAfter');
    if (!d) { if (after) after.textContent = 'Select a device first.'; return; }
    if (!simSnapshot) simSnapshot = simSnapshotOf(d);
    var beforeScore = d.riskScore; d.patchLevel = 'Current'; rescoreDevice(d);
    logHistory('SIMULATED FIX', d.hostname + ' patched in the simulator — risk ' + beforeScore + ' → ' + d.riskScore + '.');
    render(); if (after) after.textContent = 'Patched! ' + d.hostname + ' went from ' + beforeScore + ' to ' + d.riskScore + '/100. That is what “patch it” is worth, in plain numbers.';
  }
  function doSimClose() {
    var d = devices.find(function (x) { return x.id === selectedId; }); var after = document.getElementById('simAfter');
    if (!d) { if (after) after.textContent = 'Select a device first.'; return; }
    var idx = -1; d.services.forEach(function (x, i) { if (idx === -1 && (x.indexOf('Telnet') !== -1 || x.indexOf('RDP') !== -1 || x.indexOf('SMB') !== -1 || x.indexOf('FTP') !== -1)) idx = i; });
    if (idx === -1) { if (after) after.textContent = d.hostname + ' has no Telnet, RDP, SMB or FTP service to close in this demo.'; return; }
    if (!simSnapshot) simSnapshot = simSnapshotOf(d);
    var removed = d.services.splice(idx, 1)[0]; var beforeScore = d.riskScore; rescoreDevice(d);
    logHistory('SIMULATED FIX', removed + ' closed on ' + d.hostname + ' in the simulator — risk ' + beforeScore + ' → ' + d.riskScore + '.');
    render(); if (after) after.textContent = 'Closed ' + removed + ' on ' + d.hostname + ': ' + beforeScore + ' → ' + d.riskScore + '/100.';
  }
  function doSimUndo() {
    var d = devices.find(function (x) { return x.id === selectedId; }); var after = document.getElementById('simAfter');
    if (!d || !simSnapshot) { if (after) after.textContent = 'Nothing to undo — try a simulator fix first.'; return; }
    Object.assign(d, { patchLevel: simSnapshot.patchLevel, services: simSnapshot.services.slice(), exposed: simSnapshot.exposed, lastSeenDays: simSnapshot.lastSeenDays });
    simSnapshot = null; rescoreDevice(d); logHistory('SIMULATED FIX UNDONE', d.hostname + ' restored — back to ' + d.riskScore + '/100.');
    render(); if (after) after.textContent = 'Undone. ' + d.hostname + ' is back to ' + d.riskScore + '/100.';
  }
  var tourSteps = [
    { text: 'Step 1 of 6 — This is the whole story: a live map of every device, and which ones need attention. Red first, amber soon, cyan fine.', action: null },
    { text: 'Step 2 of 6 — A fresh demo network, built in your browser. The big square in the middle is the main router; everything connects to it.', action: function () { generateNetwork(); } },
    { text: 'Step 3 of 6 — This is the fix-first queue: the riskiest devices, in plain words, with what to do about each one.', action: function () { var top = devices.filter(function (d) { return d.risk === 'Critical' || d.risk === 'High'; }).sort(function (a, b) { return b.riskScore - a.riskScore; })[0]; if (top) { selectedId = top.id; render(); } document.getElementById('fixFirstPanel').scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth' }); } },
    { text: 'Step 4 of 6 — Now the simulator: press “Patch this device” and watch its risk dial drop. Nothing real changed — it is demo maths, live.', action: function () { var el = document.getElementById('simPanel'); if (el) el.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth' }); } },
    { text: 'Step 5 of 6 — Subnets are neighbourhoods. Pick one chip and the map zooms into just that neighbourhood.', action: function () { var subs = [...new Set(devices.map(function (d) { return d.subnet; }))].sort(); if (subs.length) { subnetFocus = subs[0]; render(); } var el = document.getElementById('subnetPanel'); if (el) el.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth' }); } },
    { text: 'Step 6 of 6 — Done. The table below is the same map as a list — the handover view. Press “End tour” or generate a fresh network to play again.', action: function () { subnetFocus = null; render(); } }
  ];
  function showTour() { var t = document.getElementById('tourText'); if (t && tourStep >= 0 && tourStep < tourSteps.length) t.textContent = tourSteps[tourStep].text; }


  function loadStored(key, fallback) {
    try {
      var v = localStorage.getItem(key);
      return v ? JSON.parse(v) : fallback;
    } catch (e) { return fallback; }
  }
  function saveStored(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* private mode: history/rules just live in memory */ }
  }

  function logHistory(action, detail) {
    history.unshift({ at: new Date().toLocaleString(), action: action, detail: detail });
    history = history.slice(0, 200);
    saveStored('netmap-full-history', history);
    renderHistory();
  }

  function computeRisk(d) {
    var flags = [];
    var breakdown = [{ label: 'Base score', points: 10 }];
    var score = 10;
    var add = function (points, flag) { score += points; flags.push(flag); breakdown.push({ label: flag, points: points }); };
    rules.forEach(function (r) {
      if (r.kind === 'role' && d.role === r.match) add(r.weight, 'UNKNOWN DEVICE');
      if (r.kind === 'stale' && d.lastSeenDays > staleDays) add(r.weight, 'STALE — NOT SEEN IN ' + d.lastSeenDays + ' DAYS');
      if (r.kind === 'service' && d.services.some(function (s) { return s.indexOf(r.match) !== -1; })) add(r.weight, 'RISKY SERVICE: ' + r.match.toUpperCase() + ' (SIMULATED / IMPORTED DATA)');
      if (r.kind === 'exposed-rdp' && d.exposed && d.services.some(function (s) { return s.indexOf('RDP') !== -1; })) add(r.weight, 'EXPOSED RDP');
      if (r.kind === 'smb-ws' && d.role === 'Workstation' && d.services.some(function (s) { return s.indexOf('SMB') !== -1; })) add(r.weight, 'SMB ON WORKSTATION');
      if (r.kind === 'patch' && d.patchLevel === 'Outdated') add(r.weight, 'OUTDATED PATCH LEVEL');
      if (r.kind === 'custom-service' && r.match && d.services.some(function (s) { return s.toLowerCase().indexOf(r.match.toLowerCase()) !== -1; })) add(r.weight, 'CUSTOM RULE: SERVICE CONTAINS ' + r.match.toUpperCase());
    });
    score = Math.min(100, score);
    var level = score >= 80 ? 'Critical' : score >= 60 ? 'High' : score >= 35 ? 'Medium' : score >= 20 ? 'Low' : 'Safe';
    return { score: score, level: level, flags: flags, breakdown: breakdown };
  }
  function rescoreAll() {
    devices.forEach(function (d) { var r = computeRisk(d); d.riskScore = r.score; d.risk = r.level; d.flags = r.flags; d.breakdown = r.breakdown; });
  }

  function generateNetwork() {
    devices = []; links = []; selectedId = null; nextId = 1; subnetFocus = null; simSnapshot = null;
    var core = { id: nextId++, hostname: 'core-rtr-01', ip: '10.0.1.1', mac: '02:00:4A:11:00:01', subnet: SUBNETS[0], role: 'Core', os: 'RouterOS (simulated)', services: SERVICES_BY_ROLE.Core.slice(), lastSeenDays: 0, patchLevel: 'Current', exposed: false, source: 'generated' };
    devices.push(core);
    SUBNETS.forEach(function (subnet, si) {
      // Refinement Pass 1 fix: derive the host prefix from the subnet itself,
      // so 192.168.10.0/24 yields 192.168.10.x, not 192.168.4.x.
      var base = subnet.split('.').slice(0, 3).join('.');
      var count = si === 0 ? 8 : randInt(5, 8);
      var subnetDevices = [];
      for (var i = 0; i < count; i++) {
        var role = si === 0 && i === 0 ? 'Network' : pick(['Server', 'Server', 'Workstation', 'Workstation', 'Workstation', 'IoT', 'Printer', 'Unknown']);
        var host = pick(FIRST) + '-' + String(randInt(10, 99));
        var d = {
          id: nextId++, hostname: host + '-' + String(nextId).padStart(2, '0'),
          ip: base + '.' + (10 + i * 3 + randInt(0, 2)),
          mac: '02:00:4A:' + String(randInt(10, 99)) + ':' + String(randInt(10, 99)) + ':' + String(randInt(10, 99)),
          subnet: subnet, role: role, os: pick(OS_BY_ROLE[role]),
          services: SERVICES_BY_ROLE[role].slice(0, randInt(1, SERVICES_BY_ROLE[role].length)),
          lastSeenDays: role === 'Unknown' ? randInt(31, 90) : randInt(0, 28),
          patchLevel: Math.random() < 0.28 ? 'Outdated' : 'Current',
          exposed: Math.random() < 0.22, source: 'generated'
        };
        devices.push(d); subnetDevices.push(d);
        links.push({ from: core.id, to: d.id });
      }
      for (var j = 1; j < subnetDevices.length; j++) {
        if (Math.random() < 0.45) links.push({ from: subnetDevices[j - 1].id, to: subnetDevices[j].id });
      }
    });
    rescoreAll();
    logHistory('GENERATED', 'New demo network generated (' + devices.length + ' assets). Synthetic data only.');
    layout(); render();
  }

  function layout() {
    var W = canvas.width, H = canvas.height;
    if (groupMode === 'subnet') {
      var groups = {};
      devices.forEach(function (d) { (groups[d.subnet] = groups[d.subnet] || []).push(d); });
      Object.keys(groups).forEach(function (key, gi) {
        var cx = W * (0.18 + 0.64 * (gi % 2));
        var cy = H * (gi < 2 ? 0.28 : 0.74);
        groups[key].forEach(function (d, i) {
          var angle = (i / Math.max(1, groups[key].length)) * Math.PI * 2;
          var radius = 78 + (i % 3) * 22;
          d.x = Math.max(40, Math.min(W - 40, cx + Math.cos(angle) * radius));
          d.y = Math.max(40, Math.min(H - 40, cy + Math.sin(angle) * radius));
        });
      });
      var core = devices.find(function (d) { return d.role === 'Core'; });
      if (core) { core.x = W / 2; core.y = H / 2; }
    } else {
      var rgroups = {};
      devices.forEach(function (d) { (rgroups[d.role] = rgroups[d.role] || []).push(d); });
      Object.keys(rgroups).forEach(function (key, gi) {
        var cx = W * (0.14 + (gi % 4) * 0.24);
        var cy = H * (gi < 4 ? 0.30 : 0.72);
        rgroups[key].forEach(function (d, i) {
          // Refinement Pass 1: 4 columns per role cluster instead of 3.
          d.x = Math.max(35, Math.min(W - 35, cx + (i % 4 - 1.5) * 48));
          d.y = Math.max(35, Math.min(H - 35, cy + Math.floor(i / 4) * 44 - 20));
        });
      });
    }
  }

  function visibleDevices() {
    var role = document.getElementById('roleFilter').value;
    var risk = document.getElementById('riskFilter').value;
    var src = document.getElementById('sourceFilter').value;
    var q = document.getElementById('searchInput').value.trim().toLowerCase();
    return devices.filter(function (d) {
      return (role === 'All' || d.role === role) &&
        (risk === 'All' || d.risk === risk) &&
        (src === 'All' || d.source === src) &&
        (!subnetFocus || d.subnet === subnetFocus) &&
        (!q || d.hostname.toLowerCase().indexOf(q) !== -1 || d.ip.indexOf(q) !== -1);
    });
  }

  function linkColour(a, b) {
    if (a.risk === 'Critical' || b.risk === 'Critical') return '#ff3b4e';
    if (a.risk === 'High' || b.risk === 'High' || a.risk === 'Medium' || b.risk === 'Medium') return '#ffb020';
    return '#00e5ff';
  }
  function nodeColour(d) {
    if (d.risk === 'Critical') return '#ff3b4e';
    if (d.risk === 'High' || d.risk === 'Medium') return '#ffb020';
    if (d.risk === 'Low' || d.risk === 'Safe') return '#00e5ff';
    return '#8a9aa3';
  }

  function draw(now) {
    var t = now || Date.now();
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    // Pass 2 empty state: an empty network is a valid state, not a broken map.
    if (!devices.length) {
      ctx.fillStyle = '#a9ccd8'; ctx.textAlign = 'center'; ctx.font = 'bold 16px monospace';
      ctx.fillText('No assets on this map yet.', canvas.width / 2, canvas.height / 2 - 10);
      ctx.font = '13px monospace';
      ctx.fillText('Click Generate Network, or import an authorised inventory.', canvas.width / 2, canvas.height / 2 + 16);
      return;
    }
    ctx.strokeStyle = '#0e2a38'; ctx.lineWidth = 1;
    for (var x = 0; x <= canvas.width; x += 45) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke(); }
    for (var y = 0; y <= canvas.height; y += 45) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke(); }
    var vis = new Set(visibleDevices().map(function (d) { return d.id; }));
    links.forEach(function (l) {
      var a = devices.find(function (d) { return d.id === l.from; });
      var b = devices.find(function (d) { return d.id === l.to; });
      if (!a || !b) return;
      var dim = !vis.has(a.id) || !vis.has(b.id);
      ctx.strokeStyle = linkColour(a, b); ctx.globalAlpha = dim ? 0.12 : 0.75; ctx.lineWidth = dim ? 1 : 1.6;
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    });
    ctx.globalAlpha = 1;
    devices.forEach(function (d) {
      var dim = !vis.has(d.id);
      ctx.globalAlpha = dim ? 0.25 : 1;
      if (!dim && !reducedMotion && (d.risk === 'Critical' || d.risk === 'High')) {
        var pr = 16 + 4 * Math.sin(t / 280 + d.id);
        ctx.strokeStyle = nodeColour(d); ctx.globalAlpha = 0.55; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(d.x, d.y, pr, 0, Math.PI * 2); ctx.stroke(); ctx.globalAlpha = 1;
      }
      if (d.id === hoverId && !dim) { ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(d.x, d.y, 20, 0, Math.PI * 2); ctx.stroke(); }
      ctx.fillStyle = nodeColour(d);
      ctx.beginPath();
      if (d.role === 'Core') { ctx.rect(d.x - 11, d.y - 11, 22, 22); ctx.fill(); }
      else if (d.role === 'IoT' || d.role === 'Printer') { ctx.moveTo(d.x, d.y - 11); ctx.lineTo(d.x + 11, d.y + 9); ctx.lineTo(d.x - 11, d.y + 9); ctx.closePath(); ctx.fill(); }
      else { ctx.arc(d.x, d.y, 10, 0, Math.PI * 2); ctx.fill(); }
      if (d.id === selectedId) { ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 2.5; ctx.beginPath(); ctx.arc(d.x, d.y, 17, 0, Math.PI * 2); ctx.stroke(); }
      // Refinement Pass 1: dark halo behind labels for readability.
      ctx.textAlign = 'center';
      ctx.font = 'bold 11px monospace';
      var hostW = ctx.measureText(d.hostname).width;
      ctx.fillStyle = 'rgba(4,32,31,0.88)';
      ctx.fillRect(d.x - hostW / 2 - 4, d.y + 19, hostW + 8, 15);
      ctx.fillStyle = '#d7f6fb';
      ctx.fillText(d.hostname, d.x, d.y + 30);
      ctx.font = '10px monospace';
      var ipW = ctx.measureText(d.ip).width;
      ctx.fillStyle = 'rgba(4,32,31,0.88)';
      ctx.fillRect(d.x - ipW / 2 - 4, d.y + 31, ipW + 8, 14);
      ctx.fillStyle = '#7fa6b1'; ctx.fillText(d.ip, d.x, d.y + 42);
    });
    ctx.globalAlpha = 1;
  }

  function renderStats() {
    var vis = visibleDevices();
    var risky = devices.filter(function (d) { return d.risk === 'Critical' || d.risk === 'High'; }).length;
    var unknown = devices.filter(function (d) { return d.role === 'Unknown'; }).length;
    var stale = devices.filter(function (d) { return d.lastSeenDays > staleDays; }).length;
    document.getElementById('stats').innerHTML =
      '<div class="stat"><b>' + devices.length + '</b><span>Total assets</span></div>' +
      '<div class="stat"><b>' + vis.length + '</b><span>Visible</span></div>' +
      '<div class="stat bad"><b>' + risky + '</b><span>Critical / High</span></div>' +
      '<div class="stat warn"><b>' + unknown + '</b><span>Unknown</span></div>' +
      '<div class="stat warn"><b>' + stale + '</b><span>Stale &gt;' + staleDays + 'd</span></div>' +
      '<div class="stat"><b>' + new Set(devices.map(function (d) { return d.subnet; })).size + '</b><span>Subnets</span></div>';
    document.getElementById('visibleCount').textContent = vis.length + ' of ' + devices.length + ' assets visible';
    var summary = document.getElementById('filterSummary');
    if (summary) {
      summary.textContent = 'Active filters: Role=' + document.getElementById('roleFilter').value +
        ' · Risk=' + document.getElementById('riskFilter').value +
        ' · Source=' + document.getElementById('sourceFilter').value +
        ' · Search=' + (document.getElementById('searchInput').value.trim() || '—') +
        ' · ' + vis.length + ' visible';
    }
    var sel = document.getElementById('selectedLabel');
    if (sel) {
      var sd = devices.find(function (x) { return x.id === selectedId; });
      sel.textContent = sd ? 'Selected: ' + sd.hostname + ' — ' + sd.risk + ' (' + sd.riskScore + '/100). Use the detail panel to remove it or walk its connections.' : 'No node selected — click a node on the map or a row in the table.';
    }
  }

  function renderTable() {
    var vis = visibleDevices();
    document.getElementById('assetRows').innerHTML = vis.map(function (d) {
      return '<tr data-id="' + d.id + '" class="' + (d.id === selectedId ? 'selected' : '') + '">' +
        '<td>' + esc(d.hostname) + '</td><td>' + esc(d.ip) + '</td><td>' + esc(d.subnet) + '</td><td>' + esc(d.role) + '</td>' +
        '<td>' + esc(d.os) + '</td><td>' + esc(d.source) + '</td><td><span class="risk-pill ' + d.risk + '">' + d.risk + ' (' + d.riskScore + ')</span></td>' +
        '<td>' + (d.flags.length ? esc(d.flags.join(' · ')) : '—') + '</td><td>' + (d.lastSeenDays === 0 ? 'Today' : daysAgo(d.lastSeenDays)) + '</td></tr>';
    }).join('') || '<tr><td colspan="9">No assets match the current filters.</td></tr>';
    document.querySelectorAll('#assetRows tr[data-id]').forEach(function (row) {
      row.tabIndex = 0;
      var selectRow = function () { selectedId = Number(row.dataset.id); renderDetail(); draw(); renderTable(); };
      row.addEventListener('click', selectRow);
      row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectRow(); } });
    });
  }

  function renderDetail() {
    var d = devices.find(function (x) { return x.id === selectedId; });
    var title = document.getElementById('detailTitle');
    var body = document.getElementById('detailBody');
    var actions = document.getElementById('detailActions');
    if (!d) { title.textContent = 'SELECT A NODE'; body.innerHTML = '<p class="hint">Click a node on the map, or a row in the asset table below, to inspect it.</p>'; actions.innerHTML = ''; return; }
    var neighbours = links.filter(function (l) { return l.from === d.id || l.to === d.id; })
      .map(function (l) { return devices.find(function (x) { return x.id === (l.from === d.id ? l.to : l.from); }); }).filter(Boolean);
    title.textContent = d.hostname.toUpperCase();
    var breakdownText = (d.breakdown || []).map(function (b) { return b.label + ' (+' + b.points + ')'; }).join(' · ');
    body.innerHTML =
      '<div class="plain-card"><strong>IN PLAIN WORDS</strong><p>' + esc(plainSentence(d)) + '</p><p class="hint">Do this first: ' + esc(fixSuggestion(d)) + '</p></div>' +
      '<div class="dial ' + (d.risk === 'Critical' ? 'crit' : (d.risk === 'High' || d.risk === 'Medium' ? 'warn' : 'ok')) + '" aria-label="Risk dial"><span>' + d.riskScore + '</span><small>risk score</small></div>' +
      '<div class="risk ' + d.risk + '">' + d.risk + ' — ' + d.riskScore + '/100</div>' +
      '<div class="risk-bar" aria-label="Risk score"><span class="' + d.risk + '" style="width:' + d.riskScore + '%"></span></div>' +
      '<p class="hint">Why this score: ' + (breakdownText || 'Base score only') + '. Capped at 100. Change weights in the Risk Rule Editor and click Apply rules &amp; re-score to see this change.</p>' +
      '<dl><dt>IP</dt><dd>' + esc(d.ip) + '</dd>' +
      '<dt>MAC</dt><dd>' + esc(d.mac || '—') + '</dd>' +
      '<dt>Subnet / Role / OS / Source</dt><dd>' + esc(d.subnet) + ' · ' + esc(d.role) + ' · ' + esc(d.os) + ' · ' + esc(d.source) + '</dd>' +
      '<dt>Services (as data, not a scan)</dt><dd>' + esc(d.services.join(', ') || '—') + '</dd>' +
      '<dt>Patch level</dt><dd>' + esc(d.patchLevel) + ' · Last seen: ' + (d.lastSeenDays === 0 ? 'Today' : daysAgo(d.lastSeenDays)) + '</dd>' +
      '<dt>Flags</dt><dd>' + (d.flags.length ? d.flags.map(function (f) { return '<span class="flag ' + (d.risk === 'Critical' ? 'crit' : '') + '">' + esc(f) + '</span>'; }).join('') : 'No flags') + '</dd>' +
      '<dt>Connections (' + neighbours.length + ')</dt><dd>' +
      (neighbours.length ? neighbours.map(function (n) { return '<button class="conn-btn" data-id="' + n.id + '">' + esc(n.hostname) + ' — ' + esc(n.ip) + ' (' + n.risk + ')</button>'; }).join('') : 'Isolated in this view') +
      '</dd></dl>';
    actions.innerHTML = '<button id="removeAssetBtn" class="secondary" type="button">Remove this asset (logs change)</button>';
    document.getElementById('removeAssetBtn').addEventListener('click', function () { removeAsset(d.id); });
    body.querySelectorAll('.conn-btn').forEach(function (btn) {
      btn.addEventListener('click', function () { selectedId = Number(btn.dataset.id); renderDetail(); draw(); renderTable(); });
    });
  }

  function renderHistory() {
    document.getElementById('historyList').innerHTML = history.map(function (h) {
      return '<li><b>' + esc(h.action) + '</b> — ' + esc(h.detail) + ' <span class="muted">' + esc(h.at) + '</span></li>';
    }).join('') || '<li>No changes yet in this session.</li>';
  }

  function renderRules() {
    document.getElementById('ruleEditor').innerHTML = rules.map(function (r, i) {
      return '<label class="field">' + esc(r.label) +
        ' <input type="number" data-rule="' + i + '" value="' + r.weight + '" min="0" max="100"></label>';
    }).join('') +
    '<label class="field">Stale threshold (days) <input id="staleDaysInput" type="number" value="' + staleDays + '" min="1" max="365"></label>';
    document.querySelectorAll('#ruleEditor input[data-rule]').forEach(function (inp) {
      inp.addEventListener('input', function () { rules[Number(inp.dataset.rule)].weight = Number(inp.value) || 0; });
    });
    var sd = document.getElementById('staleDaysInput');
    if (sd) sd.addEventListener('input', function () { staleDays = Number(sd.value) || 30; });
  }

  function render() { draw(); renderStats(); renderTable(); renderDetail(); renderHistory(); renderFixQueue(); renderSubnet(); renderTimeline(); renderSimulator(); renderCompareOptions(); }

  // Pass 2: same IP + hostname = update (existing behaviour). Same IP with a
  // *different* hostname, or same hostname with a *different* IP, is a
  // conflict — it is reported, not silently merged or duplicated.
  function addOrUpdateAssets(list, sourceLabel) {
    var added = 0, updated = 0, conflicts = [];
    list.forEach(function (raw) {
      var norm = raw.hostname && raw.ip ? raw : (A.normalise ? A.normalise(raw, raw.source || sourceLabel) : raw);
      var existing = devices.find(function (d) { return d.ip === norm.ip && d.hostname === norm.hostname; });
      if (!existing) {
        var clash = devices.find(function (d) { return d.ip === norm.ip || d.hostname === norm.hostname; });
        if (clash) conflicts.push(norm.hostname + ' (' + norm.ip + ') conflicts with existing ' + clash.hostname + ' (' + clash.ip + ') — added as a separate row, check the source export.');
      }
      if (existing) {
        var before = existing.risk + ' (' + existing.riskScore + ')';
        Object.assign(existing, norm);
        existing.source = norm.source || sourceLabel;
        var r = computeRisk(existing); existing.riskScore = r.score; existing.risk = r.level; existing.flags = r.flags; existing.breakdown = r.breakdown;
        updated++;
        logHistory('UPDATED', existing.hostname + ' (' + existing.ip + ') re-imported; risk ' + before + ' → ' + existing.risk + ' (' + existing.riskScore + ').');
      } else {
        norm.id = nextId++;
        norm.source = norm.source || sourceLabel;
        norm.mac = norm.mac || '';
        norm.services = norm.services || [];
        var rr = computeRisk(norm); norm.riskScore = rr.score; norm.risk = rr.level; norm.flags = rr.flags; norm.breakdown = rr.breakdown;
        devices.push(norm);
        var core = devices.find(function (d) { return d.role === 'Core'; });
        if (core && norm.role !== 'Core') links.push({ from: core.id, to: norm.id });
        added++;
        logHistory('ADDED', norm.hostname + ' (' + norm.ip + ') added via ' + norm.source + '.');
      }
    });
    layout(); render();
    return { added: added, updated: updated, conflicts: conflicts };
  }

  function removeAsset(id) {
    var d = devices.find(function (x) { return x.id === id; });
    if (!d) return;
    devices = devices.filter(function (x) { return x.id !== id; });
    links = links.filter(function (l) { return l.from !== id && l.to !== id; });
    if (selectedId === id) selectedId = null;
    logHistory('REMOVED', d.hostname + ' (' + d.ip + ') removed from the topology.');
    layout(); render();
  }

  function importTextData(text, format) {
    var status = document.getElementById('importStatus');
    try {
      var trimmed = text.trim();
      if (!trimmed) { status.textContent = 'Nothing to import — paste JSON or CSV first.'; return; }
      var list;
      if (format === 'inventory-csv' || (format === 'auto' && !trimmed.startsWith('{') && !trimmed.startsWith('['))) {
        if (!A.parseInventoryCsv) throw new Error('CSV parser (adapters.js) did not load.');
        list = A.parseInventoryCsv(trimmed);
      } else if (format === 'cloud-json') {
        if (!A.parseCloudJson) throw new Error('Cloud parser (adapters.js) did not load.');
        list = A.parseCloudJson(trimmed);
      } else {
        if (!A.parseCmdbJson) throw new Error('CMDB parser (adapters.js) did not load.');
        list = A.parseCmdbJson(trimmed);
      }
      var res = addOrUpdateAssets(list, 'imported');
      status.textContent = 'Imported: ' + res.added + ' added, ' + res.updated + ' updated (deduplicated by IP + hostname).' +
        (res.conflicts.length ? ' Conflicts (same IP or hostname, different other field): ' + res.conflicts.join(' | ') : '');
    } catch (e) {
      status.textContent = 'Import failed: ' + e.message;
    }
  }

  function exportTopology() {
    var payload = {
      exportedAt: new Date().toISOString(),
      source: 'NETMAP FULL — demo/export. Default data is synthetic; imported rows are user-supplied.',
      safety: 'No real scan was performed by this app.',
      staleDays: staleDays,
      rules: rules,
      devices: devices,
      links: links,
      history: history.slice(0, 100)
    };
    var blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'netmap-topology-export.json';
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    logHistory('EXPORTED', 'Topology exported as JSON (' + devices.length + ' assets, ' + links.length + ' links).');
    render();
  }

  function injectEvent() {
    var d = pick(devices.filter(function (x) { return x.role !== 'Core'; }));
    if (!d) { document.getElementById('mapMeta').textContent = 'No assets to change — click Generate Network first. (Empty map, by design.)'; return; }
    d.lastSeenDays = 0;
    if (d.flags.indexOf('SIMULATED EVENT: NEW SERVICE APPEARED') === -1) d.flags.push('SIMULATED EVENT: NEW SERVICE APPEARED');
    if (d.services.indexOf('HTTP 8080 (simulated)') === -1) d.services.push('HTTP 8080 (simulated)');
    var r = computeRisk(d); d.riskScore = r.score; d.risk = r.level;
    selectedId = d.id;
    logHistory('CHANGED', d.hostname + ' — simulated event: new simulated service appeared.');
    render();
    document.getElementById('mapMeta').textContent = 'Simulated event injected on ' + d.hostname + ' — a new simulated service appeared. No real device changed.';
  }

  // ---- wiring ----
  // Pass 2 keyboard navigation: arrows move selection through the visible
  // nodes in table order, so the map is usable without a mouse.
  canvas.addEventListener('keydown', function (e) {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowDown' && e.key !== 'ArrowLeft' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    var vis = visibleDevices();
    if (!vis.length) return;
    var cur = -1;
    vis.forEach(function (d, i) { if (d.id === selectedId) cur = i; });
    var next = (e.key === 'ArrowRight' || e.key === 'ArrowDown') ? (cur + 1) % vis.length : (cur - 1 + vis.length) % vis.length;
    selectedId = vis[next].id; renderDetail(); draw(); renderTable();
  });
  document.getElementById('clearMapBtn').addEventListener('click', function () {
    devices = []; links = []; selectedId = null; subnetFocus = null; simSnapshot = null;
    logHistory('CLEARED', 'Map cleared to the empty state (demo). Generate or import to rebuild.');
    document.getElementById('mapMeta').textContent = 'Map cleared — empty state. Click Generate Network or import an authorised inventory. No real device was touched.';
    layout(); render();
  });
  canvas.addEventListener('click', function (e) {
    var rect = canvas.getBoundingClientRect();
    var x = (e.clientX - rect.left) * (canvas.width / rect.width);
    var y = (e.clientY - rect.top) * (canvas.height / rect.height);
    var best = null, bestDist = 26;
    devices.forEach(function (d) { var dist = Math.hypot(d.x - x, d.y - y); if (dist < bestDist) { best = d; bestDist = dist; } });
    if (best) { selectedId = best.id; renderDetail(); draw(); renderTable(); }
  });
  document.getElementById('generateBtn').addEventListener('click', generateNetwork);
  document.getElementById('randomEventBtn').addEventListener('click', injectEvent);
  var clearBtn = document.getElementById('clearFiltersBtn');
  if (clearBtn) clearBtn.addEventListener('click', function () {
    document.getElementById('roleFilter').value = 'All';
    document.getElementById('riskFilter').value = 'All';
    document.getElementById('sourceFilter').value = 'All';
    document.getElementById('searchInput').value = '';
    render();
  });
  document.getElementById('exportBtn').addEventListener('click', exportTopology);
  ['roleFilter', 'riskFilter', 'sourceFilter', 'searchInput'].forEach(function (id) {
    document.getElementById(id).addEventListener('input', render);
  });
  document.getElementById('groupSubnetBtn').addEventListener('click', function () {
    groupMode = 'subnet';
    document.getElementById('groupSubnetBtn').classList.add('active');
    document.getElementById('groupSubnetBtn').setAttribute('aria-pressed', 'true');
    document.getElementById('groupRoleBtn').classList.remove('active');
    document.getElementById('groupRoleBtn').setAttribute('aria-pressed', 'false');
    document.getElementById('layoutLabel').textContent = 'By subnet';
    layout(); render();
  });
  document.getElementById('groupRoleBtn').addEventListener('click', function () {
    groupMode = 'role';
    document.getElementById('groupRoleBtn').classList.add('active');
    document.getElementById('groupRoleBtn').setAttribute('aria-pressed', 'true');
    document.getElementById('groupSubnetBtn').classList.remove('active');
    document.getElementById('groupSubnetBtn').setAttribute('aria-pressed', 'false');
    document.getElementById('layoutLabel').textContent = 'By role';
    layout(); render();
  });
  document.getElementById('importTextBtn').addEventListener('click', function () {
    importTextData(document.getElementById('importText').value, document.getElementById('importFormat').value);
  });
  document.getElementById('loadSampleBtn').addEventListener('click', function () {
    document.getElementById('importText').value = JSON.stringify([
      { hostname: 'sample-srv-01', ip: '10.0.8.11', subnet: '10.0.8.0/24', role: 'Server', os: 'Ubuntu Server (sample)', services: ['HTTPS 443'], patchLevel: 'Current', lastSeenDays: 0, exposed: false },
      { hostname: 'sample-unknown-01', ip: '10.0.8.99', subnet: '10.0.8.0/24', role: 'Unknown', os: 'Unknown (sample)', services: ['Telnet 23'], patchLevel: 'Outdated', lastSeenDays: 60, exposed: false }
    ], null, 2);
    document.getElementById('importFormat').value = 'cmdb-json';
    importTextData(document.getElementById('importText').value, 'cmdb-json');
  });
  document.getElementById('importFileBtn').addEventListener('click', function () {
    var file = document.getElementById('importFile').files[0];
    var status = document.getElementById('importStatus');
    if (!file) { status.textContent = 'Choose a .json or .csv file first.'; return; }
    var reader = new FileReader();
    reader.onload = function () { importTextData(String(reader.result || ''), document.getElementById('importFormat').value); };
    reader.onerror = function () { status.textContent = 'Could not read that file in this browser.'; };
    reader.readAsText(file);
  });
  document.getElementById('addAssetBtn').addEventListener('click', function () {
    var hostname = document.getElementById('addHostname').value.trim();
    var ip = document.getElementById('addIp').value.trim();
    var status = document.getElementById('addStatus');
    if (!hostname || !ip) { status.textContent = 'Hostname and IP are required.'; return; }
    if (!IP_RE.test(ip)) { status.textContent = 'That IP does not look like an IPv4 address (e.g. 10.0.9.42) — asset not added.'; return; }
    var res = addOrUpdateAssets([{
      hostname: hostname, ip: ip, subnet: document.getElementById('addSubnet').value.trim() || '10.0.9.0/24',
      role: document.getElementById('addRole').value, os: 'Manual entry (demo)', services: [], patchLevel: 'Current', lastSeenDays: 0, exposed: false, source: 'manual'
    }], 'manual');
    status.textContent = (res.added ? 'Asset added.' : 'Asset updated (same IP + hostname already existed).') +
      (res.conflicts.length ? ' Conflict: ' + res.conflicts.join(' | ') : '');
  });
  document.getElementById('applyRulesBtn').addEventListener('click', function () {
    saveStored('netmap-full-rules', { rules: rules, staleDays: staleDays });
    rescoreAll();
    logHistory('RULES CHANGED', 'Risk weights / stale threshold updated; all assets re-scored.');
    document.getElementById('ruleStatus').textContent = 'Rules applied and all assets re-scored.';
    render();
  });
  document.getElementById('resetRulesBtn').addEventListener('click', function () {
    rules = JSON.parse(JSON.stringify(DEFAULT_RULES));
    staleDays = DEFAULT_STALE_DAYS;
    saveStored('netmap-full-rules', { rules: rules, staleDays: staleDays });
    renderRules();
    rescoreAll();
    logHistory('RULES RESET', 'Risk rules reset to defaults.');
    document.getElementById('ruleStatus').textContent = 'Rules reset to defaults.';
    render();
  });
  document.getElementById('addRuleBtn').addEventListener('click', function () {
    var svc = document.getElementById('customService').value.trim();
    var w = Number(document.getElementById('customWeight').value) || 0;
    if (!svc) { document.getElementById('ruleStatus').textContent = 'Enter a service name for the custom rule first.'; return; }
    rules.push({ id: 'custom-' + Date.now(), label: 'Custom: service contains ' + svc, weight: w, kind: 'custom-service', match: svc });
    renderRules();
    document.getElementById('ruleStatus').textContent = 'Custom rule added — click Apply rules & re-score to use it.';
  });
  document.getElementById('clearHistoryBtn').addEventListener('click', function () {
    history = [];
    saveStored('netmap-full-history', history);
    renderHistory();
  });
  document.getElementById('saveKeyBtn').addEventListener('click', function () {
    var key = document.getElementById('apiKeyInput').value.trim();
    if (!key) { document.getElementById('adapterStatus').textContent = 'No key entered — mock fallback will be used.'; return; }
    saveStored('netmap-full-api-key-present', true);
    document.getElementById('adapterStatus').textContent = 'Key saved in this browser only (flag only — the demo does not send it anywhere). Mock data will still be returned.';
  });
  document.getElementById('clearKeyBtn').addEventListener('click', function () {
    try { localStorage.removeItem('netmap-full-api-key-present'); } catch (e) {}
    document.getElementById('apiKeyInput').value = '';
    document.getElementById('adapterStatus').textContent = 'Local key flag cleared — mock fallback will be used.';
  });
  document.getElementById('runAdapterBtn').addEventListener('click', function () {
    var name = document.getElementById('adapterSelect').value;
    var key = document.getElementById('apiKeyInput').value.trim();
    var status = document.getElementById('adapterStatus');
    status.textContent = 'Running ' + name + ' adapter…';
    if (A.runAdapter) {
      A.runAdapter(name, key).then(function (res) {
        var out = addOrUpdateAssets(res.assets, 'adapter');
        status.textContent = 'Adapter "' + res.adapter + '": ' + res.mode + '. Added ' + out.added + ', updated ' + out.updated + '.';
      });
    } else {
      status.textContent = 'Adapters file did not load — check adapters.js is next to index.html.';
    }
  });

  // ---- Refinement Pass 3 wiring ----
  canvas.addEventListener('mousemove', function (e) {
    var rect = canvas.getBoundingClientRect();
    var x = (e.clientX - rect.left) * (canvas.width / rect.width);
    var y = (e.clientY - rect.top) * (canvas.height / rect.height);
    var hit = null;
    devices.forEach(function (d) { if (Math.hypot(d.x - x, d.y - y) < 22) hit = d; });
    var nextHover = hit ? hit.id : null;
    if (nextHover !== hoverId) { hoverId = nextHover; if (reducedMotion) draw(); }
    canvas.style.cursor = hit ? 'pointer' : 'default';
  });
  document.getElementById('simPatchBtn').addEventListener('click', doSimPatch);
  document.getElementById('simCloseBtn').addEventListener('click', doSimClose);
  document.getElementById('simUndoBtn').addEventListener('click', doSimUndo);
  document.getElementById('subnetBackBtn').addEventListener('click', function () { subnetFocus = null; render(); });
  document.getElementById('compareBtn').addEventListener('click', function () {
    var a = devices.find(function (d) { return String(d.id) === document.getElementById('compareA').value; });
    var b = devices.find(function (d) { return String(d.id) === document.getElementById('compareB').value; });
    var out = document.getElementById('compareOut');
    if (!a || !b) { out.innerHTML = '<p class="hint">Pick two devices first.</p>'; return; }
    var first = a.riskScore >= b.riskScore ? a : b; var second = first === a ? b : a;
    out.innerHTML = '<table class="compare-table"><tr><th></th><th>' + esc(a.hostname) + '</th><th>' + esc(b.hostname) + '</th></tr>' +
      '<tr><td>Risk</td><td>' + a.risk + ' (' + a.riskScore + ')</td><td>' + b.risk + ' (' + b.riskScore + ')</td></tr>' +
      '<tr><td>Role / subnet / source</td><td>' + esc(a.role) + ' · ' + esc(a.subnet) + ' · ' + esc(a.source) + '</td><td>' + esc(b.role) + ' · ' + esc(b.subnet) + ' · ' + esc(b.source) + '</td></tr>' +
      '<tr><td>Services</td><td>' + esc(a.services.join(', ') || '—') + '</td><td>' + esc(b.services.join(', ') || '—') + '</td></tr>' +
      '<tr><td>Patch</td><td>' + esc(a.patchLevel) + '</td><td>' + esc(b.patchLevel) + '</td></tr></table>' +
      '<p><b>Verdict:</b> ' + esc(first.hostname) + ' needs attention first (' + first.riskScore + ' vs ' + second.riskScore + ') — ' + esc(plainSentence(first)) + '</p>';
  });
  document.getElementById('tourStartBtn').addEventListener('click', function () { tourStep = 0; showTour(); var s = tourSteps[0]; if (s.action) s.action(); });
  document.getElementById('tourNextBtn').addEventListener('click', function () {
    tourStep++;
    if (tourStep >= tourSteps.length) { tourStep = -1; document.getElementById('tourText').textContent = 'Tour finished — press “Try this” to run it again.'; return; }
    showTour(); var s = tourSteps[tourStep]; if (s.action) s.action();
  });
  document.getElementById('tourEndBtn').addEventListener('click', function () { tourStep = -1; document.getElementById('tourText').textContent = 'Tour stopped. Press “Try this” to run it again.'; });

  // ---- init ----
  var storedRules = loadStored('netmap-full-rules', null);
  rules = storedRules && Array.isArray(storedRules.rules) ? storedRules.rules : JSON.parse(JSON.stringify(DEFAULT_RULES));
  staleDays = storedRules && storedRules.staleDays ? storedRules.staleDays : DEFAULT_STALE_DAYS;
  history = loadStored('netmap-full-history', []);
  renderRules();
  generateNetwork();
  if (!reducedMotion) { var animate = function (t) { draw(t); requestAnimationFrame(animate); }; requestAnimationFrame(animate); }
})();
