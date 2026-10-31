// NETMAP FULL — authorised-source adapters.
// These are DOCUMENTED IMPORT FORMATS, not scanners. They never send packets,
// never probe a host, and never contact a real API in this browser demo.
// With no key configured, every adapter returns clearly-labelled mock data.
// In a future server version, the same adapter names would read keys from
// environment variables (see .env.example) and call only APIs the owner
// is authorised to use. Never commit a real key.
(function () {
  'use strict';

  // Canonical asset shape produced by every adapter / importer:
  // { hostname, ip, mac?, subnet, role, os, services[], patchLevel,
  //   lastSeenDays, exposed, source }
  // Roles: Core, Server, Workstation, Network, IoT, Printer, Unknown.
  // patchLevel: "Current" or "Outdated". lastSeenDays: number, 0 = today.

  function cleanStr(v, fallback) {
    const s = String(v == null ? '' : v).trim();
    return s || fallback;
  }
  function toInt(v, fallback) {
    const n = parseInt(v, 10);
    return Number.isFinite(n) && n >= 0 ? n : fallback;
  }
  function toServices(v) {
    if (Array.isArray(v)) return v.map(function (s) { return String(s); });
    if (typeof v === 'string') return v.split(/[;|,]/).map(function (s) { return s.trim(); }).filter(Boolean);
    return [];
  }
  var ROLES = ['Core', 'Server', 'Workstation', 'Network', 'IoT', 'Printer', 'Unknown'];
  var IP_RE = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  // Pass 2: rows missing a hostname or a valid IPv4 address are INVALID,
  // not silently defaulted to 'unknown-host' / '0.0.0.0'. Parsers throw an
  // aggregated error naming the bad rows, so the UI can show it verbatim.
  function validateRows(list, format) {
    var bad = [];
    list.forEach(function (r, i) {
      var h = String(r.hostname || r.name || r.host || r.instance_name || '').trim();
      var ip = String(r.ip || r.address || r.ip_address || r.private_ip || '').trim();
      if (!h || !IP_RE.test(ip)) bad.push('row ' + (i + 1) + ' (hostname=' + (h || 'missing') + ', ip=' + (ip || 'missing') + ')');
    });
    if (bad.length) throw new Error(format + ' rejected: ' + bad.length + ' invalid row(s) missing a hostname or a valid IPv4 address — ' + bad.slice(0, 5).join('; ') + (bad.length > 5 ? ' (and ' + (bad.length - 5) + ' more)' : '') + '. Fix the source export and re-import; nothing was added.');
  }
  function normalise(raw, source) {
    var role = cleanStr(raw.role || raw.type || raw.device_type, 'Unknown');
    return {
      hostname: cleanStr(raw.hostname || raw.name || raw.host, 'unknown-host'),
      ip: cleanStr(raw.ip || raw.address || raw.ip_address, '0.0.0.0'),
      mac: cleanStr(raw.mac || raw.mac_address, ''),
      subnet: cleanStr(raw.subnet || raw.network || raw.cidr, '10.0.1.0/24'),
      role: ROLES.indexOf(role) !== -1 ? role : 'Unknown',
      os: cleanStr(raw.os || raw.operating_system || raw.platform, 'Unknown (demo)'),
      services: toServices(raw.services || raw.open_services || raw.ports),
      patchLevel: cleanStr(raw.patchLevel || raw.patch_level, 'Current') === 'Outdated' ? 'Outdated' : 'Current',
      lastSeenDays: toInt(raw.lastSeenDays != null ? raw.lastSeenDays : raw.last_seen_days, 0),
      exposed: raw.exposed === true || String(raw.exposed || '').toLowerCase() === 'true',
      source: source
    };
  }

  // CMDB export — JSON: { "assets": [ {hostname, ip, subnet, role, os,
  // services[], patchLevel, lastSeenDays, exposed}, ... ] }
  // Also accepts a bare array of asset objects.
  function parseCmdbJson(text) {
    const data = JSON.parse(text);
    const list = Array.isArray(data) ? data : (Array.isArray(data.assets) ? data.assets : []);
    if (!list.length) throw new Error('CMDB JSON contained no assets. Expected {"assets":[...]} or a bare array.');
    validateRows(list, 'CMDB JSON');
    return list.map(function (r) { return normalise(r, 'imported-json'); });
  }

  // Cloud inventory — JSON: { "instances": [ {name, private_ip, vpc, ...} ] }
  // Also accepts { "resources": [...] } and bare arrays.
  function parseCloudJson(text) {
    const data = JSON.parse(text);
    const list = Array.isArray(data) ? data
      : (Array.isArray(data.instances) ? data.instances
      : (Array.isArray(data.resources) ? data.resources : []));
    if (!list.length) throw new Error('Cloud JSON contained no instances/resources.');
    validateRows(list, 'Cloud JSON');
    return list.map(function (r) {
      return normalise({
        hostname: r.hostname || r.name || r.instance_name,
        ip: r.ip || r.private_ip || r.address,
        subnet: r.subnet || r.vpc || r.network,
        role: r.role || 'Server',
        os: r.os || r.image || r.platform,
        services: r.services,
        patchLevel: r.patchLevel || r.patch_level,
        lastSeenDays: r.lastSeenDays != null ? r.lastSeenDays : r.last_seen_days,
        exposed: r.exposed || r.public_ip != null
      }, 'imported-json');
    });
  }

  // Inventory CSV — header row required, e.g.:
  // hostname,ip,subnet,role,os,services,patchLevel,lastSeenDays,exposed
  // services may be separated by ";" inside a quoted field.
  function parseInventoryCsv(text) {
    const lines = String(text).split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean);
    if (lines.length < 2) throw new Error('CSV needs a header row plus at least one asset row.');
    function splitRow(row) {
      const out = [];
      let cur = '', inQ = false;
      for (let i = 0; i < row.length; i++) {
        const ch = row[i];
        if (ch === '"') { inQ = !inQ; }
        else if (ch === ',' && !inQ) { out.push(cur.trim()); cur = ''; }
        else { cur += ch; }
      }
      out.push(cur.trim());
      return out;
    }
    const header = splitRow(lines[0]).map(function (h) { return h.replace(/^"|"$/g, '').trim(); });
    const objs = lines.slice(1).map(function (row) {
      const cells = splitRow(row);
      const obj = {};
      header.forEach(function (h, i) { obj[h] = (cells[i] || '').replace(/^"|"$/g, ''); });
      return obj;
    });
    validateRows(objs, 'Inventory CSV');
    return objs.map(function (obj) { return normalise(obj, 'imported-csv'); });
  }

  function mockAssets(adapterName) {
    const base = [
      { hostname: 'cmdb-srv-01', ip: '10.0.7.11', subnet: '10.0.7.0/24', role: 'Server', os: 'Ubuntu Server (mock)', services: ['HTTPS 443'], patchLevel: 'Current', lastSeenDays: 0, exposed: false },
      { hostname: 'cmdb-ws-04', ip: '10.0.7.24', subnet: '10.0.7.0/24', role: 'Workstation', os: 'Windows 11 (mock)', services: ['SMB 445'], patchLevel: 'Outdated', lastSeenDays: 2, exposed: false },
      { hostname: 'cmdb-iot-02', ip: '10.0.7.31', subnet: '10.0.7.0/24', role: 'IoT', os: 'Embedded Linux (mock)', services: ['HTTP 80'], patchLevel: 'Outdated', lastSeenDays: 45, exposed: false }
    ];
    return base.map(function (r) {
      const n = normalise(r, 'adapter');
      n.hostname = adapterName + '-' + n.hostname;
      return n;
    });
  }

  // Mock-fetch an adapter. In the browser demo this NEVER makes a network
  // request: if a key is present it is only recorded as "configured" locally,
  // and mock data is still returned, so the demo cannot leak a key or
  // touch a real system. A server version would replace this body with a
  // real, authorised API call using process.env.<KEY> from .env.example.
  function runAdapter(adapterName, apiKey) {
    return new Promise(function (resolve) {
      setTimeout(function () {
        resolve({
          adapter: adapterName,
          mode: apiKey ? 'key-configured-locally — mock data returned (demo cannot call a real API)' : 'mock fallback — no key configured',
          assets: mockAssets(adapterName)
        });
      }, 350);
    });
  }

  window.NetmapAdapters = {
    normalise: normalise,
    parseCmdbJson: parseCmdbJson,
    parseCloudJson: parseCloudJson,
    parseInventoryCsv: parseInventoryCsv,
    runAdapter: runAdapter,
    ADAPTER_DOCS: {
      cmdb: 'CMDB export JSON — {"assets":[{hostname, ip, subnet, role, os, services[], patchLevel, lastSeenDays, exposed}]}',
      inventory: 'Inventory CSV — hostname,ip,subnet,role,os,services,patchLevel,lastSeenDays,exposed',
      cloud: 'Cloud inventory JSON — {"instances":[{name, private_ip, vpc, os, services[]}]}'
    }
  };
})();
