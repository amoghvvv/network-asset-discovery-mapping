# NETMAP FULL — Network Asset Discovery and Mapping (Full-Feature Version)

A working, standalone full-feature prototype for the CyberForge Hackathon 2026 theme **AI in Cybersecurity**. It extends the simulation version (`network-asset-discovery-mapping-simulation`) with import, change history, authorised-source adapters, a risk-rule editor, and topology export — while keeping the same safety rule: **no real network is probed, no packets are sent, no port scanning is performed.**

**SYNTHETIC / DEMO DATA BY DEFAULT. Imported rows are exactly what you import — only import data you are authorised to use.**

## 30-second demo guide

1. Say: "Default data is synthetic — no real scan. Imports are authorised exports, not live scans."
2. Click **Generate Network** — note the core, subnet clusters, and red/amber nodes.
3. Click a red node — read its risk bar and "Why this score" breakdown, then follow a neighbour connection.
4. Click **Load sample import** — two new assets appear, one critical unknown, and a history entry is logged.
5. Open the **Risk Rule Editor**, raise a weight, click **Apply rules & re-score** — scores and colours change live.


## 2-minute judge demo script

Say the safety line first, then run it in this order — no setup, no keys:

1. **(0:00) Safety line (10s):** "Default data is synthetic — no real scan. Imports are authorised exports, not live scans." Point to the badges.
2. **(0:10) Generate + inspect (30s):** Click **Generate Network**, click a red node, read its risk bar and "Why this score" breakdown, then follow a neighbour connection.
3. **(0:40) Import (30s):** Click **Load sample import** — two new assets appear, one critical unknown, and a history entry is logged. Re-import the same sample to show deduplication: it updates, it does not duplicate.
4. **(1:10) Rules (25s):** In the **Risk Rule Editor**, raise a weight, click **Apply rules & re-score** — scores and colours change live, and a history entry appears.
5. **(1:35) Edge cases (25s):** Paste a CSV row with a missing IP and import it — the import is rejected with the bad row named, nothing is added. Then click **Clear map (empty-state demo)** to show the empty map, and **Generate Network** to rebuild it.
6. **(2:00) Close:** Click **Export topology (JSON)** — "the whole topology, rules, and history leave as one file. In a server version the adapter names stay the same and keys come from `.env` — here, mock fallback proves the workflow without touching a real system."

Keyboard-only version: Tab to the map, use arrow keys to move between nodes, Tab to the table, Enter to select a row.

## Run it in under 2 minutes

No build step, no install, no API key required:

```bash
# Option 1 — open directly
open index.html

# Option 2 — serve locally (recommended)
python3 -m http.server 8000
# then open http://localhost:8000
```

Then:

1. Click **Generate Network** for a fresh synthetic topology, or use the sample imports.
2. Click any node on the dark topology canvas to inspect it.
3. Use **Filter by role / risk / source**, **Search**, and **Group: By subnet / By role**.
4. Try the full features below — import, adapters, rules, history, export.

## Full features (beyond the simulation)

### 1. Import assets / connections as JSON or CSV
- **CMDB export — JSON:** `{"assets":[{hostname, ip, subnet, role, os, services[], patchLevel, lastSeenDays, exposed}]}` or a bare array. See `sample-assets.json`.
- **Inventory — CSV:** header row `hostname,ip,subnet,role,os,services,patchLevel,lastSeenDays,exposed`. Services may be `;`-separated inside a quoted field. See `sample-assets.csv`.
- **Cloud inventory — JSON:** `{"instances":[{name, private_ip, vpc, os, services[]}]}` (also accepts `resources` or a bare array).
- Import by file upload **or** by pasting into the textarea. Files are read only in your browser; nothing is sent to a server.
- **Deduplication:** same IP + hostname = one asset. Re-importing updates that asset and logs a change instead of creating a duplicate. New assets are linked to the core node for the map.
- **Invalid rows (Pass 2):** a row missing a hostname or a valid IPv4 address is rejected, not silently defaulted — the import status names the bad rows and nothing is added. An unknown role is normalised to Unknown.
- **Conflicts (Pass 2):** same IP with a different hostname, or same hostname with a different IP, is reported in the import status and added as a separate row for the user to check against the source export — it is never silently merged.

### 2. Asset change history
- Every generate, add, update, remove, import, adapter run, rule change, and export is logged with a timestamp in the **Change History** panel.
- History is kept in this browser session and in `localStorage` on this device only (it does not leave the device). **Clear history** empties it.
- Removing an asset from its detail panel also logs a change and removes its links.

### 3. Authorised-source adapters (`adapters.js`)
Adapters are **documented import formats, not scanners**. The three adapters are:

| Adapter | Format it documents |
|---|---|
| `cmdb` | CMDB export JSON (see above) |
| `inventory` | Inventory / agent export CSV |
| `cloud` | Cloud inventory JSON |

- With no key configured, an adapter returns **mock data, clearly labelled** (`source: adapter`, hostnames prefixed with the adapter name).
- The **API key slot** in the UI stores only a *flag* in this browser's `localStorage` — the demo never sends a key anywhere and still returns mock data. That is deliberate: this browser demo cannot call a real API safely.
- A future server version would use the same adapter names and read keys from environment variables (see `.env.example`), calling only APIs the owner is authorised to use.

### 4. Risk rule editor
- Edit any built-in weight (Unknown, Stale, Telnet, Exposed RDP, SMB on workstation, Outdated patch) and the stale threshold in days, then click **Apply rules & re-score** — every asset is re-scored immediately.
- **Add a custom rule:** enter a service substring (e.g. `FTP`) and a weight; it applies to any asset whose service name contains it.
- **Reset defaults** restores the simulation's original weights and a 30-day stale threshold. Rules are also kept in `localStorage` on this device only.

### 5. Export topology as JSON
- **Export topology (JSON)** downloads `netmap-topology-export.json` containing devices, links, current rules, stale threshold, and recent history, with a safety note. You can re-import the `devices` portion via the CMDB JSON format.

### 6. Manual assets
- The **Add asset** form in the detail panel adds (or updates, on IP + hostname match) a manual asset, linked to the core, and logs the change. It rejects IPs that do not look like IPv4 addresses, with a plain-language message.

## How to add keys later

1. Copy `.env.example` to `.env` in a future server version of this project — **never commit `.env`**, and never paste a real key into this repo, into chat, or into the browser demo expecting it to reach a real API (it will not).
2. Fill in `CMDB_API_KEY`, `CLOUD_API_KEY`, and/or `INVENTORY_API_KEY` with keys for APIs you are authorised to use.
3. In that server version, replace the mock body of `runAdapter()` in `adapters.js` with a real, authorised API call using those variables. Adapter names, the canonical asset shape, deduplication, and risk scoring stay the same.
4. Until that server version exists, leave the key slot blank and use mock fallback — the demo is fully usable without any key.

## Safety notes (hackathon margins)

- Original work, built for this hackathon, extending the simulation prototype.
- No unauthorised testing, no real-world scanning, no malicious code, no packets sent by this app.
- No real personal data by default; imported data is user-supplied and must be authorised.
- Third-party dependencies: none. HTML, CSS, and vanilla JavaScript only, so it runs offline.
- If you present this, say clearly on stage: “Default data is synthetic. Imports are authorised inventory exports, not live scans.”

## Design

Dark topology-console style, continued from the simulation but deepened: deep-teal canvas with a faint grid, cyan links, amber/red risk colours, monospace data labels, and a new FULL badge. Deliberately distinct from a generic AI template — no purple gradient hero, no generic hero/CTA layout. The map itself is the hero.

## Workflow summary

See [WORKFLOW.md](WORKFLOW.md) for the step-by-step workflow, simulation vs full differences, data flow, and risk rules.

## Refinement Pass 3 — what changed

- **Plain-language layer (new):** the same hero as the simulation — “A live map of every device on the network, and which ones need attention” — with an inline SVG blueprint illustration (no images, no external fonts, works offline). Every selected device now opens with an “IN PLAIN WORDS” card and a “Do this first” line, so a non-technical person can follow the demo.
- **Fix the riskiest thing first (new):** top 5 Critical/High devices as plain-language cards with a fix-first suggestion; clicking opens the device (including imported and adapter assets, with their source shown in comparison).
- **Risk simulator (new):** patch or close a risky service on the selected device and watch its score drop live, with Undo. Simulator actions are logged in Change History as `SIMULATED FIX` / `SIMULATED FIX UNDONE`, so the timeline and the history stay consistent. Nothing real changes.
- **Subnet drill-down (new):** subnet chips zoom map, table, stats, and fix queue into one subnet (added as a predicate in `visibleDevices()`, alongside role/risk/source/search), with count, average risk, riskiest device in plain words, and a back button.
- **Device comparison (new):** side-by-side table including source (generated / imported / adapter / manual) plus a plain verdict on which device needs attention first.
- **Change timeline (new):** a plain “what changed, and when” panel that renders the existing Change History in timeline form — so imports, adapter runs, rule changes, removes, and simulator fixes all appear in one readable list, in addition to the existing history panel.
- **Guided “Try this” tour (new):** 6 steps (hero → generate → fix-first queue → simulator → subnet drill-down → table), with Next/End and `aria-live` text.
- **Motion/design (new):** pulsing Critical/High nodes, animated risk dials, hover rings on the map, hover lift on buttons/cards. `prefers-reduced-motion` disables animation; keyboard navigation, aria labels, and contrast are preserved.
- **Design language:** dark blueprint console, deep-teal canvas with blueprint grid, cyan wireframe, amber/red risk, Mobbin-style device cards, GetLayers-style layered hero background. No generic AI template.
- **Preserved, unchanged:** JSON/CSV import with dedupe (IP + hostname) and conflict reporting, change history (localStorage), risk-rule editor, topology export, manual add/remove, adapters as documented import formats with mock fallback, source filter.
- **Safety unchanged:** synthetic demo data by default; authorised imports only; adapters never scan, probe, or send packets; badges “SYNTHETIC / DEMO DATA BY DEFAULT” and “NO REAL SCAN — NO PACKETS SENT” remain; all rendered user input is escaped.
- **Pass 3 demo add-on (30 seconds, after the 2-minute script):** run “Try this”, patch the riskiest device in the simulator, read the score drop and its new history entry aloud, then drill into its subnet and back out.
