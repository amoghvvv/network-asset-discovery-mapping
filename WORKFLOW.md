# WORKFLOW — Network Asset Discovery and Mapping (Full-Feature Version)

## Simulation vs full — what changed

| Area | Simulation | Full (this repo) |
|---|---|---|
| Data source | Generated in-browser only | Generated **plus** JSON/CSV import, manual add, and adapter (mock) runs |
| Persistence | Session only | Change history + risk rules in `localStorage` on this device only; export to JSON file |
| Risk scoring | Fixed weights, 30-day stale threshold | Editable weights, editable stale threshold, custom service rules, re-score on demand |
| Change tracking | Inject-event only | Full history log: generated, added, updated, removed, imported, adapter, rules, exported |
| Source visibility | No source field | Source filter and source column: `generated`, `imported-json`, `imported-csv`, `adapter`, `manual` |
| Export | None | Topology + rules + history as downloadable JSON |
| API keys | None | Key slots in `.env.example` and a browser-local key flag; mock fallback; **no real key ever committed, no real API called by this demo** |
| Safety rule | No real scan | Unchanged — still no packets, no probing, no port scanning |

What did **not** change: the core topology layout (by subnet / by role), node shapes and colours, click-to-inspect workflow, and the transparent risk-flag display. Those carry over from the simulation unchanged in spirit, so a judge who saw the simulation can follow the full version immediately.

## Step-by-step workflow

### 1. Start with demo data
- On load, `generateNetwork()` in `app.js` builds the same kind of synthetic network as the simulation: 1 core router plus 5–8 devices in each of 4 subnets, with roles, simulated OS/services, patch level, last-seen age, and an `exposed` flag.
- `rescoreAll()` applies the current risk rules (defaults, or rules restored from `localStorage`) and `layout()` + `draw()` render the topology.

### 2. Import authorised inventory (optional, full only)
- User chooses a format (auto / CMDB JSON / inventory CSV / cloud JSON) and uploads a file or pastes text.
- `adapters.js` parses it into the canonical asset shape: `{hostname, ip, mac, subnet, role, os, services[], patchLevel, lastSeenDays, exposed, source}`.
- `addOrUpdateAssets()` in `app.js` deduplicates by **IP + hostname**: an existing asset is updated in place (and its risk change is logged); a new asset is added and linked to the core node.
- Sample files: `sample-assets.json` (CMDB JSON) and `sample-assets.csv` (inventory CSV). The **Load sample import** button pastes and imports the JSON sample in one click.

### 3. Run an authorised-source adapter (optional, full only)
- User picks `cmdb`, `inventory`, or `cloud`, optionally enters a key in the browser-local key slot, and clicks **Run adapter**.
- `runAdapter()` in `adapters.js` returns mock assets after a short delay. It makes **no network request** in this demo, so a key can never leak and no real system is touched; the status line says plainly whether mock fallback or a locally-configured key flag was used.
- Returned assets flow through the same `addOrUpdateAssets()` deduplication and history logging as an import.

### 4. Score risk transparently (editable in full)
- `computeRisk(device)` starts at 10 and adds weights from the current rule set:
  - Unknown role: +45 (default)
  - Stale (last seen over the threshold, default 30 days): +30
  - Service contains Telnet: +40
  - Exposed RDP: +30
  - SMB on a workstation: +15
  - Outdated patch level: +20
  - Any custom service rule: its configured weight
- Total is capped at 100. Level: ≥80 Critical, ≥60 High, ≥35 Medium, ≥20 Low, otherwise Safe. Every contributing rule becomes a visible flag on the asset.
- In the **Risk Rule Editor**, changing a weight or the stale threshold and clicking **Apply rules & re-score** re-runs `computeRisk()` for every asset, updates the map colours, table pills, and detail panel, and logs a `RULES CHANGED` history entry. **Reset defaults** restores the simulation weights.

### 5. Lay out, filter, and inspect
- `layout()` positions nodes by subnet (rings around subnet centres, core in the middle) or by role (role clusters).
- `visibleDevices()` applies role, risk, source, and search filters to both the map and the inventory table; filtered-out nodes are dimmed, not removed.
- Clicking a canvas node (within ~26 px) or a table row opens the detail panel: IP/MAC, subnet, role, OS, **source**, services, patch level, last-seen date, risk score, flags, and neighbour buttons to walk the topology node by node.
- From the detail panel, **Remove this asset** deletes it and its links and logs a `REMOVED` entry.

### 6. Add, change, and track history
- **Add asset** (manual form) creates or updates an asset with `source: manual` and logs it.
- **Inject simulated event** (carried over from the simulation) updates a non-core asset's last-seen age and adds a simulated service, re-scores it, and logs a `CHANGED` entry.
- **Change History** lists the newest entries first: generated, added, updated, removed, imported, adapter, rules, exported. It is capped at 200 entries and persisted in `localStorage` on this device only.

### 7. Export
- **Export topology (JSON)** downloads `netmap-topology-export.json` with `exportedAt`, devices, links, current rules, stale threshold, recent history, and a safety note. The `devices` array in that file can be re-imported as CMDB JSON.

## Data flow

```
Demo generation (app.js)
  OR authorised import (file / paste → adapters.js parsers)
  OR adapter run (adapters.js → mock assets, no network request)
  OR manual add (detail panel form)
        ↓  canonical asset shape, deduplicated by IP + hostname
  addOrUpdateAssets() → computeRisk() with editable rules → flags + score
        ↓
  layout() by subnet or role → draw() on canvas (grid, links, nodes)
        ↓
  visibleDevices() filters (role / risk / source / search)
        ↓
  renderStats() + renderTable() + renderDetail() + renderHistory()
        ↓
  User action (generate / import / adapter / rule change / add / remove / export)
        ↓  re-score / re-layout / re-render, history logged — no server round-trip
```

No network request is made by this prototype itself. There is no backend and no database in this repo; persistence is limited to the browser (`localStorage`) and the JSON export file. That is the honest boundary of the full version: it is "full" in workflow — import, history, rules, adapters, export — not in live scanning, which is deliberately excluded.

## Import formats (documented, copy-ready)

CMDB JSON:
```json
{"assets":[{"hostname":"srv-01","ip":"10.0.5.12","subnet":"10.0.5.0/24","role":"Server","os":"Ubuntu Server","services":["HTTPS 443"],"patchLevel":"Current","lastSeenDays":1,"exposed":false}]}
```

Inventory CSV:
```csv
hostname,ip,subnet,role,os,services,patchLevel,lastSeenDays,exposed
srv-02,10.0.9.12,10.0.9.0/24,Server,Debian,"HTTPS 443; SSH 22",Current,1,false
```

Cloud JSON:
```json
{"instances":[{"name":"web-01","private_ip":"10.0.6.8","vpc":"10.0.6.0/24","os":"Ubuntu Server","services":["HTTPS 443"]}]}
```

## Refinement Pass 1 — what changed

- Fixed the same subnet/IP bug as the simulation: generated hosts now derive their prefix from their own subnet, so 192.168.10.0/24 correctly yields 192.168.10.x addresses.
- Fixed the legend to match the drawing: ◆ Core, ● Server / Workstation / Network, ▲ IoT / Printer.
- Canvas readability: dark halo behind hostname/IP labels, bold hostnames, and 4-column (was 3) By-role clusters to reduce overlap.
- Filter clarity: added a Clear filters button (role, risk, source, search) and a live "Active filters" summary; a "Selected: …" line now sits under the map.
- Risk scoring made unmistakable: the detail panel now shows a risk bar plus a "Why this score" breakdown (base 10 + each rule weight, capped at 100), and the breakdown is preserved through imports, adapter runs, and re-scoring. The Risk Rule Editor's effect on that breakdown is now explained in the panel itself.
- Mobile stacking: narrow-screen canvas drops to 380px high, panels stack map-first, and focus outlines are visible for keyboard users.
- Safety/keys: verified `.env.example` contains placeholders only (example URLs, PASTE_YOUR_KEY_HERE), no real keys anywhere in the repo, adapters still return mock data with no network request, and a new `.gitignore` now excludes `.env`. Imports remain authorised exports only — no packets, no probing, no port scanning.
- Style unchanged: dark topology-console, deep-teal canvas, cyan/amber/red risk — no generic AI look introduced.

## Refinement Pass 2 — what changed

- **Accessibility:** a skip link ("Skip to topology map"), `role="img"` + `aria-describedby` on the canvas, a visible keyboard hint, and `aria-pressed` on the group-layout buttons. The map is now keyboard-navigable (arrow keys move through visible nodes in table order) and inventory rows are focusable and select with Enter or Space. Muted text was brightened (`#7fa6b1` → `#a9ccd8`) for contrast, and table rows get a visible focus outline.
- **Empty network (new edge case):** a **Clear map (empty-state demo)** button empties the map and logs a `CLEARED` history entry — the canvas draws a plain "No assets yet" message, stats read 0, and Inject on an empty map explains itself. Generate or import rebuilds it.
- **Invalid imports (fixed, was silent):** parsers in `adapters.js` previously defaulted a row with no hostname to `unknown-host` and no IP to `0.0.0.0`, so bad exports looked like real assets. They now throw an aggregated error naming every bad row (hostname or valid IPv4 missing, first five listed), the UI shows it verbatim, and nothing is added. Unknown roles are normalised to Unknown instead of passing arbitrary role strings through to filters and the legend.
- **Duplicate / conflict handling (clarified):** same IP + hostname still updates in place (existing behaviour). Same IP with a different hostname, or same hostname with a different IP, is now reported as a conflict in the import/manual-add status and added as a separate row to check against the source export — never silently merged, never silently duplicated by the dedupe rule.
- **Manual-add validation:** the Add asset form now rejects IPs that do not match an IPv4 pattern, with a plain-language message, instead of accepting garbage into the topology.
- **Simulation vs full consistency (checked):** same default risk weights and bands, same node shapes/colours, same group layouts, same subnet/IP generation rule (Pass 1 fix). The full version differs only where it is supposed to: import, adapters, editable rules, history, export, and source tracking.
- **Demo script:** the README now carries a timed 2-minute judge script (with a keyboard-only variant) in addition to the 30-second guide; it deliberately demos the invalid-import rejection and the empty state, not just the happy path.
- Safety unchanged: synthetic data by default, authorised imports only, no packets sent, no real network probed, no port scanning, `.env.example` placeholders only, adapters mock-only in this browser demo.

## Demo script (about 3 minutes)

1. "Default data is synthetic — no real scan." Point to the badges and the FULL badge.
2. Click **Generate Network** — note the core, subnet clusters, and red/amber nodes.
3. Click **Load sample import** — show two new assets appearing, one critical unknown, and a history entry.
4. Open the **Risk Rule Editor**, raise a weight, click **Apply rules & re-score** — watch scores and colours change, and the history entry appear.
5. Click a critical node, then **Remove this asset** — show the history entry and the map updating (or undo by regenerating).
6. Click **Export topology (JSON)** — show that the whole topology, rules, and history leave as one file.
7. Close with: "In a server version, the adapter names stay the same and keys come from `.env` — here, mock fallback proves the workflow without touching a real system."

## Refinement Pass 3 — what changed

- **Plain language:** same `plainSentence()` / `fixSuggestion()` approach as the simulation, adapted to the full version's editable stale threshold (`staleDays` instead of a fixed 30 days). Rendered in the detail panel's “IN PLAIN WORDS” card and in every fix-first card. Hero in one everyday sentence, inline SVG blueprint, no binary images, no CDN.
- **Fix-first queue:** `renderFixQueue()` — top 5 Critical/High by score, focusable cards, same selection path as node clicks. Works across generated, imported, adapter, and manual assets.
- **Risk simulator:** `doSimPatch()` / `doSimClose()` / `doSimUndo()` snapshot only affected fields, mutate the demo/imported device, re-score with the editable-rule `computeRisk()`, and log via the existing `logHistory()` (`SIMULATED FIX` / `SIMULATED FIX UNDONE`) — so the simulator is visible in both Change History and the new timeline panel. It does not call an adapter, does not send a packet, and does not change any real device.
- **Subnet drill-down:** `subnetFocus` added to `visibleDevices()` alongside role, risk, source, and search filters. `renderSubnet()` renders chips, count, average risk, riskiest device in plain words, and device list; drill-down is cleared on generate/clear and by the back button.
- **Comparison:** `renderCompareOptions()` (rebuild only on device/score-key change, preserving choices) plus a compare table that includes the source column, and a plain verdict.
- **Timeline:** `renderTimeline()` renders the existing `history` array (capped at 200, localStorage-persisted) as a plain timeline, in addition to the existing Change History list. No second history store was introduced — one source of truth, two views.
- **Tour:** `tourSteps` (6 steps) with text + optional action, Next/End, `aria-live` text. Tour actions reuse existing functions (`generateNetwork()`, selection + `render()`, subnet focus) rather than duplicating logic.
- **Motion:** `draw(now)` with pulsing Critical/High rings and a hover ring (`hoverId` from a new canvas mousemove listener); `requestAnimationFrame` loop only when `prefers-reduced-motion` is off. Risk dials in detail and simulator; hover lift on buttons/cards.
- **Data flow (Pass 3 additions):** simulator/tour/drill-down actions → existing `computeRisk()` / `visibleDevices()` / `logHistory()` → `render()` → `renderFixQueue()` / `renderSubnet()` / `renderTimeline()` / `renderSimulator()` / `renderCompareOptions()`. Import, adapters, rules, history, and export flows are untouched.
- **Safety unchanged:** synthetic by default, authorised imports only, adapters are documented import formats with mock fallback, no packets, no probing, no port scanning, `esc()` on rendered text.
