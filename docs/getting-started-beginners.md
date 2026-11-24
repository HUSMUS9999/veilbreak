# Beginner's Guide to CloakGate

[← Back to README](../README.md) · [Hardware Invariants & Threat Model](./invariants-and-threat-model.md)

CloakGate makes blocking **CloakBrowser** and fingerprint-spoofing anti-detect browsers simple — even if you have never written bot-defense code before.

---

## Step 1: See All 6 Checks Live in Your Own Browser

```bash
node bin/cloakgate.js demo --port 8089
```

Open `http://127.0.0.1:8089/__cloakgate/playground`:
- In **regular Chrome, Firefox, Edge, or Safari**, all 6 rows show **`CLEAN`** (`Score: 0 / 11`) and the `<cloak-gate>` Web Component renders normally.
- In **CloakBrowser**, the hardware invariants light up red (`Score: 11 / 11`), `<cloak-gate>` wipes its protected content, and the protected page shows **`CLOAK_BROWSER_DENIED`**.

---

## Step 2: Use Plain English (`explain` & `ask`)

```bash
# Preview the exact command first without starting anything
node bin/cloakgate.js explain "block cloakbrowser on http://localhost:3000 on port 8080"

# Protect a website right now in strict mode
node bin/cloakgate.js ask "block cloakbrowser on http://localhost:3000 on port 8080"

# Keep Brave Shields Aggressive working while still blocking CloakBrowser
node bin/cloakgate.js ask "block cloakbrowser on http://localhost:3000 while keeping brave working"

# Roll out safely in monitor-only mode first
node bin/cloakgate.js ask "watch for cloakbrowser without blocking on http://localhost:3000"

# Print copy-paste HTML / <cloak-gate> / Express snippets
node bin/cloakgate.js ask "give me html and web component snippets"
```

---

## Step 3: Which Mode Should I Choose?

- Pick **`strict`** if you protect paid content, Web Components, login/signup flows, or anti-scraping APIs and want maximum CloakBrowser + headless browser blocking.
- Pick **`balanced`** if your site has users on privacy browsers that inject Canvas-only farbling (such as Brave Shields set to Aggressive) — CloakBrowser still triggers `8/11` to `11/11` and gets blocked (`>= 4`), while Canvas-only farbling (`2/11`) passes cleanly.
- Pick **`monitor`** for your first 24 hours in production to observe `X-CloakGate-Score` telemetry before enabling blocking.
