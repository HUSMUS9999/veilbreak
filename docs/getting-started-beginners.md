# VeilBreak — Natural-Language Beginner's Guide

[← Back to README](../README.md) · [14 Invariants & Threat Model](./invariants-and-threat-model.md)

You do not need to memorize flags to protect an app with VeilBreak. Describe what you want in plain English using `explain` (safe preview, zero side effects) or `ask` (run immediately).

---

## Everyday Natural-Language Recipes

From a cloned `veilbreak` directory (zero npm dependencies, Node.js >= 20):

```bash
# 1. Preview safely first (dry-run — prints the exact command and why)
node bin/veilbreak.js explain "block stealth browsers on http://localhost:3000 on port 8080"

# 2. Protect your app in strict mode (maximum protection across Chromium & Gecko)
node bin/veilbreak.js ask "block stealth browsers on http://localhost:3000 on port 8080"

# 3. Protect behind Nginx / Caddy / ALB (enables IPv4/IPv6 CIDR --trust-proxy)
node bin/veilbreak.js ask "block stealth browsers on http://localhost:3000 on port 8080 behind nginx"

# 4. Balanced mode (allows single-signal Canvas farbling while still enforcing IP/UA/PoW tickets)
node bin/veilbreak.js ask "protect http://localhost:3000 on port 8080 in balanced mode"

# 5. Monitor & score traffic without blocking anyone (recommended initial rollout)
node bin/veilbreak.js ask "watch for anti-detect browsers without blocking on http://localhost:3000"

# 6. Print ready-to-paste HTML, <veil-break> Web Component, and Express snippets
node bin/veilbreak.js ask "give me html and web component snippet"

# 7. Launch the interactive 14-invariant diagnostic playground
node bin/veilbreak.js ask "show me a demo"
```

The reverse-proxy shield automatically injects `/__veilbreak/gate.js` into HTML responses (including gzip/deflate/brotli upstream HTML) and transparently instruments both `window.fetch()` and async `XMLHttpRequest` (Axios, jQuery, HTMX, Angular HttpClient).

---

## Testing Live in Your Own Browsers

1. Start the interactive diagnostic playground:
   ```bash
   node bin/veilbreak.js demo --port 8089 --mode strict
   ```
   *(If you want to keep browser DevTools open while testing, pass `--no-anti-cdp`.)*
2. Open `http://127.0.0.1:8089/__veilbreak/playground` in **unmodified Google Chrome** or **Mozilla Firefox** (with DevTools closed) — all 14 invariants report `CLEAN` (`score = 0`), `<veil-break>` mounts cleanly, and clicking **Verify Protected Action** returns `HTTP 200`.
3. Try `curl http://127.0.0.1:8089/api/protected` or open the playground from any automated/stealth browser (Playwright, Puppeteer-Stealth, Patchright, Rebrowser, CloakBrowser, Camoufox, SeleniumBase UC, or Nodriver) to see the specific invariants and `403` enforcement trigger in real time.

---

## Reproducing the Multi-Browser Live Benchmark

```bash
python3 benchmarks/run_live_benchmark.py
```

The runner starts `benchmarks/bench_server.js`, discovers `google-chrome`/`chromium`/`firefox` from `PATH` (or via `VB_CHROME_BIN` / `VB_FIREFOX_BIN`), runs every browser and automation framework installed in your environment, marks any uninstalled optional framework as `SKIPPED_MISSING_TOOL` (never fabricating blocks), and writes machine-readable results to `benchmarks/results.json`.
