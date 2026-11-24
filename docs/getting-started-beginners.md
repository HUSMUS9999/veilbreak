# VeilBreak — Natural-Language Beginner's Guide

You do not need to memorize flags or security terminology to protect an app with VeilBreak. Describe what you want in natural language using `explain` (safe preview, zero side effects) or `ask` (run immediately).

---

## Everyday Natural-Language Recipes

```bash
# 1. Preview safely first (dry-run — prints the exact command and why)
npx veilbreak explain "block stealth browsers on http://localhost:3000 on port 8080"

# 2. Protect your app in strict mode (maximum protection across all engines)
npx veilbreak ask "block stealth browsers on http://localhost:3000 on port 8080"

# 3. Protect your app while keeping privacy browsers (Brave / LibreWolf) working
npx veilbreak ask "protect http://localhost:3000 on port 8080 while keeping privacy browsers working"

# 4. Monitor & score traffic without blocking anyone (observe first)
npx veilbreak ask "watch for anti-detect browsers without blocking on http://localhost:3000"

# 5. Print ready-to-paste HTML, <veil-break> Web Component, and Express snippets
npx veilbreak ask "give me html and web component snippet"

# 6. Launch the interactive 14-invariant diagnostic playground
npx veilbreak ask "show me a demo"
```

---

## Testing Live in Your Own Browsers

1. Start the interactive diagnostic playground:
   ```bash
   node bin/veilbreak.js demo --port 8089 --mode strict
   ```
2. Open `http://127.0.0.1:8089/__veilbreak/playground` in **standard Google Chrome** or **Mozilla Firefox** — all 14 invariants report `CLEAN` (`score = 0`), `<veil-break>` mounts cleanly, and clicking **Verify Protected Action** returns `HTTP 200`.
3. Open the exact same URL from any automated or stealth browser (Playwright, Puppeteer-Stealth, Patchright, Rebrowser, CloakBrowser, Camoufox, SeleniumBase UC, or Nodriver) to watch the specific invariants trigger in real time.

---

## Reproducing the 19-Browser Live Benchmark

```bash
python3 benchmarks/run_live_benchmark.py
```

The runner starts a live local VeilBreak server (`benchmarks/bench_server.js`), tests clean desktop controls (Chrome + Firefox with real OS mouse movement via `xdotool`) alongside all installed stealth & automation frameworks, and writes machine-readable output to `benchmarks/results.json`.
