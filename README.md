<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/veilbreak-hero-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="assets/veilbreak-hero-light.svg" />
    <img src="assets/veilbreak-hero-light.svg" alt="VeilBreak — Universal Anti-Stealth &amp; Browser Integrity Gate" width="400" />
  </picture>
</p>

<h1 align="center">VeilBreak</h1>

<p align="center">
  <a href="#live-19-browser-benchmark"><img src="assets/badges/version.svg" alt="version: 2.2.0" /></a>
  <a href="docs/invariants-and-threat-model.md"><img src="assets/badges/invariants.svg" alt="invariants: 15 + kinematics" /></a>
  <a href="#live-19-browser-benchmark"><img src="assets/badges/engines.svg" alt="engines: Chromium + Gecko" /></a>
  <a href="#quickstart"><img src="assets/badges/deps.svg" alt="deps: 0" /></a>
  <a href="LICENSE"><img src="assets/badges/license.svg" alt="license: MIT" /></a>
</p>

<p align="center">
  <a href="#live-19-browser-benchmark">Benchmark</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#modes--honest-boundaries">Presets &amp; Boundaries</a> &middot;
  <a href="#documentation--ecosystem">Docs</a>
</p>

**VeilBreak** is a zero-dependency browser integrity SDK (`fetch` + `XMLHttpRequest`), `<veil-break>` closed Shadow DOM Web Component, reverse-proxy middleware, unified **ProxySnare** browser-proof provider (`VB_HS_V3`), and thread-safe pure-stdlib Python verifier for detecting and blocking `curl`, Firecrawl/AI scrapers, headless automation, active CDP sessions, CDP-patched forks, JS-spoofed plugins, and C++-patched anti-detect browsers across Chromium and Gecko engines.

## Problem & Solution

**Problem:** Modern stealth browsers, Firecrawl/Browserless scraping clouds, CDP-patched automation forks, and JS evasion plugins strip `navigator.webdriver`, hide `Runtime.enable` traps, and forge User-Agent and GPU strings directly inside C++ or injected wrappers. Naive bot detectors either miss them or block legitimate desktop, mobile, Brave, Safari, accessibility, and developer visitors.

**Solution:** VeilBreak checks properties stealth frameworks struggle to keep consistent across layers: **15 cross-engine graphics, audio, font, viewport, software-WebGL, active-CDP, fresh-`iframe`, and `Web Worker` invariants** paired with Stage-2 click kinematics, Firecrawl/AI-crawler blocking, static SRI (`?v=<hash12>`), and IP+UA+PoW+method/path-bound single-use server tickets (`VB_ATTEST_V2`) — or zero-extra-round-trip `VB_HS_V3` handshake proofs inside ProxySnare's `createUnifiedShield`. Five adjustable presets (`off`, `monitor`/`observe`, `balanced`, `strict`, `paranoid`) let every team tune the exact availability-vs-security balance.

## Features

- **15 Cross-Engine Physics, Active CDP & Headless-Cloud Invariants**: Checks Canvas2D / `OffscreenCanvas` solid-fill noise & repeat determinism, WebGL dither-free `gl.clear(128/255)` readback & GPU hardware coherence, corroborated headless software WebGL (`SwiftShader`/`llvmpipe` + CDP/automation), preset-weighted active CDP fingerprinting (`cdpActive`, native `console.debug` verified so Sentry/Datadog RUM never false-positives), silent `OfflineAudioContext` noise, zoom-safe `DOMRect` poisoning, accessibility/RFP-safe OS core font presence, Wayland/compact-safe viewport geometry, and permissions coherence.
- **Zero-FP Privacy, Accessibility & Mobile Engineering**: Exempts clean native Brave Shields deterministic LSB farbling, Safari zoom, Firefox custom-font accessibility & RFP, Linux Wayland, VoiceOver/NVDA/JAWS screen readers, MacBook touchpad taps, and Sentry/Datadog wrapped `console.debug`; honors Express `app.set("trust proxy", ...)`; automatically retries `X-VB-Retry-Ticket: 1` on mobile Wi-Fi↔5G IP roaming and same-origin `GET`/`HEAD` redirects in both `fetch()` and `XMLHttpRequest`.
- **Firecrawl & AI-Crawler Denial + Unified `VB_HS_V3` Bridge**: Blocks `Firecrawl`, `Apify`, `Browserless`, `Stagehand`, `GPTBot`, `ClaudeBot`, `x-firecrawl-*`, etc. by default (`blockAiCrawlers: false` to opt out), and exposes `collectHandshakeProof(challenge)` / `verifyHandshakeProof()` over a private per-page bridge token so `proxysnare/unified` binds real-browser verification directly into `POST /__proxysnare/handshake`.
- **Hardened IP + UA + PoW + Method/Path-Bound One-Time Tickets (`VB_ATTEST_V2`) & Pluggable Store**: Supports optional multi-worker async `store` adapter (`get`/`set`/`take`/`delete`), content-hashed `?v=<hash12>` immutable `gate.js` with `sha384` SRI, and full parity with `python/veilbreak.py` (accepting FastAPI/Starlette `Headers`, Flask/Werkzeug, Django, and `HTTPMessage` mappings).
- **Modular Subpath Exports & Bundled `.d.ts`**: Import `veilbreak/presets`, `veilbreak/probes`, `veilbreak/middleware`, `veilbreak/browser-sdk`, or `veilbreak/nl` with TypeScript declarations.

---

## Live 19-Browser Benchmark

Measured live against a running VeilBreak server (`mode=strict`, `benchmarks/run_live_benchmark.py`, raw data in [`benchmarks/results.json`](benchmarks/results.json)). Clean Linux desktop controls (Chrome 158 and Firefox 153 ESR) were run in isolated Xvfb profiles with simulated multi-step OS pointer trajectories (`87.6–88.0 ms` dwell via `xdotool`).

- **Clean Linux Desktop Controls (`N = 2`):** **`2 / 2` ALLOWED** *(Windows, macOS, Safari/WebKit, mobile, and live privacy browsers are not yet part of this automated matrix — see [Modes & Honest Boundaries](#modes--honest-boundaries))*
- **Stage-1 Passive Detection (zero interaction):** **`15 / 17` BLOCKED (`88.2%`)** — median probe time `19.7 ms` across the 14 browsers executing JS (`15.8 ms` including `0.0 ms` HTTP-403 UA blocks; Gecko probes take `20–70 ms`)
- **Stage-1 + Stage-2 Combined (with click kinematics):** **`17 / 17` BLOCKED (`100.0%`)**

| Browser / Framework | Category | Stage 1 | Stage 2 | Key Triggered Signals |
| :--- | :--- | :-: | :-: | :--- |
| **Google Chrome 158 (Clean Desktop)** | Control | **ALLOW (`0`)** | **ALLOW (`+0`)** | `CLEAN` (`10.1 ms` probe; `13` moves, `87.6 ms` dwell) |
| **Mozilla Firefox 153 ESR (Clean Desktop)** | Control | **ALLOW (`0`)** | **ALLOW (`+0`)** | `CLEAN` (`53.0 ms` probe; `17` moves, `88.0 ms` dwell) |
| **`curl` / Python `urllib`** | Tier 1 | **BLOCK (`6`)** | `n/a` | `AUTOMATION_UA_DENIED`, `ATTEST_REQUIRED`, `TICKET_REPLAYED_OR_INVALID` |
| **Playwright Chromium (Headless)** | Tier 2 | **BLOCK (`6`)** | `n/a` | `AUTOMATION_UA_DENIED` (HTTP 403) |
| **Playwright Chromium (Headed)** | Tier 2 | **BLOCK (`6`)** | **BLOCK (`+4`)** | `WEBDRIVER_FLAG`, `VIEWPORT_GEOMETRY`, `TELEPORT_CLICK` |
| **Playwright Firefox 151 (Headless / Headed)** | Tier 2 | **BLOCK (`8`)** | **BLOCK (`+4`)** | `WEBDRIVER_FLAG`, `VIEWPORT_GEOMETRY`, `TELEPORT_CLICK` |
| **Playwright + `playwright-stealth`** | Tier 3 | **BLOCK (`6`)** | `n/a` | `AUTOMATION_UA_DENIED` (default headless UA -> HTTP 403) |
| **Puppeteer + `puppeteer-extra-stealth`** | Tier 3 | **BLOCK (`12`)** | **BLOCK (`+4`)** | `WORKER_REALM`, `WEBGL_HARDWARE`, `OS_FONT`, `TELEPORT_CLICK` |
| **CloakBrowser 146 (Headless / Headed)** | Tier 4a | **BLOCK (`12`/`10`)** | **BLOCK (`+4`)** | `CANVAS2D`, `WEBGL_CLEAR`, `AUDIO`, `DOMRECT`, `OS_FONT`, `TELEPORT_CLICK` |
| **Camoufox 158 (Headless)** | Tier 4a | **BLOCK (`4`)** | **BLOCK (`+4`)** | `CANVAS2D_NON_DETERMINISTIC`, `TELEPORT_CLICK` |
| **Camoufox 158 (Headed)** | Tier 4a | **ALLOW (`0`)*** | **BLOCK (`+4`)** | `TELEPORT_CLICK` *(caught at Stage 2 on interaction)* |
| **Patchright (Headless)** | Tier 4b | **BLOCK (`6`)** | `n/a` | `AUTOMATION_UA_DENIED` (HTTP 403) |
| **Patchright (Headed)** | Tier 4b | **BLOCK (`2`)**† | **BLOCK (`+4`)** | `VIEWPORT_GEOMETRY`, `TELEPORT_CLICK` |
| **Rebrowser-Playwright (Headless)** | Tier 4b | **BLOCK (`6`)** | `n/a` | `AUTOMATION_UA_DENIED` (HTTP 403) |
| **Rebrowser-Playwright (Headed)** | Tier 4b | **BLOCK (`2`)**† | **BLOCK (`+4`)** | `VIEWPORT_GEOMETRY`, `TELEPORT_CLICK` |
| **SeleniumBase UC Mode (Headed)** | Tier 4b | **BLOCK (`6`)** | **BLOCK (`+6`)** | `AUTOMATION_GLOBAL`, `VIEWPORT_GEOMETRY`, `UNTRUSTED_CLICK` |
| **Nodriver (Headed)** | Tier 4b | **ALLOW (`0`)** | **BLOCK (`+6`)** | `UNTRUSTED_SYNTHETIC_CLICK` *(caught at Stage 2)* |

*\*Camoufox (Headed) passed Stage 1 when rolling a matching-OS zero-noise profile; cross-OS / noise profiles trigger Stage 1 invariants. †Patchright & Rebrowser (Headed) were launched with default Playwright viewport settings (scoring `2` via `VIEWPORT_GEOMETRY_IMPOSSIBILITY` at Stage 1, and caught by `TELEPORT_CLICK_PHYSICS` `+4` at Stage 2 regardless of `no_viewport=True`).*

---

## Quickstart

### 1. Clone & Launch Diagnostic Playground (Zero Dependencies, Node >= 20)

```bash
git clone https://github.com/HUSMUS9999/veilbreak.git
cd veilbreak
node bin/veilbreak.js demo --port 8089 --mode strict
# Open http://127.0.0.1:8089/__veilbreak/playground
```

### 2. Natural-Language CLI (`explain` & `ask`)

```bash
# Preview the exact command first (safe dry-run)
node bin/veilbreak.js explain "block stealth browsers on http://localhost:3000 on port 8080"

# Protect any upstream web app via reverse proxy (auto-injects /__veilbreak/gate.js)
node bin/veilbreak.js ask "block stealth browsers on http://localhost:3000 on port 8080"

# Behind Nginx / ALB / Cloudflare (supports IPv4/IPv6 CIDR trust lists)
node bin/veilbreak.js ask "block stealth browsers on http://localhost:3000 on port 8080 behind nginx"

# Balanced mode (requires score >= 4 on physics invariants while enforcing one-time PoW tickets)
node bin/veilbreak.js ask "protect http://localhost:3000 on port 8080 in balanced mode"
```

### 3. Drop-In HTML & `<veil-break>` Web Component

```html
<!-- Full-page automatic protection (instruments both fetch() and XMLHttpRequest) -->
<script src="/__veilbreak/gate.js" data-mode="strict" data-block-page="true"></script>

<!-- Or gate specific UI widgets inside a closed Shadow DOM component -->
<!-- Pass data-anti-cdp="false" / anti-cdp="false" in staging if developers keep DevTools open -->
<script src="/__veilbreak/gate.js" data-mode="strict" data-block-page="false"></script>
<veil-break mode="strict">
  <my-pricing-widget></my-pricing-widget>
</veil-break>
```

*`<veil-break>` dispatches `veilbreak-allowed` and `veilbreak-denied` CustomEvents on the host element. Light DOM children still exist in initial HTML until hydrated; keep confidential data behind protected `/api/*` endpoints.*

### 4. Node.js / Express Middleware & Python Verifier

```js
const express = require("express");
const { createVeilBreakMiddleware } = require("veilbreak/middleware"); // or require("./src/index.js")

const app = express();
app.use(createVeilBreakMiddleware({
  mode: "strict",              // "strict" (>=2) | "balanced" (>=4) | "monitor" ("observe") | "off"
  protectedPaths: ["/api"],
  trustProxy: ["127.0.0.1", "10.0.0.0/8"],
  antiCdp: true,               // set false in dev/staging if DevTools stays open
  enablePlayground: false,     // disable diagnostic playground in production
  exposeDebugHeaders: false,   // hide scoring headers in production
  onDetect: (ev) => console.log(ev.blocked, ev.score, ev.reasons),
}));
// Note: unlike createVeilBreakServer, direct middleware does NOT auto-inject HTML;
// add <script src="/__veilbreak/gate.js"></script> to your HTML templates.
```

```python
import sys
sys.path.insert(0, "python")
from veilbreak import VeilBreakTicketStore, is_path_protected

# Thread-safe one-time ticket store with IP/UA/PoW/method/path binding parity
vb = VeilBreakTicketStore(mode="strict")

# 1. Serve GET /__veilbreak/ticket ->
#    rec = vb.mint_ticket_challenge(ip=client_ip, user_agent=request.headers.get("User-Agent", ""))
#    if rec is None: return 503, {"error": "TICKET_CAPACITY_EXCEEDED"}
#    return 200, {"ok": True, **rec}
# 2. On protected /api/* routes (checked with is_path_protected(request.full_path, ["/api"])):
verdict = vb.verify_request(
    headers=dict(request.headers),
    ip=client_ip,
    method=request.method,
    path=request.path,
)
if verdict.blocked:
    return 403, {"error": "VEILBREAK_DENIED"}
```

---

## Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/veilbreak-arch-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="assets/veilbreak-arch-light.svg" />
    <img src="assets/veilbreak-arch-light.svg" alt="VeilBreak Dual-Stage Browser Integrity Gate Architecture" width="100%" />
  </picture>
</p>

---

## Modes & Honest Boundaries

| Preset | Threshold | PoW Bits | IP Bind | CDP Weight | Auto-Block DOM | Recommended Use |
| :--- | :-: | :-: | :-: | :-: | :-: | :--- |
| **`off`** | `∞` | `0` | Off | `0` | Off | Local development & automated integration tests |
| **`monitor`** *(alias: `observe`)* | `∞` | `0` | Off | `+1` | Off | Staging, shadow auditing & rollout verification |
| **`balanced`** | `>= 4` | `10` | **Off** *(mobile safe)* | `+1` *(DevTools + single farbling = `3 < 4`)* | **Off** | **Best default for public consumer sites** — blocks Firecrawl, Docker headless (`+3 + 1 = 4`), stealth forks & bots with zero FP on mobile/Brave/DevTools |
| **`strict`** *(default)* | `>= 2` | `12` | On *(auto-retries IP roam)* | `+4` *(`+1` with `allowDevTools: true`)* | On *(only at score `>= 4`)* | Protected APIs, anti-scraping & high-value web apps |
| **`paranoid`** | `>= 2` | `14` | On | `+6` *(hard-fail unless `allowDevTools: true`)* | On *(only at score `>= 4`)* | Maximum anti-CDP / anti-automation hardening |

*HTTP operational status codes: `403` (blocked / invalid or replayed ticket / failed PoW), `429` (per-IP `/ticket` rate limit exceeded), `503` (ticket store capacity reached — fails closed).*

### Important Security & Operational Caveats
- **Client-Side Telemetry Scope (`VB_ATTEST_V2` / `VB_HS_V3`):** Defeats out-of-the-box `curl`, Firecrawl/AI scrapers, headless/stealth browsers, and Caido/Burp Repeater replay/path-tampering workflows. However, because probe execution runs inside client JavaScript, a dedicated adversary who reverse-engineers `gate.js`, forges complete desktop browser headers + Fetch Metadata, solves `VB_POW_V2`, and submits synthetic `s=0, f=0` JSON operates at the irreducible client-side boundary. Pair with **ProxySnare (`createUnifiedShield`)**, authentication, rate limiting, and server-side business rules.
- **Open DevTools (`CDP_RUNTIME_ENABLE`):** In `balanced` mode, open DevTools scores only `+1` (never solo-blocks, even alongside a single `+2` privacy quirk). In `strict`/`paranoid`, pass `allowDevTools: true` (or `antiCdp: false`) when developers keep DevTools open.
- **Aggressive Multi-Signal Privacy Browsers:** Clean native Brave Standard Shields and Firefox custom-font accessibility are exempted, and `balanced` tolerates single-signal Firefox Private Browsing Canvas randomization + open DevTools. Multi-signal privacy profiles that simultaneously randomize Canvas + WebGL + Audio (e.g., Tor Browser) can still reach `score >= 4`; audit with `monitor` mode first on Tor-heavy audiences.
- **Plain HTML `<form>` Posts & Sync XHR:** `gate.js` automatically instruments `window.fetch()` and async `XMLHttpRequest` (including Axios/jQuery/HTMX). Plain HTML `<form>` submissions or deprecated synchronous XHR cannot attach async tickets and should use `fetch()`/async XHR or stay outside `protectedPaths`.
- **Multi-Worker Scaling:** Pass an optional async `store` adapter (`{ get, set, take, delete }`, e.g., Redis) to `createVeilBreakMiddleware({ store })` or enable sticky sessions behind load balancers.

---

## Testing & Reproducing Benchmarks

```bash
# Run zero-dependency Node.js + Python parity unit & integration tests
npm test

# Reproduce the live benchmark for any installed browsers on your machine
# (missing third-party frameworks are marked SKIPPED_MISSING_TOOL, never fabricated as 403)
python3 benchmarks/run_live_benchmark.py
```

---

## Documentation & Ecosystem

- **[15 Invariants, Kinematics & Threat Model](docs/invariants-and-threat-model.md)** — Complete specification of every invariant, server-side scoring weight, `VB_ATTEST_V2` PoW/binding wire format, and honest boundaries.
- **[Natural-Language Beginner's Guide](docs/getting-started-beginners.md)** — Copy-paste `ask`/`explain` recipes and live playground walkthrough.
- **[Live Benchmark Raw Results](benchmarks/results.json)** — Machine-readable JSON output from the 19-browser test run.

Companion repositories:
- **[Vibe-Slayer](https://github.com/HUSMUS9999/vibe-slayer)** — Zero-dependency Rust + C99 asset, binary, website/Web Component, AI weight, and zero-geometry 3D stream protection platform.
- **[ProxySnare](https://github.com/HUSMUS9999/proxysnare)** — Standalone reverse-proxy shield, middleware, and Python verifier defending browser APIs against `curl` and Caido/Burp Repeater via ephemeral `PS_ECDH_V2`.

---

## License

MIT License — see [LICENSE](LICENSE).
