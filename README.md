<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/veilbreak-hero-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="assets/veilbreak-hero-light.svg" />
    <img src="assets/veilbreak-hero-light.svg" alt="VeilBreak — Universal Anti-Stealth &amp; Browser Integrity Gate" width="400" />
  </picture>
</p>

<h1 align="center">VeilBreak</h1>

<p align="center">
  <a href="#live-19-browser-benchmark"><img src="assets/badges/version.svg" alt="version: 2.1.0" /></a>
  <a href="docs/invariants-and-threat-model.md"><img src="assets/badges/invariants.svg" alt="invariants: 14 + kinematics" /></a>
  <a href="#live-19-browser-benchmark"><img src="assets/badges/engines.svg" alt="engines: Chromium + Gecko" /></a>
  <a href="#quickstart"><img src="assets/badges/deps.svg" alt="deps: 0" /></a>
  <a href="LICENSE"><img src="assets/badges/license.svg" alt="license: MIT" /></a>
</p>

<p align="center">
  <a href="#live-19-browser-benchmark">Benchmark</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#modes--honest-boundaries">Modes &amp; Boundaries</a> &middot;
  <a href="#documentation--ecosystem">Docs</a>
</p>

**VeilBreak** is a zero-dependency browser integrity SDK (`fetch` + `XMLHttpRequest`), `<veil-break>` closed Shadow DOM Web Component, reverse-proxy middleware, and thread-safe pure-stdlib Python verifier for detecting and blocking `curl`, HTTP repeaters, headless automation, CDP-patched forks, JS-spoofed plugins, and C++-patched anti-detect browsers across Chromium and Gecko engines.

## Problem & Solution

**Problem:** Modern stealth browsers, CDP-patched automation forks, and JS evasion plugins strip `navigator.webdriver`, hide `Runtime.enable` traps, and forge User-Agent and GPU strings directly inside C++ or injected wrappers. Naive bot detectors either miss them or block unmodified desktop Chrome and Firefox visitors.

**Solution:** VeilBreak checks properties stealth frameworks struggle to keep consistent across layers: 14 cross-engine graphics, audio, font, viewport, fresh-`iframe`, and `Web Worker` invariants paired with Stage-2 click kinematics and IP+UA+PoW+method/path-bound single-use server tickets (`VB_ATTEST_V2`). In our live 19-browser Linux benchmark (`mode=strict`), both clean desktop controls passed (`0` score) while `15/17` automated/stealth browsers were blocked passively at Stage 1 and `17/17` were blocked when combined with Stage-2 click kinematics.

## Features

- **14 Cross-Engine Physics & Coherence Invariants**: Checks Canvas2D / `OffscreenCanvas` solid-fill noise & repeat determinism, WebGL dither-free `gl.clear(128/255)` readback & GPU hardware coherence, silent `OfflineAudioContext` noise, CSP-safe integer-DPR `DOMRect` poisoning, OS core font presence, viewport geometry impossibilities (notch/PWA/F11-safe), and permissions coherence.
- **Cross-Realm & Web Worker Verification**: Uses a fresh untouched `iframe` realm (Proxy-throw-aware native checks) and a dedicated `Web Worker` (`OffscreenCanvas` + `self.navigator`) to expose main-thread JS stealth wrappers and spoofed native getters.
- **Stage-2 Click Kinematics**: Flags untrusted synthetic DOM clicks (`isTrusted === false`) and programmatic CDP/Juggler teleport clicks (`<= 3` pointer moves, `< 12 ms` `pointerdown`→`click` dwell, dead-center hit), while exempting trusted keyboard activation (`Enter`/`Space`), trackpad taps, and `touch`/`pen` pointers.
- **Hardened IP + UA + PoW + Method/Path-Bound One-Time Tickets (`VB_ATTEST_V2`)**: `/__veilbreak/ticket` enforces CLI/proxy/automation UA denial, Fetch Metadata (`Sec-Fetch-Site`/`Sec-Fetch-Mode`), `Accept-Language`, and per-IP rate limits (`429`); protected API requests must present a single-use ticket, solve a lightweight `VB_POW_V2` SHA-256 PoW (`12`-bit strict / `10`-bit balanced), and bind `(challenge, powNonce, method, normalizedPath)` into the SHA-256 attestation digest.
- **Full `fetch()` + `XMLHttpRequest` Auto-Instrumentation & Modular Exports**: `gate.js` transparently instruments both `window.fetch()` (including same-origin `GET`/`HEAD` `302` redirect re-attestation) and async `XMLHttpRequest` (Axios, jQuery, HTMX, Angular HttpClient, with clean `abort()` recovery), provides `<veil-break>` closed Shadow DOM gating (React 18 reconnect-safe), exports modular subpaths (`veilbreak/probes`, `veilbreak/middleware`, `veilbreak/browser-sdk`, `veilbreak/nl`) with bundled `.d.ts` types, and maintains full parity with `python/veilbreak.py`.

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

*`<veil-break>` dispatches `veilbreak-verified` and `veilbreak-blocked` CustomEvents on the host element. Light DOM children still exist in initial HTML until hydrated; keep confidential data behind protected `/api/*` endpoints.*

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

| Mode | Threshold | PoW Bits | Behavior | Best For |
| :--- | :-: | :-: | :--- | :--- |
| `strict` *(default)* | `>= 2` | `12` | Blocks on any triggered physics/coherence invariant, CLI/automation UA, missing Fetch Metadata, or invalid/replayed PoW ticket | Protected APIs, anti-scraping, high-value web apps |
| `balanced` | `>= 4` | `10` | Enforces IP/UA/PoW one-time tickets and automation UA denial, while requiring `>= 4` on browser physics invariants (allows single `+2` Canvas-only farbling) | Public consumer sites needing headroom for single-signal farbling |
| `monitor` *(alias: `observe`)* | `∞` | `0` | Never blocks; emits `X-VeilBreak-Score` and `onDetect` telemetry | Staging, shadow auditing, rollout verification |
| `off` | `∞` | `0` | Completely disabled | Local development & automated integration tests |

*HTTP operational status codes: `403` (blocked / invalid or replayed ticket / failed PoW), `429` (per-IP `/ticket` rate limit exceeded), `503` (ticket store capacity reached — fails closed).*

### Important Security & Operational Caveats
- **Client-Side Telemetry Scope (`VB_ATTEST_V2`):** `VB_ATTEST_V2` enforces one-time IP/UA/PoW/method/path-bound tickets and Fetch Metadata checks, defeating out-of-the-box `curl`, headless browsers, and Caido/Burp Repeater replay/path-tampering workflows. However, because probe execution runs inside browser JS, a dedicated adversary who reverse-engineers `gate.js`, forges complete desktop browser headers + Fetch Metadata, fetches a ticket from the same IP/UA, and solves `VB_POW_V2` in a custom script can still submit synthetic `s=0, f=0` telemetry. Always pair VeilBreak with authentication, rate limiting, and server-side business rules.
- **Open DevTools (`CDP_RUNTIME_ENABLE`):** Opening browser DevTools trips `CDP_RUNTIME_ENABLE` (`+4`). Pass `antiCdp: false` (or CLI `--no-anti-cdp` / `data-anti-cdp="false"`) in staging/developer environments.
- **Multi-Signal Privacy Browsers:** `balanced` (`>= 4`) allows single-signal Canvas-only farbling (`+2`), but aggressive privacy browsers that simultaneously randomize Canvas + WebGL + Audio (e.g., Brave Shields Strict, LibreWolf / Firefox `privacy.resistFingerprinting`, Tor Browser) can still reach `score >= 4`. Audit with `monitor` mode first on privacy-heavy audiences.
- **Plain HTML `<form>` Posts & Sync XHR:** `gate.js` automatically instruments `window.fetch()` and async `XMLHttpRequest` (including Axios/jQuery/HTMX). Plain HTML `<form>` submissions or deprecated synchronous XHR cannot attach async tickets and should use `fetch()`/async XHR or stay outside `protectedPaths`.
- **Multi-Worker Scaling:** Default ticket storage is process-local (`Map`); enable sticky sessions behind load balancers when running multiple worker processes.

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

- **[14 Invariants, Kinematics & Threat Model](docs/invariants-and-threat-model.md)** — Complete specification of every invariant, server-side scoring weight, `VB_ATTEST_V2` PoW/binding wire format, and honest boundaries.
- **[Natural-Language Beginner's Guide](docs/getting-started-beginners.md)** — Copy-paste `ask`/`explain` recipes and live playground walkthrough.
- **[Live Benchmark Raw Results](benchmarks/results.json)** — Machine-readable JSON output from the 19-browser test run.

Companion repositories:
- **[Vibe-Slayer](https://github.com/HUSMUS9999/vibe-slayer)** — Zero-dependency Rust + C99 asset, binary, website/Web Component, AI weight, and zero-geometry 3D stream protection platform.
- **[ProxySnare](https://github.com/HUSMUS9999/proxysnare)** — Standalone reverse-proxy shield, middleware, and Python verifier defending browser APIs against `curl` and Caido/Burp Repeater via ephemeral `PS_ECDH_V2`.

---

## License

MIT License — see [LICENSE](LICENSE).
