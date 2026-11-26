# VeilBreak — 15 Invariants, Active CDP, Click Kinematics & Threat Model

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md)

VeilBreak checks **15 cross-engine graphics, audio, cross-realm, prototype, geometry, active-CDP, headless-software-WebGL, and engine-coherence invariants** (Stage 1) plus a **biomechanical interaction kinematics layer** (Stage 2), bound either to IP+UA+PoW+method/path-bound single-use server tickets (`VB_ATTEST_V2`) or directly into ProxySnare's ECDSA-authenticated ECDH handshake (`VB_HS_V3`).

---

## Stage 1: The 15 Passive & Active-CDP Invariants

| # | Code | Weight | Exact Check | Primary Targets |
| :-: | :--- | :-: | :--- | :--- |
| 1 | `WEBDRIVER_FLAG` | `+4` | `navigator.webdriver` or untouched `iframe.contentWindow.navigator.webdriver` is `true` | Playwright, Selenium, Puppeteer |
| 2 | `AUTOMATION_GLOBAL_ARTIFACT` | `+4` | `window`/`document` owns `$cdc_*`, `cdc_*`, `__playwright*`, `__pw_manual`, `__pwInitScripts`, `__puppeteer*`, `__webdriver*`, `domAutomation*` | SeleniumBase UC, Chromedriver, Playwright |
| 3 | `CDP_RUNTIME_ENABLE` | `+1` (`balanced`/`allowDevTools`) / `+4` (`strict`) / `+6` (`paranoid`) | Native-verified `console.debug(err)` invokes custom `Error.stack` getter side-channel *(uses lightweight closed-ShadowRoot iframe fallback if Sentry/Datadog wraps `console.debug`; re-evaluated live after load)* | Active CDP `Runtime.enable` scrapers |
| 4 | `WEBDRIVER_GETTER_SPOOFED` | `+4` | Own-property `navigator.webdriver` override or non-native `Navigator.prototype.webdriver` getter (verified on both main realm and closed-ShadowRoot fresh iframe) | `playwright-stealth`, custom JS spoofers |
| 5 | `NATIVE_FUNCTION_TAMPERED` | `+4` | Closed-ShadowRoot fresh `iframe.contentWindow.Function.prototype.toString` mismatches main-thread `toString`, throws on Proxy trap, or lacks `[native code]` on core APIs (`toDataURL`, `getImageData`, `getParameter` WebGL1/2, `platform`, `userAgent`, `permissions.query`, `RegExp.prototype[Symbol.replace]`, `OfflineAudioContext.prototype.startRendering`) | `playwright-stealth`, JS stealth wrappers |
| 6 | `WORKER_REALM_CONTRADICTION` | `+4` | `Web Worker` (`self.navigator`) reports a different `platform`, `hardwareConcurrency`, `userAgent`, cross-OS GPU family, or `webdriver` state than the main thread *(Brave & dual-GPU laptop safe)* | `puppeteer-extra-plugin-stealth` |
| 7 | `CANVAS2D_SYNTHETIC_NOISE` / `NON_DETERMINISTIC` | `+2` / `+4` | Flat `#808080` Canvas2D or `OffscreenCanvas` produces `> 1` unique RGB color (`+2`; clean Brave Shields, Firefox Private/ETP FPP, LibreWolf RFP & Safari 17+/iOS 17+ Private Browsing ATP deterministic farbling exempted), or two identical renders differ (`+4`) | CloakBrowser, Camoufox, noise forks |
| 8 | `WEBGL_CLEAR_SYNTHETIC_NOISE` | `+2` | Dither-disabled `gl.clearColor(128/255, ...)` + `gl.readPixels()` yields `> 1` unique color *(clean Brave, Firefox FPP/RFP & Safari 17+ Private Browsing ATP exempted)* | CloakBrowser, WebGL-noise forks |
| 9 | `WEBGL_HARDWARE_COHERENCE_LIE` | `+2` | Discrete/D3D11 GPU string with impossibly low extension count (`<= 12` WebGL2 / `<= 19` WebGL1), GTX 6/7/9xx claiming `MAX_TEXTURE_SIZE >= 32768`, macOS renderer on claimed Windows, D3D11 on claimed Linux or macOS, or Chromium D3D11 RTX missing `KHR_parallel_shader_compile` (`< 30` exts) | Camoufox, CloakBrowser, `puppeteer-stealth` |
| 10 | `SILENT_AUDIO_SYNTHETIC_NOISE` | `+2` | All-zero `OfflineAudioContext` buffer renders non-zero samples (`|x| > 1e-12`, 1.5s timeout-guarded) | CloakBrowser, audio-noise forks |
| 11 | `DOMRECT_SUBPIXEL_POISONING` | `+2` | CSP-safe CSSOM fixed `10×20` `100×50` box at integer DPR (skipped when `visualViewport.scale !== 1` or root CSS zoom/transform is active; same-`left` sibling comparison on Safari) drifts within `(1e-3, 1.5) px` | CloakBrowser, DOMRect-poisoning forks |
| 12 | `OS_CORE_FONT_LIE` | `+2` | Claims desktop Windows or macOS (non-touch) with `0` OS core fonts while `sans-serif !== monospace` *(skips Firefox custom-font accessibility overrides & RFP)* | CloakBrowser, `puppeteer-stealth`, cross-OS spoofers |
| 13 | `VIEWPORT_GEOMETRY_IMPOSSIBILITY` | `+2` | Integer-DPR non-fullscreen desktop (Wayland, compact browsers, notch, F11, PWA & tiling-WM safe) with zero chrome on default automation viewport (`1280×720` / `800×600` at `(0,0)`) or corroborated automation | Patchright, Rebrowser, Playwright, SeleniumBase UC |
| 14 | `ENGINE_COHERENCE_LIE` | `+2` | Genuine `Notification.permission` contradiction (`default`/`denied` while `permissions.query` reports `granted`, 900ms timeout-guarded) | Broken permission-spoofing scripts |
| 15 | `HEADLESS_SOFTWARE_WEBGL` | `+3` | Software WebGL renderer (`SwiftShader`, `llvmpipe`, `Mesa OffScreen`) corroborated by active CDP (when `!allowDevTools`), `webdriver`, automation globals, missing `window.chrome`, or viewport anomaly | Firecrawl, Browserless, Docker headless Chromium |

---

## Stage 2: Biomechanical Interaction Kinematics

When a user interacts with a visible control before calling a protected API, VeilBreak evaluates pointer kinematics (tracked per element via `WeakMap` and reset per click):

- **`UNTRUSTED_SYNTHETIC_CLICK` (`+6`)**: `event.isTrusted === false` (catches Nodriver `.click()`, SeleniumBase UC `.uc_click()`, and synthetic DOM dispatch).
- **`TELEPORT_CLICK_PHYSICS` (`+4`)**: `event.isTrusted === true && event.detail >= 1` (non-touch/non-pen) with `pointerMoves <= 3`, `pointerdown`→`click` `dwellMs < 12 ms`, and exact geometric center hit (`< 0.75 px`).
- **`ZERO_TRAJECTORY_INSTANT_CLICK` (`+4`)**: `event.isTrusted === true && event.detail >= 1` (non-touch/non-pen) with `pointerMoves === 0` and `0 < dwellMs < 8 ms` (excludes `dwellMs === 0` coarsened privacy timers).
- **Accessibility & Mobile Exemptions (`0` penalty)**: Trusted keyboard activation (`Enter`/`Space` → `isTrusted === true && detail === 0`), trackpad taps, and `touch`/`pen` pointer events are explicitly exempted.

---

## Hardened One-Time Ticket Envelope (`VB_ATTEST_V2` + `VB_POW_V2`)

1. **Ticket Minting (`GET /__veilbreak/ticket`):**
   - Rejects CLI/proxy/automation UAs, `Sec-Fetch-Site: cross-site`, cross-origin `Origin`, missing `Sec-Fetch-*` / `Accept-Language` on modern browser UAs, `Connection: close` (skipped behind trusted reverse proxies), and per-IP rate limits (`429`).
   - Returns `{ ok: true, ticket, challenge, difficulty, mode }` (`503` fail-closed at capacity). Each ticket is bound to `(ip, sha256(User-Agent))` and deleted atomically on first use.
2. **Proof-of-Work & Request Binding:**
   - `gate.js` solves `leading_zero_bits(SHA-256("VB_POW_V2|" + ticket + "|" + challenge + "|" + powNonce)) >= difficulty` (`12` bits strict / `10` bits balanced, ~1–2 ms) and computes:
   ```text
   SHA-256("VB_ATTEST_V2|" + ticket + "|" + nonce + "|" + score + "|" + flags + "|" + platform + "|" + challenge + "|" + powNonce + "|" + METHOD + "|" + path)
   ```
   - Transmitted via `X-VB-Ticket`, `X-VB-Nonce`, and `X-VB-Attest` on both `window.fetch()` (with automatic 1x re-attestation on same-origin `GET`/`HEAD` `302` redirects) and async `XMLHttpRequest`.

### Server-Side Enforcement Signals (Node `src/probes.js` & Python `python/veilbreak.py` Parity)

| Signal Code | Weight | Trigger Condition |
| :--- | :-: | :--- |
| `CL_TE_SMUGGLING` | `+10` | Both `Content-Length` and `Transfer-Encoding` headers present |
| `AI_CRAWLER_OR_SCRAPER_DENIED` | `+6` | Firecrawl, Apify, Browserless, Stagehand, GPTBot, ClaudeBot, or `x-firecrawl-*` / `x-browserless-*` scraper header detected |
| `AUTOMATION_UA_DENIED` | `+6` | Missing UA or CLI/proxy/automation UA (`curl`, `python-requests`, `HeadlessChrome`, `Burp`, `Caido`, `Playwright`, etc.) |
| `PROXY_HEADER_LEAK` | `+6` | Explicit intercepting proxy artifact header (`Proxy-Connection`, `X-Burp-*`, `X-Caido-*`, `X-Mitmproxy`) |
| `CROSS_SITE_REQUEST_DENIED` | `+6` | `Sec-Fetch-Site: cross-site` on protected route |
| `FETCH_METADATA_MISSING` | `+6` | Modern browser UA missing `Sec-Fetch-Site`/`Sec-Fetch-Mode` when `requireFetchMetadata` is enabled (default `true` in `strict`) |
| `TICKET_REPLAYED_OR_INVALID` | `+6` | Ticket missing, unknown, expired, or already consumed |
| `TICKET_BINDING_MISMATCH` | `+6` | Client IP or `User-Agent` changed between `/ticket` and protected API call |
| `POW_INVALID` | `+6` | `VB_POW_V2` nonce missing or fails required leading-zero difficulty |
| `REQUEST_BINDING_MISMATCH` | `+6` | Attested HTTP method or normalized pathname does not match the actual request |
| `ATTEST_REQUIRED` / `ATTEST_INVALID` / `ATTEST_DIGEST_MISMATCH` | `+6` | Missing, malformed, delimiter-injected (`\|`), inconsistent flag/score, or mismatched `VB_ATTEST_V2` SHA-256 digest |
| `UA_PLATFORM_CONTRADICTION` / `OS_PLATFORM_CONTRADICTION` | `+4` | Mismatch across `User-Agent`, `Sec-CH-UA-Platform`, and `navigator.platform` |
| `CHROME_GREASE_OUTDATED` | `+2` | Chrome 115+ claiming legacy `"Not A;Brand"` GREASE token |

Path matching (`isProtectedPath` / `is_path_protected`) expands lenient percent-decoding (`/%61pi`, `%ff`), dot-segments (`/api/%2e%2e/secret`), null bytes (`%00`), fragments (`#`), encoded queries (`%3F`), trailing dots/spaces (`/api./`, `/api%20/`), matrix params, and `X-Original-URL`/`X-Rewrite-URL` overrides identically in Node and Python.

---

## Honest Threat Model & Irreducible Boundaries

- **Client-side telemetry boundary:** Because `VB_ATTEST_V2` executes inside client JavaScript, a motivated adversary who reverse-engineers `gate.js`, spoofs full desktop headers + Fetch Metadata, fetches a ticket from the same IP/UA, and solves `VB_POW_V2` in a custom script can still submit synthetic `s=0, f=0` telemetry without running a real browser. VeilBreak defeats off-the-shelf `curl`, headless/stealth browsers, and Caido/Burp Repeater replay/edits; always pair with authentication, rate limiting, and server-side business policy.
- **Stage-1 vs. Stage-2 coverage:** Unmodified headed Chrome/Firefox driven without viewport overrides or synthetic noise (e.g., Nodriver Headed, or Camoufox Headed on a matching-OS zero-noise profile) can pass Stage 1 and are caught at Stage 2 when clicking programmatically. A bot simulating realistic multi-step OS pointer motion or keyboard focus+Enter sits at the irreducible client-side boundary.
- **Privacy browser & DevTools trade-offs:** Clean native Brave Standard Shields, Firefox Private/ETP FPP, LibreWolf / Firefox RFP (`hw=2/4`), and Safari 17+/iOS 17+ Private Browsing ATP deterministic noise are exempted (and `balanced` `>= 4` scores open DevTools at only `+1`). Multi-signal privacy profiles that simultaneously randomize Canvas + WebGL + Audio non-deterministically (e.g., Tor Browser) can still reach `score >= 4`; pass `allowDevTools: true` (or `antiCdp: false`) in developer environments and audit with `monitor` mode first on Tor-heavy consumer traffic.
