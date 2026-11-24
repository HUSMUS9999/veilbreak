# VeilBreak — 14 Physics Invariants, Click Kinematics & Threat Model

VeilBreak does not rely on brittle User-Agent blocklists or single-browser signatures. Instead, it tests **14 cross-engine hardware, graphics, audio, cross-realm, prototype, geometry, and engine-coherence invariants** (Stage 1) plus a **biomechanical interaction kinematics layer** (Stage 2), all cryptographically bound to one-time server tickets (`VB_ATTEST_V2`).

---

## Stage 1: The 14 Passive Invariants

| # | Code | Category | Weight | Exact Invariant | Primary Targets Caught |
| :-: | :--- | :--- | :-: | :--- | :--- |
| 1 | `WEBDRIVER_FLAG` | Automation | `+4` | `navigator.webdriver` or untouched `iframe.contentWindow.navigator.webdriver` is `true` | Playwright (Chromium/Firefox), Selenium, Puppeteer |
| 2 | `AUTOMATION_GLOBAL_ARTIFACT` | Automation | `+4` | `window` or `document` owns `$cdc_*`/`cdc_*`/`__playwright*`/`__pw*`/`__puppeteer*`/`__webdriver*`/`domAutomation*` | SeleniumBase UC, Chromedriver, Playwright, Puppeteer |
| 3 | `CDP_RUNTIME_ENABLE` | Protocol | `+4` | `console.debug(err)` triggers custom `Error.stack` getter side-channel | Active CDP `Runtime.enable` scrapers & AI agents |
| 4 | `WEBDRIVER_GETTER_SPOOFED` | Prototype | `+4` | Own-property `navigator.webdriver` override or `Navigator.prototype.webdriver` getter fails native `function (get )?webdriver() { [native code] }` across Chromium & Gecko | `playwright-stealth`, custom JS webdriver overrides |
| 5 | `NATIVE_FUNCTION_TAMPERED` | Cross-Realm | `+4` | Fresh `iframe.contentWindow.Function.prototype.toString` exposes wrapped/non-native getters or main-vs-iframe divergence on `platform`, `userAgent`, `permissions.query`, `toDataURL`, `getImageData`, `getParameter`, `getOwnPropertyDescriptor` | `playwright-stealth`, JS stealth plugins |
| 6 | `WORKER_REALM_CONTRADICTION` | Cross-Realm | `+4` | `Web Worker` (`self.navigator` + `OffscreenCanvas`) reports a different `platform`, `hardwareConcurrency`, `userAgent`, or WebGL renderer than the main thread | `puppeteer-extra-plugin-stealth`, main-world spoofers |
| 7 | `CANVAS2D_SYNTHETIC_NOISE` / `CANVAS2D_NON_DETERMINISTIC` | Graphics Physics | `+2` / `+4` | Flat `#808080` 2D Canvas or `OffscreenCanvas` produces `> 1` unique RGB color, OR two identical draws differ (`repeatDiff > 0`) | CloakBrowser, Camoufox, noise-injecting Chromium/Gecko forks |
| 8 | `WEBGL_CLEAR_SYNTHETIC_NOISE` | Graphics Physics | `+2` | `gl.clearColor(0.5, 0.5, 0.5, 1.0)` + `gl.readPixels()` yields `> 1` unique color | CloakBrowser, Camoufox, WebGL-noise forks |
| 9 | `WEBGL_HARDWARE_COHERENCE_LIE` | Hardware Physics | `+2` | Discrete GPU / D3D11 string with `<= 19` WebGL extensions (Mesa `llvmpipe` masking as NVIDIA/D3D11); Maxwell/Pascal GTX 6/7/9/10 claiming `MAX_TEXTURE_SIZE >= 32768`; macOS-only renderer on claimed Windows; D3D11 on claimed Linux; or D3D11 RTX missing `KHR_parallel_shader_compile` with `< 30` extensions | Camoufox, CloakBrowser, `puppeteer-stealth`, `playwright-stealth` |
| 10 | `SILENT_AUDIO_SYNTHETIC_NOISE` | Audio Physics | `+2` | All-zero `OfflineAudioContext` buffer renders non-zero samples (`|x| > 1e-12`) | CloakBrowser, audio-noise anti-detect forks |
| 11 | `DOMRECT_SUBPIXEL_POISONING` | Layout Physics | `+2` | Integer-DPR fixed `10x20 100x50` box `getBoundingClientRect()` drifts `> 1e-3 px` | CloakBrowser, DOMRect-poisoning forks |
| 12 | `OS_CORE_FONT_LIE` | OS Physics | `+2` | Claims Windows with `0` Windows core fonts (`Segoe UI`/`Tahoma`/`Consolas`/`Calibri`), or claims macOS with `0` macOS core fonts (`Helvetica Neue`/`Geneva`/`Menlo`) | CloakBrowser, `puppeteer-stealth`, `playwright-stealth`, cross-OS spoofers |
| 13 | `VIEWPORT_GEOMETRY_IMPOSSIBILITY` | Window Physics | `+2` | Non-fullscreen desktop where `outerHeight > screen.height + 16` or `outerWidth > screen.width + 16` (CDP `setDeviceMetricsOverride` leak), OR zero browser chrome (`outer === inner === screen`), OR desktop with zero fine pointer and zero hover | Patchright (headed & headless), Rebrowser-Playwright (headed & headless), Playwright, Puppeteer-Stealth, SeleniumBase UC |
| 14 | `ENGINE_COHERENCE_LIE` | Engine Coherence | `+2` | `Notification.permission === "default"` while `permissions.query({name:"notifications"}).state !== "prompt"`, OR Gecko/Firefox with `plugins.length === 0 && pdfViewerEnabled === false` | `playwright-stealth`, `puppeteer-stealth`, Playwright Firefox |

---

## Stage 2: Biomechanical Interaction Kinematics

When a visitor clicks a protected action button before calling a protected API, VeilBreak evaluates pointer biomechanics:

- **`UNTRUSTED_SYNTHETIC_CLICK` (`+6`)**: `event.isTrusted === false` (catches Nodriver `.click()`, SeleniumBase UC `.uc_click()`, and synthetic DOM dispatch).
- **`TELEPORT_CLICK_PHYSICS` (`+4`)**: `event.isTrusted === true && event.detail >= 1` with `pointerMoves <= 3`, `dwellMs < 12 ms` (`pointerdown` → `pointerup`), and exact geometric center hit (`< 0.75 px`). In live testing, automated CDP/Juggler clicks average `0.1–5.0 ms` dwell with `1–2` pointer moves, whereas real human mouse clicks average `40–180 ms` dwell with `10–60+` pointer moves.
- **Accessibility Exemption (`0` penalty)**: Trusted keyboard activation (`Enter` / `Space` on a focused control emits `isTrusted === true` and `detail === 0`) is explicitly exempted so screen-reader and keyboard-only users experience zero friction.

---

## Cryptographic Server Attestation (`VB_ATTEST_V2`)

Every protected API request carries a one-time server ticket (`X-VB-Ticket`), client nonce (`X-VB-Nonce`), and SHA-256 attestation digest (`X-VB-Attest`):

```text
SHA-256("VB_ATTEST_V2|" + ticket + "|" + nonce + "|" + score + "|" + flags + "|" + platform)
```

Server middleware additionally enforces:
- One-time ticket consumption (`TICKET_REPLAYED_OR_INVALID`)
- Headless/automation User-Agent & `Sec-CH-UA` denial (`AUTOMATION_UA_DENIED`)
- `User-Agent` vs `Sec-CH-UA-Platform` vs `navigator.platform` cross-checks (`OS_HEADER_CONTRADICTION`, `OS_PLATFORM_CONTRADICTION`)
- Chrome 115+ legacy GREASE brand lie (`SEC_CH_UA_GREASE_LIE`)

---

## Modes & Privacy Browser Compatibility

| Mode | Threshold | Behavior | Recommended For |
| :--- | :-: | :--- | :--- |
| `strict` *(default)* | `>= 2` | Blocks on any single triggered invariant, missing/replayed ticket, or automation UA | High-value APIs, pricing/data endpoints, anti-scraping protection |
| `balanced` | `>= 4` | Requires multiple corroborating physics failures or a high-confidence automation/cross-realm invariant; allows Canvas-only privacy browsers (e.g., Brave/LibreWolf farbling) | Consumer web apps prioritizing privacy-browser compatibility |
| `monitor` | `∞` | Never blocks; attaches `X-VeilBreak-Score` and emits `onDetect` telemetry callbacks | Gradual rollout, traffic auditing, tuning |
| `off` | `∞` | Completely disabled | Local development |

---

## Honest Threat Model & Irreducible Boundaries

- **What VeilBreak blocks at Stage 1 (passive load, `< 20 ms`)**: `curl`/HTTP scrapers, standard Playwright (Chromium & Firefox, headless & headed), `playwright-stealth`, `puppeteer-extra-plugin-stealth`, CloakBrowser (headless & headed), Camoufox (headless & noise/cross-OS profiles), Patchright (headless & headed), Rebrowser-Playwright (headless & headed), and SeleniumBase UC Mode.
- **What requires Stage 2 (interaction kinematics)**: A genuine, unmodified, headed Chrome or Firefox binary driven on its native OS without viewport emulation and without canvas/WebGL noise (such as **Nodriver (Headed)** or **Camoufox (Headed)** when rolling a matching-OS zero-noise profile) can look indistinguishable from a real desktop browser on pure passive load, and is caught when interacting via Stage-2 kinematics.
- **Irreducible client-side boundary**: A human physically operating a real browser — or a custom, real-GPU, human-speed OS-level input robot controlling an unmodified desktop browser with no CDP/WebDriver instrumentation — sits at the irreducible boundary of browser-side detection. Pair VeilBreak with rate limiting, authentication, and server-side business logic for defense in depth.
