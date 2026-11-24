# VeilBreak — 14 Invariants, Click Kinematics & Threat Model

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md)

VeilBreak checks **14 cross-engine graphics, audio, cross-realm, prototype, geometry, and engine-coherence invariants** (Stage 1) plus a **biomechanical interaction kinematics layer** (Stage 2), bound to single-use server tickets (`VB_ATTEST_V2`).

---

## Stage 1: The 14 Passive Invariants

| # | Code | Weight | Exact Check | Primary Targets |
| :-: | :--- | :-: | :--- | :--- |
| 1 | `WEBDRIVER_FLAG` | `+4` | `navigator.webdriver` or untouched `iframe.contentWindow.navigator.webdriver` is `true` | Playwright, Selenium, Puppeteer |
| 2 | `AUTOMATION_GLOBAL_ARTIFACT` | `+4` | `window`/`document` owns `$cdc_*`, `cdc_*`, `__playwright*`, `__pw_manual`, `__pwInitScripts`, `__puppeteer*`, `__webdriver*`, `domAutomation*` | SeleniumBase UC, Chromedriver, Playwright |
| 3 | `CDP_RUNTIME_ENABLE` | `+4` | `console.debug(err)` invokes custom `Error.stack` getter side-channel *(also fires when DevTools is open)* | Active CDP `Runtime.enable` scrapers |
| 4 | `WEBDRIVER_GETTER_SPOOFED` | `+4` | Own-property `navigator.webdriver` override or non-native `Navigator.prototype.webdriver` getter | `playwright-stealth`, custom JS spoofers |
| 5 | `NATIVE_FUNCTION_TAMPERED` | `+4` | Fresh `iframe.contentWindow.Function.prototype.toString` mismatches main-thread `toString` or `[native code]` on core APIs (`toDataURL`, `getImageData`, `getParameter` WebGL1/2, `platform`, `userAgent`, `permissions.query`) | `playwright-stealth`, JS stealth wrappers |
| 6 | `WORKER_REALM_CONTRADICTION` | `+4` | `Web Worker` (`self.navigator`) reports a different `platform`, `hardwareConcurrency`, `userAgent`, or `webdriver` state than the main thread | `puppeteer-extra-plugin-stealth` |
| 7 | `CANVAS2D_SYNTHETIC_NOISE` / `NON_DETERMINISTIC` | `+2` / `+4` | Flat `#808080` Canvas2D or `OffscreenCanvas` produces `> 1` unique RGB color (`+2`), or two identical renders differ (`+4`) | CloakBrowser, Camoufox, noise forks |
| 8 | `WEBGL_CLEAR_SYNTHETIC_NOISE` | `+2` | Dither-disabled `gl.clearColor(128/255, ...)` + `gl.readPixels()` yields `> 1` unique color | CloakBrowser, WebGL-noise forks |
| 9 | `WEBGL_HARDWARE_COHERENCE_LIE` | `+2` | Discrete/D3D11 GPU string with impossibly low extension count (`<= 12` WebGL2 / `<= 19` WebGL1), GTX 6/7/9xx claiming `MAX_TEXTURE_SIZE >= 32768`, macOS renderer on claimed Windows, D3D11 on claimed Linux, or Chromium D3D11 RTX missing `KHR_parallel_shader_compile` (`< 30` exts) | Camoufox, CloakBrowser, `puppeteer-stealth` |
| 10 | `SILENT_AUDIO_SYNTHETIC_NOISE` | `+2` | All-zero `OfflineAudioContext` buffer renders non-zero samples (`|x| > 1e-12`, 1.5s timeout-guarded) | CloakBrowser, audio-noise forks |
| 11 | `DOMRECT_SUBPIXEL_POISONING` | `+2` | CSP-safe CSSOM fixed `10×20` `100×50` box at integer DPR drifts within `(1e-3, 1.5) px` | CloakBrowser, DOMRect-poisoning forks |
| 12 | `OS_CORE_FONT_LIE` | `+2` | Claims desktop Windows or macOS (non-touch) with `0` OS core fonts while `sans-serif !== monospace` (`base > 0`) | CloakBrowser, `puppeteer-stealth`, cross-OS spoofers |
| 13 | `VIEWPORT_GEOMETRY_IMPOSSIBILITY` | `+2` | Integer-DPR non-fullscreen desktop (excluding touch tablets) where `outer > screen + 16` or zero chrome on a sub-screen window (F11/PWA/tiling-WM safe) | Patchright, Rebrowser, Playwright, SeleniumBase UC |
| 14 | `ENGINE_COHERENCE_LIE` | `+2` | Genuine `Notification.permission` contradiction (`default`/`denied` while `permissions.query` reports `granted`, 900ms timeout-guarded) | Broken permission-spoofing scripts |

---

## Stage 2: Biomechanical Interaction Kinematics

When a user interacts with a visible control before calling a protected API, VeilBreak evaluates pointer kinematics (resetting per click):

- **`UNTRUSTED_SYNTHETIC_CLICK` (`+6`)**: `event.isTrusted === false` (catches Nodriver `.click()`, SeleniumBase UC `.uc_click()`, and synthetic DOM dispatch).
- **`TELEPORT_CLICK_PHYSICS` (`+4`)**: `event.isTrusted === true && event.detail >= 1` (non-touch/non-pen) with `pointerMoves <= 3`, `pointerdown`→`click` `dwellMs < 12 ms`, and exact geometric center hit (`< 0.75 px`).
- **`ZERO_TRAJECTORY_INSTANT_CLICK` (`+4`)**: `event.isTrusted === true && event.detail >= 1` (non-touch/non-pen) with `pointerMoves === 0` and `0 < dwellMs < 8 ms` (excludes `dwellMs === 0` coarsened privacy timers).
- **Accessibility & Mobile Exemptions (`0` penalty)**: Trusted keyboard activation (`Enter`/`Space` → `isTrusted === true && detail === 0`) and `touch` / `pen` pointer events are explicitly exempted.

---

## One-Time Ticket Telemetry Envelope (`VB_ATTEST_V2`)

Every protected API request carries a single-use server ticket (`X-VB-Ticket`), client nonce (`X-VB-Nonce`), and SHA-256 telemetry digest (`X-VB-Attest`):

```text
SHA-256("VB_ATTEST_V2|" + ticket + "|" + nonce + "|" + score + "|" + flags + "|" + platform)
```

Server verification (identical in Node.js `src/probes.js` and Python `python/veilbreak.py` + `VeilBreakTicketStore`) enforces:
- One-time ticket consumption in both `strict` and `balanced` modes (`TICKET_REPLAYED_OR_INVALID`, `+6`)
- Path normalization (`//api`, `/%61pi`, `/API`, `/./api`)
- Strict schema validation (`v === 2`, integer bounds, no `|` delimiter injection, flag-vs-score consistency, server-side flag bitmask decoding)
- Headless/automation UA & `Sec-CH-UA` denial (`AUTOMATION_UA_DENIED`, `+6`, enforced before ticket issuance too)
- `User-Agent` vs `Sec-CH-UA-Platform` vs `navigator.platform` cross-checks and Chrome 115+ legacy GREASE check

---

## Honest Threat Model & Irreducible Boundaries

- **Unkeyed client digest boundary:** Because `VB_ATTEST_V2` uses a public SHA-256 over client-reported fields, a motivated attacker who inspects `gate.js` can fetch a ticket with a desktop `User-Agent` and compute a clean `s=0, f=0` digest in a custom script without running a real browser. VeilBreak stops automated/stealth browsers operating through normal web sessions and raises the bar against off-the-shelf scrapers; always pair with authentication, rate limiting, and server-side policy.
- **Stage-1 vs. Stage-2 coverage:** Unmodified headed Chrome/Firefox driven without viewport overrides or synthetic noise (e.g., Nodriver Headed, or Camoufox Headed on a matching-OS zero-noise profile) can pass Stage 1 and are caught at Stage 2 when clicking programmatically. A bot simulating realistic multi-step OS pointer motion or keyboard focus+Enter sits at the irreducible client-side boundary.
- **Privacy browser & DevTools trade-offs:** `balanced` (`>= 4`) tolerates single-signal Canvas-only farbling (`+2`), while multi-signal privacy profiles (Brave Shields Strict, LibreWolf / Firefox RFP, Tor Browser) or open DevTools (`CDP_RUNTIME_ENABLE`, `+4`) can exceed `4`. Test in `monitor` mode before switching to blocking on consumer traffic.
