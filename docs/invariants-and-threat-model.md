# Hardware Invariants & Honest Threat Model

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md)

---

## 1. Empirical Breakdown: Unmodified Chrome 158 vs. CloakBrowser 146

| # | Hardware / Physics Invariant | Real Desktop Chrome 158 | CloakBrowser 146 (Measured) | Weight | Bit Flag |
| :---: | :--- | :--- | :--- | :---: | :---: |
| 1 | 2D Canvas solid `#808080` `fillRect` (`32×32`) | `1` unique RGB (`128,128,128`) | `5` unique RGBs (pixel noise) | `+2` | `1` |
| 2 | WebGL `gl.clear(0.5, 0.5, 0.5, 1)` `readPixels` | `1` unique RGB (`128,128,128`) | `5` unique RGBs (readback noise) | `+2` | `2` |
| 3 | Silent `OfflineAudioContext` (`512` zero samples) | `0 / 512` non-zero samples | `512 / 512` non-zero samples | `+2` | `4` |
| 4 | Integer-DPR `DOMRect` (`10, 20, 100, 50`) | `delta = 0.000000px` | `delta = 0.046875px` (`[9.953125, 19.984375]`) | `+2` | `8` |
| 5 | OS platform (`Win32`/`MacIntel`) vs. core OS fonts | Matches native OS fonts | Spoofs `Win32` on Linux with `0/4` Windows fonts | `+2` | `16` |
| 6 | D3D11 NVIDIA/RTX renderer extension parity | `KHR_parallel_shader_compile` present (`30+` exts) | Missing `KHR_parallel_shader_compile` (`< 30` exts) | `+1` | `32` |
| | **Total Anomaly Score** | **`0 / 11`** | **`11 / 11`** (`8 / 11` with `--fingerprint-platform=linux`) | `strict >= 2`, `balanced >= 4` | |

---

## 2. Server-Side Cryptographic Attestation (`CG_ATTEST_V1`)

Client-only JS checks can be skipped if an attacker calls `/api/*` directly. When paired with CloakGate's server middleware (`createCloakGateMiddleware` or `python/cloakgate.py`):
1. Client fetches a single-use server ticket (`GET /__cloakgate/ticket`).
2. Client computes `d = SHA-256("CG_ATTEST_V1|" + ticket + "|" + nonce + "|" + score + "|" + flags + "|" + platform)` and sends `X-CG-Ticket`, `X-CG-Nonce`, and `X-CG-Attest`.
3. Server burns the single-use ticket, verifies `d` in constant time, verifies `score < threshold`, rejects `HeadlessChrome`/`Playwright`/`Puppeteer` UAs (`strict`), and rejects HTTP OS contradictions (`User-Agent` vs `Sec-CH-UA-Platform` vs `attest.p`).

---

## 3. Honest Limitations (No Hype)

- **Privacy-Hardened Browsers**: Browsers with deliberate Canvas-only farbling (e.g. Brave Aggressive Shields, LibreWolf RFP) can score `+2`. Use **`mode: "balanced"`** (`threshold = 4`) when those users must be permitted — CloakBrowser still scores `8–11` and stays blocked.
- **Custom Zero-Noise C++ Browser Builds**: If a sophisticated adversary compiles Chromium from source with *zero* synthetic Canvas/WebGL/Audio/DOMRect noise, runs on real matching OS hardware with real OS fonts, and drives it via human-like OS input without CDP `Runtime.enable`, hardware physics invariants naturally read `0/11`. Never rely on browser checks alone to protect secrets that belong on the server; pair CloakGate with server-side auth, rate limits, and **[Vibe-Slayer](https://github.com/HUSMUS9999/vibe-slayer)** / **[ProxySnare](https://github.com/HUSMUS9999/proxysnare)**.
