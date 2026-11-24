"use strict";

/**
 * Generates the zero-dependency browser SDK (`/ __cloakgate/gate.js`) including:
 *   1. All 6 empirically verified hardware/physics invariants (Canvas2D, WebGL, Audio, DOMRect, Fonts, D3D11)
 *   2. Optional CDP `Runtime.enable` & `navigator.webdriver` detection
 *   3. `<cloak-gate mode="strict">...</cloak-gate>` Shadow DOM Web Component
 *   4. Automatic `fetch()` attestation injection (`X-CG-Ticket`, `X-CG-Nonce`, `X-CG-Attest`)
 */
function buildBrowserGateScript({
  basePath = "/__cloakgate",
  defaultMode = "strict",
  protectedPaths = ["/api"],
  autoBlockPage = false,
} = {}) {
  return `(() => {
  "use strict";
  if (typeof window === "undefined" || window.__CLOAKGATE_LOADED__) return;
  window.__CLOAKGATE_LOADED__ = true;

  const BASE = ${JSON.stringify(basePath)};
  const scriptEl = document.currentScript;
  const DEFAULT_MODE = (scriptEl && scriptEl.getAttribute("data-mode")) || ${JSON.stringify(defaultMode)};
  const attrBlock = scriptEl && scriptEl.getAttribute("data-block-page");
  const AUTO_BLOCK = attrBlock === "false" ? false : (attrBlock === "true" || ${JSON.stringify(Boolean(autoBlockPage))});
  const PROTECTED = ${JSON.stringify(protectedPaths)};
  const origFetch = window.fetch.bind(window);

  function toHex(buf) {
    const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < u.length; i++) out += u[i].toString(16).padStart(2, "0");
    return out;
  }

  async function sha256Hex(str) {
    const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return toHex(d);
  }

  function detectCdpRuntimeEnable() {
    let tripped = false;
    try {
      const e = new Error();
      Object.defineProperty(e, "stack", {
        get() { tripped = true; return ""; }
      });
      console.debug(e);
    } catch (_) {}
    return tripped;
  }

  async function runHardwareProbes({ antiCdp = true } = {}) {
    const details = {
      webdriver: Boolean(navigator.webdriver),
      cdpRuntimeEnable: antiCdp ? detectCdpRuntimeEnable() : false,
      canvas2dUniqueColors: 1,
      webglClearUniqueColors: 1,
      silentAudioNonZeroSamples: 0,
      domRectSubpixelDrift: false,
      domRectDelta: 0,
      osFontLie: false,
      d3d11ExtMismatch: false,
      platform: String(navigator.platform || "").slice(0, 48),
    };
    let score = 0;
    let flags = 0;
    const reasons = [];

    if (antiCdp && details.webdriver) { score += 4; flags |= 64; reasons.push("WEBDRIVER_FLAG"); }
    if (antiCdp && details.cdpRuntimeEnable) { score += 4; flags |= 128; reasons.push("CDP_RUNTIME_ENABLE"); }

    // 1. 2D Canvas solid #808080 flat-fill noise (+2)
    try {
      const c = document.createElement("canvas");
      c.width = 32; c.height = 32;
      const ctx = c.getContext("2d");
      if (ctx) {
        ctx.fillStyle = "#808080";
        ctx.fillRect(0, 0, 32, 32);
        const data = ctx.getImageData(0, 0, 32, 32).data;
        const uniq = new Set();
        for (let i = 0; i < data.length; i += 4) uniq.add((data[i] << 16) | (data[i + 1] << 8) | data[i + 2]);
        details.canvas2dUniqueColors = uniq.size;
        if (uniq.size > 1) { score += 2; flags |= 1; reasons.push("CANVAS2D_SYNTHETIC_NOISE"); }
      }
    } catch (_) {}

    // 2. WebGL gl.clear(0.5,0.5,0.5,1) readPixels noise (+2) & D3D11 extension parity (+1)
    try {
      const c = document.createElement("canvas");
      c.width = 32; c.height = 32;
      const gl = c.getContext("webgl2") || c.getContext("webgl");
      if (gl) {
        gl.clearColor(0.5, 0.5, 0.5, 1.0);
        gl.clear(gl.COLOR_BUFFER_BIT);
        const px = new Uint8Array(32 * 32 * 4);
        gl.readPixels(0, 0, 32, 32, gl.RGBA, gl.UNSIGNED_BYTE, px);
        const uniq = new Set();
        for (let i = 0; i < px.length; i += 4) uniq.add((px[i] << 16) | (px[i + 1] << 8) | px[i + 2]);
        details.webglClearUniqueColors = uniq.size;
        if (uniq.size > 1) { score += 2; flags |= 2; reasons.push("WEBGL_CLEAR_SYNTHETIC_NOISE"); }

        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        const renderer = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "") : "";
        const exts = gl.getSupportedExtensions() || [];
        if ((renderer.includes("Direct3D11") || renderer.includes("D3D11")) && (renderer.includes("NVIDIA") || renderer.includes("RTX")) && !exts.includes("KHR_parallel_shader_compile") && exts.length < 30) {
          details.d3d11ExtMismatch = true;
          score += 1; flags |= 32; reasons.push("D3D11_EXTENSION_PARITY_LIE");
        }
        const lose = gl.getExtension("WEBGL_lose_context");
        if (lose) lose.loseContext();
      }
    } catch (_) {}

    // 3. Silent OfflineAudioContext (all-zero buffer must remain 0.0) (+2)
    try {
      const OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (OAC) {
        const ac = new OAC(1, 512, 44100);
        const buf = ac.createBuffer(1, 512, 44100);
        const src = ac.createBufferSource();
        src.buffer = buf;
        src.connect(ac.destination);
        src.start(0);
        const rendered = await ac.startRendering();
        const ch = rendered.getChannelData(0);
        let nonZero = 0;
        for (let i = 0; i < ch.length; i++) if (Math.abs(ch[i]) > 1e-12) nonZero++;
        details.silentAudioNonZeroSamples = nonZero;
        if (nonZero > 0) { score += 2; flags |= 4; reasons.push("SILENT_AUDIO_SYNTHETIC_NOISE"); }
      }
    } catch (_) {}

    const root = document.body || document.documentElement;

    // 4. Integer-DPR DOMRect sub-pixel poisoning (+2)
    try {
      const dpr = window.devicePixelRatio || 1;
      if (Math.abs(dpr - Math.round(dpr)) < 1e-6 && root) {
        const dv = document.createElement("div");
        dv.style.cssText = "position:fixed;left:10px;top:20px;width:100px;height:50px;margin:0;padding:0;border:0;visibility:hidden";
        root.appendChild(dv);
        const r = dv.getBoundingClientRect();
        dv.remove();
        const delta = Math.max(Math.abs(r.left - 10), Math.abs(r.top - 20), Math.abs(r.width - 100), Math.abs(r.height - 50));
        details.domRectDelta = Number(delta.toFixed(6));
        if (delta > 1e-3) { details.domRectSubpixelDrift = true; score += 2; flags |= 8; reasons.push("DOMRECT_SUBPIXEL_POISONING"); }
      }
    } catch (_) {}

    // 5. OS platform vs. mandatory core system fonts (+2)
    try {
      const pl = String(navigator.platform || "");
      const up = String((navigator.userAgentData && navigator.userAgentData.platform) || "");
      const claimsWin = pl.startsWith("Win") || up === "Windows";
      const claimsMac = pl === "MacIntel" || up === "macOS";
      if (root && (claimsWin || claimsMac)) {
        const sp = document.createElement("span");
        sp.textContent = "mmmmmmmmmmlliWWWW1234567890";
        sp.style.cssText = "position:fixed;left:-9999px;top:0;font-size:72px;white-space:nowrap;visibility:hidden";
        root.appendChild(sp);
        const mw = (f) => { sp.style.fontFamily = f; return sp.offsetWidth; };
        const base = mw("monospace");
        const candidates = claimsWin
          ? ['"Segoe UI",monospace', '"Tahoma",monospace', '"Consolas",monospace', '"Calibri",monospace']
          : ['"Helvetica Neue",monospace', '"Geneva",monospace', '"Menlo",monospace'];
        let matched = 0;
        for (const f of candidates) if (mw(f) !== base) matched++;
        sp.remove();
        if (matched === 0) { details.osFontLie = true; score += 2; flags |= 16; reasons.push("OS_CORE_FONT_LIE"); }
      }
    } catch (_) {}

    return { score, flags, platform: details.platform, reasons, details };
  }

  function thresholdFor(mode) {
    const m = String(mode || "strict").toLowerCase();
    if (m === "strict") return 2;
    if (m === "balanced") return 4;
    return Infinity;
  }

  let cachedProbe = null;
  async function verify({ mode = DEFAULT_MODE, ticket = "", nonce = "", antiCdp = true } = {}) {
    if (!cachedProbe) cachedProbe = await runHardwareProbes({ antiCdp });
    const m = String(mode || "strict").toLowerCase();
    const threshold = thresholdFor(m);
    const blocked = m !== "off" && m !== "monitor" && cachedProbe.score >= threshold;
    const d = await sha256Hex("CG_ATTEST_V1|" + ticket + "|" + nonce + "|" + cachedProbe.score + "|" + cachedProbe.flags + "|" + cachedProbe.platform);
    return {
      ok: !blocked,
      blocked,
      mode: m,
      threshold,
      score: cachedProbe.score,
      flags: cachedProbe.flags,
      reasons: cachedProbe.reasons,
      details: cachedProbe.details,
      attest: { s: cachedProbe.score, f: cachedProbe.flags, p: cachedProbe.platform, d },
    };
  }

  // Drop-in <cloak-gate mode="strict">...</cloak-gate> Shadow DOM Web Component
  if (typeof customElements !== "undefined" && !customElements.get("cloak-gate")) {
    class CloakGateElement extends HTMLElement {
      async connectedCallback() {
        if (this._cgMounted) return;
        this._cgMounted = true;
        const mode = this.getAttribute("mode") || DEFAULT_MODE;
        const denyMsg = this.getAttribute("deny-message") || "Access denied: anti-detect / stealth browser (CLOAK_BROWSER_DENIED).";
        const root = this.attachShadow({ mode: "closed" });
        root.innerHTML = '<div id="cg-state" style="padding:12px;font-family:system-ui,sans-serif;color:#94a3b8;">Verifying browser integrity...</div>';
        const res = await verify({ mode });
        this.dataset.cloakgateScore = String(res.score);
        this.dataset.cloakgateStatus = res.blocked ? "blocked" : "allowed";
        if (res.blocked) {
          // Wipe protected light DOM children so scrapers cannot read them!
          this.innerHTML = "";
          root.innerHTML = '<div id="cg-denied" style="padding:16px;border:1px solid #ef4444;border-radius:8px;background:#1f1215;color:#fecaca;font-family:system-ui,sans-serif;"><strong>CLOAK_BROWSER_DENIED</strong> (score ' + res.score + '/' + res.threshold + '): ' + denyMsg + '</div>';
          this.dispatchEvent(new CustomEvent("cloakgate-denied", { detail: res, bubbles: true }));
        } else {
          root.innerHTML = "<slot></slot>";
          this.dispatchEvent(new CustomEvent("cloakgate-allowed", { detail: res, bubbles: true }));
        }
      }
    }
    customElements.define("cloak-gate", CloakGateElement);
  }

  // Auto-attach CloakGate attestation headers on protected fetch() paths
  function isProtectedPath(pathname) {
    for (let i = 0; i < PROTECTED.length; i++) {
      const p = PROTECTED[i];
      if (p === "*" || p === "/" || pathname === p || pathname.startsWith(p.endsWith("/") ? p : p + "/")) return true;
    }
    return false;
  }

  window.fetch = async function cloakGateFetch(input, init = {}) {
    const reqUrl = new URL(typeof input === "string" ? input : input.url, window.location.href);
    if (reqUrl.origin !== window.location.origin || reqUrl.pathname.startsWith(BASE) || !isProtectedPath(reqUrl.pathname)) {
      return origFetch(input, init);
    }
    const tkResp = await origFetch(BASE + "/ticket", { method: "GET", credentials: "same-origin" });
    const tkData = tkResp.ok ? await tkResp.json() : { ticket: "" };
    const nonce = toHex(crypto.getRandomValues(new Uint8Array(8)));
    const res = await verify({ mode: DEFAULT_MODE, ticket: tkData.ticket || "", nonce });
    if (res.blocked) {
      throw new Error("CLOAK_BROWSER_DENIED");
    }
    const headers = new Headers(typeof input !== "string" ? input.headers : undefined);
    if (init.headers) new Headers(init.headers).forEach((v, k) => headers.set(k, v));
    headers.set("X-CG-Ticket", tkData.ticket || "");
    headers.set("X-CG-Nonce", nonce);
    headers.set("X-CG-Attest", JSON.stringify(res.attest));
    return origFetch(reqUrl.toString(), { ...init, headers });
  };

  if (AUTO_BLOCK && DEFAULT_MODE !== "off" && DEFAULT_MODE !== "monitor") {
    const runPageBlock = async () => {
      const res = await verify({ mode: DEFAULT_MODE });
      window.__CLOAKGATE_RESULT__ = res;
      if (res.blocked) {
        document.documentElement.innerHTML =
          '<head><meta charset="utf-8"><title>Access Denied</title></head>' +
          '<body style="background:#0b0f19;color:#f8fafc;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">' +
          '<div id="cloakgate-blocked" style="max-width:520px;padding:28px;border:1px solid #ef4444;border-radius:12px;background:#111827;">' +
          '<h2 style="margin-top:0;color:#fca5a5;">Access Denied: CLOAK_BROWSER_DENIED</h2>' +
          '<p>CloakGate detected anti-detect / fingerprint-noise browser anomalies (score <b>' + res.score + '</b> / threshold ' + res.threshold + ').</p>' +
          '<pre style="background:#090d16;padding:12px;border-radius:8px;overflow:auto;">' + res.reasons.join("\\n") + '</pre>' +
          '</div></body>';
      }
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runPageBlock);
    else runPageBlock();
  }

  window.CloakGate = { verify, version: "1.0.0", mode: DEFAULT_MODE };
})();
`;
}

function buildPlaygroundHtml({ basePath = "/__cloakgate", mode = "strict" } = {}) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CloakGate — Live Anti-Detect Browser Diagnostics</title>
  <script src="${basePath}/gate.js" data-mode="${mode}" data-block-page="false"></script>
  <style>
    body { background:#0b0f19; color:#e2e8f0; font-family:system-ui,sans-serif; padding:28px; max-width:860px; margin:0 auto; }
    .card { background:#111827; border:1px solid #1e293b; border-radius:12px; padding:20px; margin-bottom:18px; }
    table { width:100%; border-collapse:collapse; margin-top:12px; }
    th, td { text-align:left; padding:10px; border-bottom:1px solid #1e293b; font-size:14px; }
    .pass { color:#4ade80; font-weight:600; }
    .fail { color:#f87171; font-weight:700; }
  </style>
</head>
<body>
  <h1>CloakGate Live Hardware-Invariant Diagnostic (${mode})</h1>
  <div class="card">
    <div id="verdict">Running 6 hardware/physics probes...</div>
    <table>
      <thead><tr><th>Invariant</th><th>Observed Value</th><th>Status</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <div class="card">
    <h3>Protected Web Component (<code>&lt;cloak-gate mode="${mode}"&gt;</code>)</h3>
    <cloak-gate id="demo-gate" mode="${mode}">
      <div id="protected-wc-secret" style="padding:12px;border:1px solid #22c55e;border-radius:8px;">
        Protected Component Rendered Cleanly: <strong>REAL_BROWSER_VERIFIED_OK</strong>
      </div>
    </cloak-gate>
  </div>
  <script>
    window.addEventListener("load", async () => {
      const r = await window.CloakGate.verify({ mode: ${JSON.stringify(mode)} });
      window.__CG_PLAYGROUND__ = r;
      document.getElementById("verdict").innerHTML =
        "<strong>Verdict:</strong> " + (r.blocked ? '<span class="fail">DENIED (CLOAK_BROWSER_DENIED)</span>' : '<span class="pass">ALLOWED (Clean Browser)</span>') +
        " &nbsp;|&nbsp; <strong>Score:</strong> " + r.score + " / 11 (threshold " + r.threshold + ")";
      const d = r.details;
      const items = [
        ["1. 2D Canvas #808080 flat fill", d.canvas2dUniqueColors + " unique RGB(s)", d.canvas2dUniqueColors > 1],
        ["2. WebGL gl.clear(0.5) readPixels", d.webglClearUniqueColors + " unique RGB(s)", d.webglClearUniqueColors > 1],
        ["3. Silent OfflineAudioContext (512 samples)", d.silentAudioNonZeroSamples + " non-zero sample(s)", d.silentAudioNonZeroSamples > 0],
        ["4. Integer-DPR DOMRect (10,20,100,50)", "delta=" + d.domRectDelta + "px", d.domRectSubpixelDrift],
        ["5. OS Platform vs Core Fonts (" + d.platform + ")", d.osFontLie ? "0 core fonts matched" : "Consistent", d.osFontLie],
        ["6. D3D11 NVIDIA/RTX Extension Parity", d.d3d11ExtMismatch ? "Missing KHR_parallel_shader_compile" : "Consistent", d.d3d11ExtMismatch],
      ];
      document.getElementById("rows").innerHTML = items.map(([k, v, bad]) =>
        "<tr><td>" + k + "</td><td><code>" + v + "</code></td><td class='" + (bad ? "fail" : "pass") + "'>" + (bad ? "ANOMALY" : "CLEAN") + "</td></tr>"
      ).join("");
    });
  </script>
</body>
</html>`;
}

module.exports = { buildBrowserGateScript, buildPlaygroundHtml };
