"use strict";

/**
 * Generates the zero-dependency VeilBreak browser SDK (`/__veilbreak/gate.js`):
 *   1. 14 empirically verified physics, graphics, audio, cross-realm, prototype,
 *      geometry, and engine-coherence invariants across Chromium & Gecko engines.
 *   2. Stage-2 Biomechanical Interaction Kinematics Guard (catches untrusted JS clicks
 *      and programmatic CDP/Juggler teleport clicks while exempting keyboard accessibility).
 *   3. `<veil-break mode="strict">...</veil-break>` closed Shadow DOM Web Component.
 *   4. Automatic `fetch()` cryptographic attestation injection (`X-VB-Ticket`, `X-VB-Nonce`, `X-VB-Attest`).
 */
function buildBrowserGateScript({
  basePath = "/__veilbreak",
  defaultMode = "strict",
  protectedPaths = ["/api"],
  autoBlockPage = false,
} = {}) {
  return `(() => {
  "use strict";
  if (typeof window === "undefined" || window.__VEILBREAK_LOADED__) return;
  window.__VEILBREAK_LOADED__ = true;

  const BASE = ${JSON.stringify(basePath)};
  const scriptEl = document.currentScript;
  const DEFAULT_MODE = (scriptEl && scriptEl.getAttribute("data-mode")) || ${JSON.stringify(defaultMode)};
  const attrBlock = scriptEl && scriptEl.getAttribute("data-block-page");
  const AUTO_BLOCK = attrBlock === "false" ? false : (attrBlock === "true" || ${JSON.stringify(Boolean(autoBlockPage))});
  const PROTECTED = ${JSON.stringify(protectedPaths)};
  const origFetch = window.fetch.bind(window);

  // Stage-2 global pointer kinematics observer (passive, near-zero overhead)
  const kin = { moves: 0, zeroMoves: 0, downTs: 0, lastClick: null };
  window.addEventListener("pointermove", (e) => {
    kin.moves++;
    if (e.movementX === 0 && e.movementY === 0) kin.zeroMoves++;
  }, true);
  window.addEventListener("pointerdown", () => {
    kin.downTs = performance.now();
  }, true);

  function captureInteraction(e, targetEl) {
    const upTs = performance.now();
    const el = targetEl || (e && e.currentTarget) || (e && e.target);
    let hitExactCenter = false;
    try {
      if (el && typeof el.getBoundingClientRect === "function" && e && typeof e.clientX === "number") {
        const r = el.getBoundingClientRect();
        if (r.width > 4 && r.height > 4) {
          hitExactCenter =
            Math.abs(e.clientX - (r.left + r.width / 2)) < 0.75 &&
            Math.abs(e.clientY - (r.top + r.height / 2)) < 0.75;
        }
      }
    } catch (_) {}
    const info = {
      isTrusted: Boolean(e && e.isTrusted),
      detail: Number((e && e.detail) ?? 0),
      pointerMoves: kin.moves,
      zeroMoveCount: kin.zeroMoves,
      dwellMs: kin.downTs > 0 ? Number((upTs - kin.downTs).toFixed(2)) : -1,
      hitExactCenter,
    };
    kin.lastClick = info;
    return info;
  }

  function evaluateInteractionLocal(info, mode) {
    const m = String(mode || DEFAULT_MODE).toLowerCase();
    const threshold = thresholdFor(m);
    if (m === "off" || !info) return { ok: true, blocked: false, score: 0, threshold, mode: m, reasons: [] };
    let score = 0;
    const reasons = [];
    if (info.isTrusted === false) {
      score += 6;
      reasons.push("UNTRUSTED_SYNTHETIC_CLICK");
    } else if (info.isTrusted === true && info.detail >= 1) {
      if (info.pointerMoves <= 3 && info.dwellMs >= 0 && info.dwellMs < 12 && info.hitExactCenter) {
        score += 4;
        reasons.push("TELEPORT_CLICK_PHYSICS");
      } else if (info.pointerMoves === 0 && info.dwellMs >= 0 && info.dwellMs < 8) {
        score += 4;
        reasons.push("ZERO_TRAJECTORY_INSTANT_CLICK");
      }
    }
    const blocked = m !== "monitor" && score >= threshold;
    return { ok: !blocked, blocked, score, threshold, mode: m, reasons, details: info };
  }

  window.addEventListener("click", (e) => {
    captureInteraction(e, e.target);
  }, true);

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

  function probeWebWorker(timeoutMs = 900) {
    return new Promise((resolve) => {
      if (typeof Worker === "undefined" || typeof Blob === "undefined") {
        resolve(null);
        return;
      }
      try {
        const src = [
          "self.onmessage=()=>{",
          "const o={ua:navigator.userAgent,pl:navigator.platform,hw:navigator.hardwareConcurrency,wd:Boolean(navigator.webdriver),oc:1,wr:''};",
          "try{if(typeof OffscreenCanvas!=='undefined'){",
          "const c=new OffscreenCanvas(32,32),x=c.getContext('2d');",
          "if(x){x.fillStyle='#808080';x.fillRect(0,0,32,32);const d=x.getImageData(0,0,32,32).data,u=new Set();for(let i=0;i<d.length;i+=4)u.add((d[i]<<16)|(d[i+1]<<8)|d[i+2]);o.oc=u.size;}",
          "const c2=new OffscreenCanvas(32,32),g=c2.getContext('webgl2')||c2.getContext('webgl');",
          "if(g){const db=g.getExtension('WEBGL_debug_renderer_info');if(db)o.wr=String(g.getParameter(db.UNMASKED_RENDERER_WEBGL)||'');}",
          "}}catch(_){}",
          "self.postMessage(o);};"
        ].join("");
        const url = URL.createObjectURL(new Blob([src], { type: "application/javascript" }));
        const w = new Worker(url);
        const done = (val) => {
          clearTimeout(tm);
          try { w.terminate(); } catch (_) {}
          try { URL.revokeObjectURL(url); } catch (_) {}
          resolve(val);
        };
        const tm = setTimeout(() => done(null), timeoutMs);
        w.onmessage = (ev) => done(ev.data || null);
        w.onerror = () => done(null);
        w.postMessage(1);
      } catch (_) {
        resolve(null);
      }
    });
  }

  async function runHardwareProbes({ antiCdp = true } = {}) {
    const workerPromise = probeWebWorker(900);
    const details = {
      webdriver: Boolean(navigator.webdriver),
      freshIframeWebdriver: false,
      automationGlobalArtifact: false,
      cdpRuntimeEnable: antiCdp ? detectCdpRuntimeEnable() : false,
      webdriverGetterSpoofed: false,
      nativeFunctionTampered: false,
      workerRealmContradiction: false,
      canvas2dUniqueColors: 1,
      canvas2dRepeatDiff: 0,
      offscreenCanvasUniqueColors: 1,
      webglClearUniqueColors: 1,
      webglHardwareLie: false,
      webglRenderer: "",
      silentAudioNonZeroSamples: 0,
      audioOscRepeatDiff: 0,
      domRectSubpixelDrift: false,
      domRectDelta: 0,
      osFontLie: false,
      viewportGeometryImpossibility: false,
      engineCoherenceLie: false,
      platform: String(navigator.platform || "").slice(0, 48),
    };

    let score = 0;
    let flags = 0;
    const reasons = [];

    // Fresh untouched iframe realm for cross-realm native & webdriver inspection
    let freshWin = null;
    let freshFrame = null;
    try {
      freshFrame = document.createElement("iframe");
      freshFrame.style.cssText = "position:fixed;left:-9999px;top:0;width:1px;height:1px;opacity:0;pointer-events:none;";
      (document.documentElement || document.body).appendChild(freshFrame);
      freshWin = freshFrame.contentWindow;
    } catch (_) {}

    try {
      if (freshWin && freshWin.navigator) {
        details.freshIframeWebdriver = Boolean(freshWin.navigator.webdriver);
      }
    } catch (_) {}

    // 1. WebDriver flag (main or fresh iframe) (+4)
    if (antiCdp && (details.webdriver || details.freshIframeWebdriver)) {
      score += 4; flags |= 64; reasons.push("WEBDRIVER_FLAG");
    }

    // 2. Global / Document automation artifacts (+4)
    try {
      const susRe = /^(\\$?cdc_|__playwright|__pw|__puppeteer|__webdriver|_selenium|_Selenium|__fxdriver|__driver_|domAutomation|callPhantom|_phantom|__nightmare|__lastWatir)/i;
      const winKeys = Object.getOwnPropertyNames(window);
      const docKeys = Object.getOwnPropertyNames(document);
      for (let i = 0; i < winKeys.length; i++) {
        if (susRe.test(winKeys[i])) { details.automationGlobalArtifact = true; break; }
      }
      if (!details.automationGlobalArtifact) {
        for (let i = 0; i < docKeys.length; i++) {
          if (susRe.test(docKeys[i])) { details.automationGlobalArtifact = true; break; }
        }
      }
      if (antiCdp && details.automationGlobalArtifact) {
        score += 4; flags |= 256; reasons.push("AUTOMATION_GLOBAL_ARTIFACT");
      }
    } catch (_) {}

    // 3. CDP Runtime.enable (+4)
    if (antiCdp && details.cdpRuntimeEnable) {
      score += 4; flags |= 128; reasons.push("CDP_RUNTIME_ENABLE");
    }

    // 4 & 5. Prototype / Getter Spoofing & Cross-Realm Native Integrity (+4 each)
    try {
      const freshToStr = (freshWin && freshWin.Function) ? freshWin.Function.prototype.toString : Function.prototype.toString;
      const wdOwn = Object.getOwnPropertyDescriptor(navigator, "webdriver");
      const wdProto = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
      if (wdOwn) {
        details.webdriverGetterSpoofed = true;
      } else if (wdProto && typeof wdProto.get === "function") {
        const s = freshToStr.call(wdProto.get);
        if (!/function\\s+(?:get\\s+)?webdriver\\s*\\(\\s*\\)\\s*\\{\\s*\\[native code\\]\\s*\\}/.test(s)) {
          details.webdriverGetterSpoofed = true;
        }
      }
      if (details.webdriverGetterSpoofed) {
        score += 4; flags |= 512; reasons.push("WEBDRIVER_GETTER_SPOOFED");
      }

      const checkFns = [
        Function.prototype.toString,
        Object.getOwnPropertyDescriptor,
        HTMLCanvasElement.prototype.toDataURL,
        CanvasRenderingContext2D.prototype.getImageData,
        Object.getOwnPropertyDescriptor(Navigator.prototype, "platform")?.get,
        Object.getOwnPropertyDescriptor(Navigator.prototype, "userAgent")?.get,
        navigator.permissions && navigator.permissions.query,
      ];
      if (typeof WebGLRenderingContext !== "undefined") checkFns.push(WebGLRenderingContext.prototype.getParameter);
      for (let i = 0; i < checkFns.length; i++) {
        const fn = checkFns[i];
        if (typeof fn !== "function") continue;
        const sMain = Function.prototype.toString.call(fn);
        const sFresh = freshToStr.call(fn);
        if (!/\\[native code\\]/.test(sMain) || !/\\[native code\\]/.test(sFresh) || sMain !== sFresh) {
          details.nativeFunctionTampered = true;
          break;
        }
      }
      if (details.nativeFunctionTampered) {
        score += 4; flags |= 1024; reasons.push("NATIVE_FUNCTION_TAMPERED");
      }
    } catch (_) {}

    if (freshFrame) {
      try { freshFrame.remove(); } catch (_) {}
    }

    // 7. Canvas2D solid #808080 uniqueness + 2-render determinism (+2 or +4)
    try {
      const drawSolid = () => {
        const c = document.createElement("canvas");
        c.width = 32; c.height = 32;
        const ctx = c.getContext("2d");
        if (!ctx) return null;
        ctx.fillStyle = "#808080";
        ctx.fillRect(0, 0, 32, 32);
        return ctx.getImageData(0, 0, 32, 32).data;
      };
      const d1 = drawSolid();
      const d2 = drawSolid();
      if (d1 && d2) {
        const uniq = new Set();
        let diff = 0;
        for (let i = 0; i < d1.length; i += 4) {
          uniq.add((d1[i] << 16) | (d1[i + 1] << 8) | d1[i + 2]);
          if (d1[i] !== d2[i] || d1[i + 1] !== d2[i + 1] || d1[i + 2] !== d2[i + 2]) diff++;
        }
        details.canvas2dUniqueColors = uniq.size;
        details.canvas2dRepeatDiff = diff;
      }
    } catch (_) {}

    // 8 & 9. WebGL gl.clear noise (+2) & GPU-to-Capabilities / OS hardware coherence (+2)
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
        details.webglRenderer = renderer;
        const exts = gl.getSupportedExtensions() || [];
        const maxTex = Number(gl.getParameter(gl.MAX_TEXTURE_SIZE) || 0);
        const pl = details.platform;
        const claimsWin = pl.startsWith("Win") || /Windows NT/i.test(navigator.userAgent);
        const claimsLinux = pl.startsWith("Linux") && !/Android/i.test(navigator.userAgent);

        const claimsDiscreteOrD3D = /NVIDIA|GeForce|RTX|GTX|Radeon|Direct3D11|D3D11/i.test(renderer);
        const lowExtDiscreteLie = claimsDiscreteOrD3D && exts.length > 0 && exts.length <= 19;
        const maxwellTexLie = /GTX\\s*(6|7|9|10)\\d{2}/i.test(renderer) && maxTex >= 32768;
        const d3d11ParallelLie = /(Direct3D11|D3D11)/i.test(renderer) && /(NVIDIA|RTX)/i.test(renderer) && !exts.includes("KHR_parallel_shader_compile") && exts.length < 30;
        const osGpuImpossibility =
          (claimsWin && (/Intel Iris OpenGL Engine|Apple GPU|Apple M\\d/i.test(renderer))) ||
          (claimsLinux && /Direct3D11|D3D11|Direct3D9/i.test(renderer));

        if (lowExtDiscreteLie || maxwellTexLie || d3d11ParallelLie || osGpuImpossibility) {
          details.webglHardwareLie = true;
          score += 2; flags |= 32; reasons.push("WEBGL_HARDWARE_COHERENCE_LIE");
        }
        const lose = gl.getExtension("WEBGL_lose_context");
        if (lose) lose.loseContext();
      }
    } catch (_) {}

    // 10. Silent OfflineAudioContext + oscillator determinism (+2)
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

    // 11. Integer-DPR DOMRect sub-pixel poisoning (+2)
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

    // 12. OS platform vs mandatory core system fonts (+2)
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

    // 13. Euclidean Viewport / Screen Geometry Impossibility & Headless Desktop checks (+2)
    try {
      const isFullscreen = Boolean(document.fullscreenElement || document.webkitFullscreenElement);
      const isDesktop = !/Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) && screen.width >= 600 && screen.height >= 400;
      if (isDesktop && !isFullscreen) {
        const exceedsScreen = window.outerHeight > screen.height + 16 || window.outerWidth > screen.width + 16;
        const zeroChromeFullScreenSize =
          window.outerWidth > 0 &&
          window.outerWidth === window.innerWidth &&
          window.outerHeight === window.innerHeight &&
          window.outerWidth === screen.width &&
          window.outerHeight === screen.height;
        const noDesktopPointer =
          (navigator.maxTouchPoints || 0) === 0 &&
          typeof matchMedia === "function" &&
          !matchMedia("(pointer: fine)").matches &&
          !matchMedia("(hover: hover)").matches;
        if (exceedsScreen || zeroChromeFullScreenSize || noDesktopPointer) {
          details.viewportGeometryImpossibility = true;
          score += 2; flags |= 4096; reasons.push("VIEWPORT_GEOMETRY_IMPOSSIBILITY");
        }
      }
    } catch (_) {}

    // 14. Engine & Permissions Coherence (+2)
    try {
      let permLie = false;
      if (typeof Notification !== "undefined" && Notification.permission === "default" && navigator.permissions && navigator.permissions.query) {
        try {
          const st = await navigator.permissions.query({ name: "notifications" });
          if (st && st.state !== "prompt") permLie = true;
        } catch (_) {}
      }
      const isGecko = /Firefox\\//.test(navigator.userAgent) || (typeof CSS !== "undefined" && CSS.supports("-moz-appearance", "none"));
      const geckoAutomationProfile = isGecko && navigator.plugins && navigator.plugins.length === 0 && navigator.pdfViewerEnabled === false;
      if (permLie || geckoAutomationProfile) {
        details.engineCoherenceLie = true;
        score += 2; flags |= 8192; reasons.push("ENGINE_COHERENCE_LIE");
      }
    } catch (_) {}

    // 6. Await Web Worker cross-realm comparison (+4) & OffscreenCanvas check
    try {
      const w = await workerPromise;
      if (w) {
        details.offscreenCanvasUniqueColors = w.oc || 1;
        const platDiff = w.pl && details.platform && w.pl !== details.platform;
        const hwDiff = w.hw && navigator.hardwareConcurrency && w.hw !== navigator.hardwareConcurrency;
        const uaDiff = w.ua && navigator.userAgent && w.ua !== navigator.userAgent;
        const wglDiff = w.wr && details.webglRenderer && w.wr !== details.webglRenderer;
        if (platDiff || hwDiff || uaDiff || wglDiff || (antiCdp && w.wd && !details.webdriver)) {
          details.workerRealmContradiction = true;
          score += 4; flags |= 2048; reasons.push("WORKER_REALM_CONTRADICTION");
        }
      }
    } catch (_) {}

    // Finalize Canvas2D / OffscreenCanvas score (flag 1)
    if (details.canvas2dUniqueColors > 1 || details.offscreenCanvasUniqueColors > 1 || details.canvas2dRepeatDiff > 0) {
      score += details.canvas2dRepeatDiff > 0 ? 4 : 2;
      flags |= 1;
      reasons.push(details.canvas2dRepeatDiff > 0 ? "CANVAS2D_NON_DETERMINISTIC" : "CANVAS2D_SYNTHETIC_NOISE");
    }

    return { score, flags, platform: details.platform, reasons, details };
  }

  function thresholdFor(mode) {
    const m = String(mode || "strict").toLowerCase();
    if (m === "strict") return 2;
    if (m === "balanced") return 4;
    return Infinity;
  }

  let cachedProbe = null;
  async function verify({ mode = DEFAULT_MODE, ticket = "", nonce = "", antiCdp = true, includeInteraction = false } = {}) {
    if (!cachedProbe) cachedProbe = await runHardwareProbes({ antiCdp });
    const m = String(mode || "strict").toLowerCase();
    const threshold = thresholdFor(m);

    let totalScore = cachedProbe.score;
    let totalFlags = cachedProbe.flags;
    const allReasons = [...cachedProbe.reasons];
    let interactionVerdict = null;

    if (includeInteraction && kin.lastClick) {
      interactionVerdict = evaluateInteractionLocal(kin.lastClick, m);
      if (interactionVerdict.score > 0) {
        totalScore += interactionVerdict.score;
        totalFlags |= 16384;
        allReasons.push(...interactionVerdict.reasons);
      }
    }

    const blocked = m !== "off" && m !== "monitor" && totalScore >= threshold;
    const d = await sha256Hex("VB_ATTEST_V2|" + ticket + "|" + nonce + "|" + totalScore + "|" + totalFlags + "|" + cachedProbe.platform);
    return {
      ok: !blocked,
      blocked,
      mode: m,
      threshold,
      score: totalScore,
      flags: totalFlags,
      reasons: allReasons,
      details: cachedProbe.details,
      interaction: interactionVerdict,
      attest: { v: 2, s: totalScore, f: totalFlags, p: cachedProbe.platform, d },
    };
  }

  // Drop-in <veil-break mode="strict">...</veil-break> Closed Shadow DOM Web Component
  if (typeof customElements !== "undefined" && !customElements.get("veil-break")) {
    class VeilBreakElement extends HTMLElement {
      async connectedCallback() {
        if (this._vbMounted) return;
        this._vbMounted = true;
        const mode = this.getAttribute("mode") || DEFAULT_MODE;
        const denyMsg = this.getAttribute("deny-message") || "Access denied: automated or stealth browser integrity failure (VEILBREAK_DENIED).";
        const root = this.attachShadow({ mode: "closed" });
        root.innerHTML = '<div id="vb-state" style="padding:12px;font-family:system-ui,sans-serif;color:#94a3b8;">Verifying browser physics...</div>';
        const res = await verify({ mode });
        this.dataset.veilbreakScore = String(res.score);
        this.dataset.veilbreakStatus = res.blocked ? "blocked" : "allowed";
        if (res.blocked) {
          this.innerHTML = "";
          root.innerHTML = '<div id="vb-denied" style="padding:16px;border:1px solid #ef4444;border-radius:8px;background:#1f1215;color:#fecaca;font-family:system-ui,sans-serif;"><strong>VEILBREAK_DENIED</strong> (score ' + res.score + '/' + res.threshold + '): ' + denyMsg + '</div>';
          this.dispatchEvent(new CustomEvent("veilbreak-denied", { detail: res, bubbles: true }));
        } else {
          root.innerHTML = "<slot></slot>";
          this.dispatchEvent(new CustomEvent("veilbreak-allowed", { detail: res, bubbles: true }));
        }
      }
    }
    customElements.define("veil-break", VeilBreakElement);
  }

  // Auto-attach VeilBreak attestation headers on protected fetch() paths
  function isProtectedPath(pathname) {
    for (let i = 0; i < PROTECTED.length; i++) {
      const p = PROTECTED[i];
      if (p === "*" || p === "/" || pathname === p || pathname.startsWith(p.endsWith("/") ? p : p + "/")) return true;
    }
    return false;
  }

  window.fetch = async function veilBreakFetch(input, init = {}) {
    const reqUrl = new URL(typeof input === "string" ? input : input.url, window.location.href);
    if (reqUrl.origin !== window.location.origin || reqUrl.pathname.startsWith(BASE) || !isProtectedPath(reqUrl.pathname)) {
      return origFetch(input, init);
    }
    const tkResp = await origFetch(BASE + "/ticket", { method: "GET", credentials: "same-origin" });
    const tkData = tkResp.ok ? await tkResp.json() : { ticket: "" };
    const nonce = toHex(crypto.getRandomValues(new Uint8Array(8)));
    const res = await verify({ mode: DEFAULT_MODE, ticket: tkData.ticket || "", nonce, includeInteraction: Boolean(kin.lastClick) });
    if (res.blocked) {
      throw new Error("VEILBREAK_DENIED:" + res.reasons.join(","));
    }
    const headers = new Headers(typeof input !== "string" ? input.headers : undefined);
    if (init.headers) new Headers(init.headers).forEach((v, k) => headers.set(k, v));
    headers.set("X-VB-Ticket", tkData.ticket || "");
    headers.set("X-VB-Nonce", nonce);
    headers.set("X-VB-Attest", JSON.stringify(res.attest));
    return origFetch(reqUrl.toString(), { ...init, headers });
  };

  if (AUTO_BLOCK && DEFAULT_MODE !== "off" && DEFAULT_MODE !== "monitor") {
    const runPageBlock = async () => {
      const res = await verify({ mode: DEFAULT_MODE });
      window.__VEILBREAK_RESULT__ = res;
      if (res.blocked) {
        document.documentElement.innerHTML =
          '<head><meta charset="utf-8"><title>Access Denied</title></head>' +
          '<body style="background:#0b0f19;color:#f8fafc;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">' +
          '<div id="veilbreak-blocked" style="max-width:540px;padding:28px;border:1px solid #ef4444;border-radius:12px;background:#111827;">' +
          '<h2 style="margin-top:0;color:#fca5a5;">Access Denied: VEILBREAK_DENIED</h2>' +
          '<p>VeilBreak detected automated or anti-detect browser physics anomalies (score <b>' + res.score + '</b> / threshold ' + res.threshold + ').</p>' +
          '<pre style="background:#090d16;padding:12px;border-radius:8px;overflow:auto;">' + res.reasons.join("\\n") + '</pre>' +
          '</div></body>';
      }
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runPageBlock);
    else runPageBlock();
  }

  window.VeilBreak = {
    verify,
    evaluateClick: (ev, el) => evaluateInteractionLocal(captureInteraction(ev, el), DEFAULT_MODE),
    getLastInteraction: () => kin.lastClick,
    version: "2.0.0",
    mode: DEFAULT_MODE,
  };
})();
`;
}

function buildPlaygroundHtml({ basePath = "/__veilbreak", mode = "strict" } = {}) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VeilBreak — Live 14-Invariant Browser Integrity Diagnostics</title>
  <script src="${basePath}/gate.js" data-mode="${mode}" data-block-page="false"></script>
  <style>
    body { background:#0b0f19; color:#e2e8f0; font-family:system-ui,sans-serif; padding:28px; max-width:900px; margin:0 auto; }
    .card { background:#111827; border:1px solid #1e293b; border-radius:12px; padding:20px; margin-bottom:18px; }
    table { width:100%; border-collapse:collapse; margin-top:12px; }
    th, td { text-align:left; padding:9px 10px; border-bottom:1px solid #1e293b; font-size:13.5px; }
    .pass { color:#4ade80; font-weight:600; }
    .fail { color:#f87171; font-weight:700; }
    button { background:#0284c7; color:#fff; border:0; border-radius:8px; padding:10px 18px; font-size:14px; font-weight:600; cursor:pointer; }
  </style>
</head>
<body>
  <h1 style="margin-top:0;">VeilBreak — 14-Invariant Multi-Engine Diagnostic Playground</h1>
  <div class="card" id="summary">Running Stage-1 hardware, cross-realm, and engine-coherence probes...</div>
  <div class="card">
    <h3 style="margin-top:0;">Stage-2 Interaction Kinematics Test</h3>
    <button id="vb-action-btn">Verify Protected Action</button>
    <div id="kin-out" style="margin-top:10px;font-family:monospace;font-size:13px;color:#94a3b8;">Click the button above to test mouse/pointer biomechanics + protected /api fetch.</div>
  </div>
  <div class="card">
    <h3 style="margin-top:0;">&lt;veil-break&gt; Shadow DOM Component Test</h3>
    <veil-break id="demo-gate" mode="${mode}">
      <div style="padding:12px;background:#052e16;border:1px solid #22c55e;border-radius:8px;color:#bbf7d0;">
        Protected Web Component mounted cleanly (genuine browser verified).
      </div>
    </veil-break>
  </div>
  <div class="card">
    <h3 style="margin-top:0;">Invariant Matrix</h3>
    <table>
      <thead><tr><th>Invariant</th><th>Measured</th><th>Status</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <script>
  (async () => {
    const res = await window.VeilBreak.verify({ mode: ${JSON.stringify(mode)} });
    document.getElementById("summary").innerHTML =
      '<strong>Verdict:</strong> <span class="' + (res.blocked ? 'fail' : 'pass') + '">' +
      (res.blocked ? 'VEILBREAK_DENIED (BLOCKED)' : 'ALLOWED (CLEAN BROWSER)') +
      '</span> &nbsp;|&nbsp; Score: <b>' + res.score + '</b> / threshold ' + res.threshold +
      ' &nbsp;|&nbsp; Mode: <code>' + res.mode + '</code> &nbsp;|&nbsp; Platform: <code>' + (res.details.platform || 'unknown') + '</code>';
    const d = res.details;
    const checks = [
      ["1. WebDriver Flag (Main + Fresh Iframe)", "main=" + d.webdriver + " iframe=" + d.freshIframeWebdriver, !(d.webdriver || d.freshIframeWebdriver)],
      ["2. Automation Global Artifacts (cdc_*, __pw*, etc.)", String(d.automationGlobalArtifact), !d.automationGlobalArtifact],
      ["3. CDP Runtime.enable Trap", String(d.cdpRuntimeEnable), !d.cdpRuntimeEnable],
      ["4. WebDriver Getter Integrity", d.webdriverGetterSpoofed ? "spoofed" : "native", !d.webdriverGetterSpoofed],
      ["5. Cross-Realm Native Function Integrity", d.nativeFunctionTampered ? "tampered" : "native", !d.nativeFunctionTampered],
      ["6. Web Worker Cross-Realm Consistency", d.workerRealmContradiction ? "mismatch" : "coherent", !d.workerRealmContradiction],
      ["7. Canvas2D / OffscreenCanvas Determinism", "uniq=" + d.canvas2dUniqueColors + " oc=" + d.offscreenCanvasUniqueColors + " rep=" + d.canvas2dRepeatDiff, d.canvas2dUniqueColors <= 1 && d.offscreenCanvasUniqueColors <= 1 && d.canvas2dRepeatDiff === 0],
      ["8. WebGL gl.clear(0.5) Readback", d.webglClearUniqueColors + " unique color(s)", d.webglClearUniqueColors <= 1],
      ["9. WebGL GPU Hardware Coherence", d.webglHardwareLie ? "lie (" + d.webglRenderer + ")" : (d.webglRenderer || "clean"), !d.webglHardwareLie],
      ["10. Silent OfflineAudioContext Zero-Invariance", d.silentAudioNonZeroSamples + " non-zero sample(s)", d.silentAudioNonZeroSamples === 0],
      ["11. Integer-DPR DOMRect Sub-Pixel Physics", "delta=" + d.domRectDelta + "px", !d.domRectSubpixelDrift],
      ["12. OS Platform vs. Core System Fonts", d.osFontLie ? "missing OS core fonts" : "coherent", !d.osFontLie],
      ["13. Viewport / Screen Euclidean Geometry", d.viewportGeometryImpossibility ? "impossible" : "valid", !d.viewportGeometryImpossibility],
      ["14. Permissions & Engine Coherence", d.engineCoherenceLie ? "contradiction" : "coherent", !d.engineCoherenceLie],
    ];
    document.getElementById("rows").innerHTML = checks.map(([name, val, ok]) =>
      '<tr><td>' + name + '</td><td><code>' + val + '</code></td><td class="' + (ok ? 'pass' : 'fail') + '">' + (ok ? 'CLEAN' : 'TRIGGERED') + '</td></tr>'
    ).join("");

    document.getElementById("vb-action-btn").addEventListener("click", async (ev) => {
      const k = window.VeilBreak.evaluateClick(ev, ev.currentTarget);
      let apiStatus = "skipped";
      try {
        const r = await fetch("/api/secret");
        apiStatus = "HTTP " + r.status;
      } catch (e) {
        apiStatus = String(e.message || e);
      }
      document.getElementById("kin-out").textContent =
        "Kinematics: " + (k.blocked ? "BLOCKED" : "CLEAN") +
        " (score=" + k.score + ", moves=" + k.details.pointerMoves +
        ", dwellMs=" + k.details.dwellMs + ", trusted=" + k.details.isTrusted +
        ", reasons=" + (k.reasons.join(",") || "none") + ") | API=" + apiStatus;
    });
  })();
  </script>
</body>
</html>`;
}

module.exports = { buildBrowserGateScript, buildPlaygroundHtml };
