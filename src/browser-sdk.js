"use strict";

const pkgVersion = (() => {
  try {
    return require("../package.json").version || "2.1.0";
  } catch {
    return "2.1.0";
  }
})();

function serializeRulesForScript(raw) {
  return (Array.isArray(raw) ? raw : []).map((r) => {
    if (r instanceof RegExp) return { regex: r.source, flags: r.flags.replace(/[gy]/g, "") };
    return r;
  });
}

function escapeInlineJson(obj) {
  return JSON.stringify(obj)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/**
 * Generates the zero-dependency VeilBreak browser SDK (`/__veilbreak/gate.js`):
 *   1. 14 cross-engine physics, graphics, audio, cross-realm, prototype,
 *      geometry, and engine-coherence invariants across Chromium & Gecko engines.
 *   2. Stage-2 Biomechanical Interaction Kinematics Guard (WeakMap-cached per event
 *      so capture-phase tracking never blinds explicit `evaluateClick()` calls).
 *   3. `<veil-break mode="strict">...</veil-break>` closed Shadow DOM Web Component (React 18 reconnect-safe).
 *   4. Automatic `fetch()` AND `XMLHttpRequest` instrumentation with per-ticket SHA-256 PoW
 *      + method/path-bound `VB_ATTEST_V2` telemetry envelope.
 */
function buildBrowserGateScript({
  basePath = "/__veilbreak",
  defaultMode = "strict",
  protectedPaths = ["/api"],
  protectedRules = null,
  autoBlockPage = false,
  antiCdp = true,
} = {}) {
  const normBase = String(basePath || "/__veilbreak").replace(/\/+$/, "") || "/__veilbreak";
  const rules = serializeRulesForScript(
    Array.isArray(protectedRules) && protectedRules.length > 0 ? protectedRules : protectedPaths
  );
  return `(() => {
  "use strict";
  if (typeof window === "undefined" || typeof document === "undefined" || window.__VEILBREAK_LOADED__) return;
  window.__VEILBREAK_LOADED__ = true;

  const BASE = ${escapeInlineJson(normBase)};
  const VERSION = ${escapeInlineJson(pkgVersion)};
  const scriptEl = document.currentScript;
  const VALID_MODES = { off: 1, monitor: 1, balanced: 1, strict: 1 };

  function normalizeClientMode(m, fallback = "strict") {
    const s = String(m || fallback).trim().toLowerCase();
    if (s === "observe") return "monitor";
    return VALID_MODES[s] ? s : fallback;
  }

  const DEFAULT_MODE = normalizeClientMode(
    (scriptEl && scriptEl.getAttribute("data-mode")) || ${escapeInlineJson(defaultMode)},
    "strict"
  );
  const attrBlock = scriptEl && scriptEl.getAttribute("data-block-page");
  const normBlock = attrBlock === null ? "" : String(attrBlock).trim().toLowerCase();
  const AUTO_BLOCK =
    normBlock === "false" || normBlock === "0"
      ? false
      : (normBlock === "true" || normBlock === "1" || ${escapeInlineJson(Boolean(autoBlockPage))});
  const attrCdp = scriptEl && scriptEl.getAttribute("data-anti-cdp");
  const normCdp = attrCdp === null ? "" : String(attrCdp).trim().toLowerCase();
  const DEFAULT_ANTI_CDP =
    normCdp === "false" || normCdp === "0"
      ? false
      : (normCdp === "true" || normCdp === "1" ? true : ${escapeInlineJson(antiCdp !== false)});

  function decodePercentSafe(s) {
    return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
      let out = "";
      let i = 0;
      while (i < run.length) {
        const b = parseInt(run.slice(i + 1, i + 3), 16);
        if (b === 0) { out += "\\0"; i += 3; continue; }
        if (b >= 1 && b <= 0x7f) { out += String.fromCharCode(b); i += 3; continue; }
        let ok = false;
        for (const n of [2, 3, 4]) {
          if (i + n * 3 <= run.length) {
            try { out += decodeURIComponent(run.slice(i, i + n * 3)); i += n * 3; ok = true; break; } catch {}
          }
        }
        if (!ok) { out += run.slice(i, i + 3); i += 3; }
      }
      return out;
    });
  }

  function normalizeClientPath(raw) {
    let s = String(raw || "/").split("?")[0];
    for (let pass = 0; pass < 2; pass++) {
      const next = decodePercentSafe(s);
      if (next === s) break;
      s = next;
    }
    s = s.replace(/\\0/g, "").replace(/\\\\/g, "/");
    if (!s.startsWith("/")) s = "/" + s;
    const segs = s.split("/").map((seg) => seg.split(";")[0]);
    const stack = [];
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i];
      if (!seg || seg === ".") continue;
      if (seg === "..") { if (stack.length) stack.pop(); }
      else stack.push(seg);
    }
    return ("/" + stack.join("/")).replace(/\\?/g, "%3F");
  }

  const RAW_RULES = ${escapeInlineJson(rules)};
  const RULES = RAW_RULES.map((r) => {
    if (r && typeof r === "object" && typeof r.regex === "string") {
      try { return new RegExp(r.regex, r.flags || ""); } catch { return null; }
    }
    if (typeof r !== "string") return null;
    const t = r.trim();
    if (t === "*") return "*";
    return normalizeClientPath(t).toLowerCase();
  }).filter(Boolean);

  const origFetch = typeof window.fetch === "function" ? window.fetch.bind(window) : null;
  const encoder = new TextEncoder();

  // Stage-2 pointer kinematics observer (WeakMap-cached per MouseEvent so capture-phase click never zeroes evaluateClick!)
  const kin = { moves: 0, zeroMoves: 0, downTs: 0, pointerType: "mouse", lastClick: null };
  const capturedEvents = new WeakMap();
  window.addEventListener("pointermove", (e) => {
    kin.pointerType = e.pointerType || kin.pointerType;
    kin.moves++;
    if (e.movementX === 0 && e.movementY === 0) kin.zeroMoves++;
  }, { capture: true, passive: true });
  window.addEventListener("pointerdown", (e) => {
    kin.pointerType = e.pointerType || "mouse";
    kin.downTs = performance.now();
  }, { capture: true, passive: true });

  function isInteractiveControl(el) {
    if (!el || typeof el.closest !== "function") return false;
    return Boolean(el.closest('button, a, [role="button"], input[type="submit"], input[type="button"]'));
  }

  function isElementVisible(el) {
    if (!el || typeof el.getClientRects !== "function") return false;
    try {
      const st = window.getComputedStyle(el);
      if (st && (st.visibility === "hidden" || st.display === "none")) return false;
      return el.getClientRects().length > 0;
    } catch (_) {
      return el.offsetParent !== null;
    }
  }

  function computeHitCenter(e, el) {
    try {
      if (el && typeof el.getBoundingClientRect === "function" && e && typeof e.clientX === "number") {
        const r = el.getBoundingClientRect();
        if (r.width > 4 && r.height > 4) {
          return (
            Math.abs(e.clientX - (r.left + r.width / 2)) < 0.75 &&
            Math.abs(e.clientY - (r.top + r.height / 2)) < 0.75
          );
        }
      }
    } catch (_) {}
    return false;
  }

  function captureInteraction(e, targetEl, explicit = false) {
    const el = targetEl || (e && e.currentTarget) || (e && e.target);
    let base = e && typeof e === "object" ? capturedEvents.get(e) : null;
    if (!base) {
      const upTs = performance.now();
      base = {
        isTrusted: Boolean(e && e.isTrusted),
        detail: Number((e && e.detail) ?? 0),
        pointerType: (e && e.pointerType) || kin.pointerType || "mouse",
        pointerMoves: kin.moves,
        zeroMoveCount: kin.zeroMoves,
        dwellMs: kin.downTs > 0 ? Number((upTs - kin.downTs).toFixed(2)) : -1,
        ts: upTs,
      };
      if (e && typeof e === "object") capturedEvents.set(e, base);
      kin.moves = 0;
      kin.zeroMoves = 0;
      kin.downTs = 0;
    }
    const info = {
      ...base,
      hitExactCenter: computeHitCenter(e, el),
    };
    if (explicit || (info.isTrusted && isInteractiveControl(el)) || (!info.isTrusted && isInteractiveControl(el) && isElementVisible(el))) {
      kin.lastClick = info;
    }
    return info;
  }

  function getFreshLastClick() {
    if (!kin.lastClick) return null;
    if (performance.now() - (kin.lastClick.ts || 0) > 10_000) {
      kin.lastClick = null;
      return null;
    }
    return kin.lastClick;
  }

  function thresholdFor(mode) {
    const m = normalizeClientMode(mode, "strict");
    if (m === "off" || m === "monitor") return Infinity;
    if (m === "balanced") return 4;
    return 2;
  }

  function evaluateInteractionLocal(info, mode) {
    const m = normalizeClientMode(mode, DEFAULT_MODE);
    const threshold = thresholdFor(m);
    if (m === "off" || !info) return { ok: true, blocked: false, score: 0, threshold, mode: m, reasons: [], details: info || null };
    let score = 0;
    const reasons = [];
    const pType = String(info.pointerType || "mouse").toLowerCase();
    if (info.isTrusted === false) {
      score += 6;
      reasons.push("UNTRUSTED_SYNTHETIC_CLICK");
    } else if (info.isTrusted === true && info.detail >= 1 && pType !== "touch" && pType !== "pen") {
      if (info.pointerMoves <= 3 && info.dwellMs >= 0 && info.dwellMs < 12 && info.hitExactCenter) {
        score += 4;
        reasons.push("TELEPORT_CLICK_PHYSICS");
      } else if (info.pointerMoves === 0 && info.dwellMs > 0 && info.dwellMs < 8 && info.hitExactCenter) {
        score += 4;
        reasons.push("ZERO_TRAJECTORY_INSTANT_CLICK");
      }
    }
    const blocked = m !== "monitor" && score >= threshold;
    return { ok: !blocked, blocked, score, threshold, mode: m, reasons, details: info };
  }

  window.addEventListener("click", (e) => {
    captureInteraction(e, e.target, false);
  }, { capture: true, passive: true });

  function toHex(buf) {
    const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < u.length; i++) out += u[i].toString(16).padStart(2, "0");
    return out;
  }

  // Compact pure-JS FIPS 180-4 SHA-256 (used for non-HTTPS origins & ~1-2ms synchronous PoW solving)
  const SHA256_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  const SHA256_W = new Int32Array(64);
  function sha256Words(str) {
    const bytes = encoder.encode(str);
    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    const bitLen = bytes.length * 8;
    const padLen = ((bytes.length + 9 + 63) >> 6) << 6;
    const m = new Uint8Array(padLen);
    m.set(bytes);
    m[bytes.length] = 0x80;
    const dv = new DataView(m.buffer);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(padLen - 4, bitLen >>> 0, false);
    for (let o = 0; o < padLen; o += 64) {
      for (let i = 0; i < 16; i++) SHA256_W[i] = dv.getInt32(o + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = ((SHA256_W[i-15]>>>7)|(SHA256_W[i-15]<<25)) ^ ((SHA256_W[i-15]>>>18)|(SHA256_W[i-15]<<14)) ^ (SHA256_W[i-15]>>>3);
        const s1 = ((SHA256_W[i-2]>>>17)|(SHA256_W[i-2]<<15)) ^ ((SHA256_W[i-2]>>>19)|(SHA256_W[i-2]<<13)) ^ (SHA256_W[i-2]>>>10);
        SHA256_W[i] = (SHA256_W[i-16] + s0 + SHA256_W[i-7] + s1) | 0;
      }
      let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + SHA256_K[i] + SHA256_W[i]) | 0;
        const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
      }
      h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0; h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
    }
    return [h0 >>> 0, h1 >>> 0, h2 >>> 0, h3 >>> 0, h4 >>> 0, h5 >>> 0, h6 >>> 0, h7 >>> 0];
  }

  function sha256FallbackHex(str) {
    return sha256Words(str).map((x) => x.toString(16).padStart(8, "0")).join("");
  }

  async function sha256Hex(str) {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      try {
        const d = await crypto.subtle.digest("SHA-256", encoder.encode(str));
        return toHex(d);
      } catch (_) {}
    }
    return sha256FallbackHex(str);
  }

  function hasLeadingZeroBits(words, bits) {
    let rem = bits;
    for (let i = 0; i < words.length && rem > 0; i++) {
      const w = words[i];
      if (rem >= 32) {
        if (w !== 0) return false;
        rem -= 32;
      } else {
        return Math.clz32(w) >= rem;
      }
    }
    return true;
  }

  function solveTicketPow(ticket, challenge, difficulty) {
    if (!difficulty || difficulty <= 0 || !ticket || !challenge) return "0";
    const prefix = "VB_POW_V2|" + ticket + "|" + challenge + "|";
    for (let i = 0; i < 5_000_000; i++) {
      const nonce = i.toString(36);
      if (hasLeadingZeroBits(sha256Words(prefix + nonce), difficulty)) return nonce;
    }
    return "0";
  }

  function withTimeout(promise, ms, fallback = null) {
    return new Promise((resolve) => {
      let done = false;
      const tm = setTimeout(() => { if (!done) { done = true; resolve(fallback); } }, ms);
      Promise.resolve(promise).then(
        (v) => { if (!done) { done = true; clearTimeout(tm); resolve(v); } },
        () => { if (!done) { done = true; clearTimeout(tm); resolve(fallback); } }
      );
    });
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
      let url = null;
      let w = null;
      let tm = null;
      let settled = false;
      const done = (val) => {
        if (settled) return;
        settled = true;
        if (tm) clearTimeout(tm);
        if (w) { try { w.terminate(); } catch (_) {} w = null; }
        if (url) { try { URL.revokeObjectURL(url); } catch (_) {} url = null; }
        resolve(val);
      };
      try {
        const src = [
          "self.onmessage=()=>{",
          "const o={ua:navigator.userAgent,pl:navigator.platform,hw:navigator.hardwareConcurrency,wd:Boolean(navigator.webdriver),oc:1,wr:''};",
          "try{if(typeof OffscreenCanvas!=='undefined'){",
          "const c=new OffscreenCanvas(32,32),x=c.getContext('2d');",
          "if(x){x.fillStyle='#808080';x.fillRect(0,0,32,32);const d=x.getImageData(0,0,32,32).data,u=new Set();for(let i=0;i<d.length;i+=4)u.add((d[i]<<16)|(d[i+1]<<8)|d[i+2]);o.oc=u.size;}",
          "const c2=new OffscreenCanvas(32,32),g=c2.getContext('webgl2')||c2.getContext('webgl');",
          "if(g){const db=g.getExtension('WEBGL_debug_renderer_info');if(db)o.wr=String(g.getParameter(db.UNMASKED_RENDERER_WEBGL)||'');const lc=g.getExtension('WEBGL_lose_context');if(lc)lc.loseContext();}",
          "}}catch(_){}",
          "self.postMessage(o);};"
        ].join("");
        url = URL.createObjectURL(new Blob([src], { type: "application/javascript" }));
        w = new Worker(url);
        tm = setTimeout(() => done(null), timeoutMs);
        w.onmessage = (ev) => done(ev.data || null);
        w.onerror = (ev) => {
          if (ev && typeof ev.preventDefault === "function") ev.preventDefault();
          done(null);
        };
        w.postMessage(1);
      } catch (_) {
        done(null);
      }
    });
  }

  async function runHardwareProbes({ antiCdp = DEFAULT_ANTI_CDP } = {}) {
    const workerPromise = probeWebWorker(900);
    const rawPlatform = String(navigator.platform || "");
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
      domRectSubpixelDrift: false,
      domRectDelta: 0,
      osFontLie: false,
      viewportGeometryImpossibility: false,
      engineCoherenceLie: false,
      platform: rawPlatform.replace(/\\|/g, "").slice(0, 48),
    };

    let score = 0;
    let flags = 0;
    const reasons = [];
    let isGecko = /Firefox\\//.test(navigator.userAgent);
    try {
      if (!isGecko && typeof CSS !== "undefined" && typeof CSS.supports === "function") {
        isGecko = CSS.supports("-moz-appearance", "none");
      }
    } catch (_) {}

    // Fresh untouched iframe realm for cross-realm native & webdriver inspection
    let freshWin = null;
    let freshFrame = null;
    try {
      freshFrame = document.createElement("iframe");
      freshFrame.style.position = "fixed";
      freshFrame.style.left = "-9999px";
      freshFrame.style.top = "0";
      freshFrame.style.width = "1px";
      freshFrame.style.height = "1px";
      freshFrame.style.opacity = "0";
      freshFrame.style.pointerEvents = "none";
      (document.documentElement || document.body).appendChild(freshFrame);
      freshWin = freshFrame.contentWindow;

      try {
        if (freshWin && freshWin.navigator) {
          details.freshIframeWebdriver = Boolean(freshWin.navigator.webdriver);
        }
      } catch (_) {}

      // 1. WebDriver flag (+4)
      if (antiCdp && (details.webdriver || details.freshIframeWebdriver)) {
        score += 4; flags |= 64; reasons.push("WEBDRIVER_FLAG");
      }

      // 2. Global / Document automation artifacts (+4)
      try {
        const susRe = /^(\\$?cdc_|__playwright|__pw_manual|__pwInitScripts|__puppeteer|__webdriver|_selenium|_Selenium|__fxdriver|__driver_|domAutomation|callPhantom|_phantom|__nightmare|__lastWatir)/i;
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

      // 4 & 5. Prototype / Getter Spoofing & Cross-Realm Native Integrity (+4 each, Proxy-throw aware!)
      const freshToStr = (freshWin && freshWin.Function) ? freshWin.Function.prototype.toString : Function.prototype.toString;
      try {
        const wdOwn = Object.getOwnPropertyDescriptor(navigator, "webdriver");
        const wdProto = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
        const freshWdProto = freshWin && freshWin.Navigator ? Object.getOwnPropertyDescriptor(freshWin.Navigator.prototype, "webdriver") : null;
        if (wdOwn) {
          details.webdriverGetterSpoofed = true;
        } else if (freshWdProto && typeof freshWdProto.get === "function" && (!wdProto || typeof wdProto.get !== "function")) {
          // Deleted or converted to data property on Navigator.prototype
          details.webdriverGetterSpoofed = true;
        } else if (wdProto && typeof wdProto.get === "function") {
          try {
            const s = freshToStr.call(wdProto.get);
            if (!/function\\s+(?:get\\s+)?webdriver\\s*\\(\\s*\\)\\s*\\{\\s*\\[native code\\]\\s*\\}/.test(s)) {
              details.webdriverGetterSpoofed = true;
            }
          } catch (_) {
            // Proxy-wrapped getter throws TypeError in untouched Function.prototype.toString!
            details.webdriverGetterSpoofed = true;
          }
        }
      } catch (_) {}
      if (details.webdriverGetterSpoofed) {
        score += 4; flags |= 512; reasons.push("WEBDRIVER_GETTER_SPOOFED");
      }

      try {
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
        if (typeof WebGL2RenderingContext !== "undefined") checkFns.push(WebGL2RenderingContext.prototype.getParameter);
        for (let i = 0; i < checkFns.length; i++) {
          const fn = checkFns[i];
          if (typeof fn !== "function") continue;
          try {
            const sMain = Function.prototype.toString.call(fn);
            const sFresh = freshToStr.call(fn);
            if (!/\\[native code\\]/.test(sMain) || !/\\[native code\\]/.test(sFresh) || sMain !== sFresh) {
              details.nativeFunctionTampered = true;
              break;
            }
          } catch (_) {
            // Calling untouched Function.prototype.toString on a Proxy throws TypeError!
            details.nativeFunctionTampered = true;
            break;
          }
        }
      } catch (_) {}
      if (details.nativeFunctionTampered) {
        score += 4; flags |= 1024; reasons.push("NATIVE_FUNCTION_TAMPERED");
      }
    } catch (_) {
    } finally {
      if (freshFrame) {
        try { freshFrame.remove(); } catch (_) {}
      }
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

    // 8 & 9. WebGL gl.clear noise & GPU hardware coherence
    let gl = null;
    try {
      const c = document.createElement("canvas");
      c.width = 32; c.height = 32;
      const gl2 = c.getContext("webgl2");
      gl = gl2 || c.getContext("webgl");
      if (gl) {
        gl.disable(gl.DITHER);
        const exact128 = 128 / 255;
        gl.clearColor(exact128, exact128, exact128, 1.0);
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
        const minExts = gl2 ? 12 : 19;
        const lowExtDiscreteLie = claimsDiscreteOrD3D && exts.length > 0 && exts.length <= minExts;
        const maxwellTexLie = /GTX\\s*(6|7|9)\\d{2}/i.test(renderer) && maxTex >= 32768;
        const d3d11ParallelLie = !isGecko && /(Direct3D11|D3D11)/i.test(renderer) && /(NVIDIA|RTX)/i.test(renderer) && !exts.includes("KHR_parallel_shader_compile") && exts.length < 30;
        const osGpuImpossibility =
          (claimsWin && (/Intel Iris OpenGL Engine|Apple GPU|Apple M\\d/i.test(renderer))) ||
          (claimsLinux && /Direct3D11|D3D11|Direct3D9/i.test(renderer));

        if (lowExtDiscreteLie || maxwellTexLie || d3d11ParallelLie || osGpuImpossibility) {
          details.webglHardwareLie = true;
          score += 2; flags |= 32; reasons.push("WEBGL_HARDWARE_COHERENCE_LIE");
        }
      }
    } catch (_) {
    } finally {
      if (gl) {
        try { const lose = gl.getExtension("WEBGL_lose_context"); if (lose) lose.loseContext(); } catch (_) {}
      }
    }

    // 10. Silent OfflineAudioContext zero-invariance
    try {
      const OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (OAC) {
        const ac = new OAC(1, 512, 44100);
        const buf = ac.createBuffer(1, 512, 44100);
        const src = ac.createBufferSource();
        src.buffer = buf;
        src.connect(ac.destination);
        src.start(0);
        const rendered = await withTimeout(ac.startRendering(), 1500, null);
        if (rendered) {
          const ch = rendered.getChannelData(0);
          let nonZero = 0;
          for (let i = 0; i < ch.length; i++) if (Math.abs(ch[i]) > 1e-12) nonZero++;
          details.silentAudioNonZeroSamples = nonZero;
          if (nonZero > 0) { score += 2; flags |= 4; reasons.push("SILENT_AUDIO_SYNTHETIC_NOISE"); }
        }
      }
    } catch (_) {}

    const root = document.documentElement || document.body;

    // 11. Integer-DPR DOMRect sub-pixel poisoning (safe even before <body> parses or when <body> has CSS transform)
    try {
      const dpr = window.devicePixelRatio || 1;
      if (Math.abs(dpr - Math.round(dpr)) < 1e-6 && root) {
        const dv = document.createElement("div");
        dv.style.all = "initial";
        dv.style.position = "fixed";
        dv.style.left = "10px";
        dv.style.top = "20px";
        dv.style.width = "100px";
        dv.style.height = "50px";
        dv.style.margin = "0";
        dv.style.padding = "0";
        dv.style.border = "0";
        dv.style.visibility = "hidden";
        root.appendChild(dv);
        try {
          const r = dv.getBoundingClientRect();
          if (Math.abs(r.width - 100) < 2 && Math.abs(r.height - 50) < 2 && Math.abs(r.left - 10) < 2 && Math.abs(r.top - 20) < 2) {
            const delta = Math.max(Math.abs(r.left - 10), Math.abs(r.top - 20), Math.abs(r.width - 100), Math.abs(r.height - 50));
            details.domRectDelta = Number(delta.toFixed(6));
            if (delta > 1e-3 && delta < 1.5) {
              details.domRectSubpixelDrift = true;
              score += 2; flags |= 8; reasons.push("DOMRECT_SUBPIXEL_POISONING");
            }
          }
        } finally {
          dv.remove();
        }
      }
    } catch (_) {}

    // 12. OS platform vs mandatory core system fonts
    try {
      const pl = String(navigator.platform || "");
      const up = String((navigator.userAgentData && navigator.userAgentData.platform) || "");
      const claimsWin = pl.startsWith("Win") || up === "Windows";
      const claimsMac = (pl === "MacIntel" || up === "macOS") && (navigator.maxTouchPoints || 0) <= 1;
      if (root && (claimsWin || claimsMac)) {
        const sp = document.createElement("span");
        sp.textContent = "mmmmmmmmmmlliWWWW1234567890";
        sp.style.all = "initial";
        sp.style.position = "fixed";
        sp.style.left = "-9999px";
        sp.style.top = "0";
        sp.style.fontSize = "72px";
        sp.style.whiteSpace = "nowrap";
        sp.style.visibility = "hidden";
        root.appendChild(sp);
        try {
          const mw = (f) => { sp.style.fontFamily = f; return sp.offsetWidth; };
          const base = mw("monospace");
          const sansW = mw("sans-serif");
          if (base > 0 && sansW > 0 && sansW !== base) {
            const candidates = claimsWin
              ? ['"Segoe UI",monospace', '"Tahoma",monospace', '"Consolas",monospace', '"Calibri",monospace']
              : ['"Helvetica Neue",monospace', '"Geneva",monospace', '"Menlo",monospace'];
            let matched = 0;
            for (const f of candidates) if (mw(f) !== base) matched++;
            if (matched === 0) { details.osFontLie = true; score += 2; flags |= 16; reasons.push("OS_CORE_FONT_LIE"); }
          }
        } finally {
          sp.remove();
        }
      }
    } catch (_) {}

    // 13. Viewport / Screen Euclidean Geometry Impossibility (F11, macOS notch, PWA, tiling-WM safe)
    try {
      const isDisplaySpecial = Boolean(
        document.fullscreenElement ||
        document.webkitFullscreenElement ||
        (typeof window.matchMedia === "function" &&
          (window.matchMedia("(display-mode: fullscreen)").matches ||
           window.matchMedia("(display-mode: standalone)").matches ||
           window.matchMedia("(display-mode: minimal-ui)").matches))
      );
      const isTouchTablet = (navigator.maxTouchPoints || 0) > 1;
      const isDesktop = !/Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) && !isTouchTablet && screen.width >= 600 && screen.height >= 400;
      const dpr = window.devicePixelRatio || 1;
      const integerDpr = Math.abs(dpr - Math.round(dpr)) < 1e-6;
      if (isDesktop && !isDisplaySpecial && integerDpr) {
        const exceedsScreen = window.outerHeight > screen.height + 16 || window.outerWidth > screen.width + 16;
        const fillsAvail =
          (screen.availWidth && window.outerWidth >= screen.availWidth - 4 &&
           screen.availHeight && window.outerHeight >= screen.availHeight - 4);
        const zeroChromeWindow =
          !fillsAvail &&
          window.outerWidth > 0 &&
          window.outerWidth === window.innerWidth &&
          window.outerHeight === window.innerHeight &&
          (window.outerWidth < screen.width - 80 || window.outerHeight < screen.height - 120);
        if (exceedsScreen || zeroChromeWindow) {
          details.viewportGeometryImpossibility = true;
          score += 2; flags |= 4096; reasons.push("VIEWPORT_GEOMETRY_IMPOSSIBILITY");
        }
      }
    } catch (_) {}

    // 14. Permissions & Engine Coherence
    try {
      let permLie = false;
      if (typeof Notification !== "undefined" && navigator.permissions && navigator.permissions.query) {
        const st = await withTimeout(navigator.permissions.query({ name: "notifications" }), 900, null);
        if (st) {
          if (Notification.permission === "default" && st.state === "granted") permLie = true;
          if (Notification.permission === "denied" && st.state === "granted") permLie = true;
        }
      }
      if (permLie) {
        details.engineCoherenceLie = true;
        score += 2; flags |= 8192; reasons.push("ENGINE_COHERENCE_LIE");
      }
    } catch (_) {}

    // 6. Await Web Worker cross-realm comparison (+4) including WebGL renderer parity
    try {
      const w = await workerPromise;
      if (w) {
        details.offscreenCanvasUniqueColors = w.oc || 1;
        const platDiff = Boolean(w.pl && rawPlatform && w.pl !== rawPlatform);
        const hwDiff = Boolean(w.hw && navigator.hardwareConcurrency && w.hw !== navigator.hardwareConcurrency);
        const uaDiff = Boolean(w.ua && navigator.userAgent && w.ua !== navigator.userAgent);
        const wrDiff = Boolean(w.wr && details.webglRenderer && w.wr !== details.webglRenderer);
        if (platDiff || hwDiff || uaDiff || wrDiff || (antiCdp && w.wd && !details.webdriver)) {
          details.workerRealmContradiction = true;
          score += 4; flags |= 2048; reasons.push("WORKER_REALM_CONTRADICTION");
        }
      }
    } catch (_) {}

    // Finalize Canvas2D / OffscreenCanvas score
    if (details.canvas2dUniqueColors > 1 || details.offscreenCanvasUniqueColors > 1 || details.canvas2dRepeatDiff > 0) {
      score += details.canvas2dRepeatDiff > 0 ? 4 : 2;
      flags |= 1;
      reasons.push(details.canvas2dRepeatDiff > 0 ? "CANVAS2D_NON_DETERMINISTIC" : "CANVAS2D_SYNTHETIC_NOISE");
    }

    return { score, flags, platform: details.platform, reasons, details };
  }

  const probeCache = new Map();
  function getProbePromise(antiCdp) {
    const key = antiCdp ? "1" : "0";
    if (!probeCache.has(key)) {
      const p = runHardwareProbes({ antiCdp }).catch((err) => {
        probeCache.delete(key);
        throw err;
      });
      probeCache.set(key, p);
    }
    return probeCache.get(key);
  }

  async function verify({
    mode = DEFAULT_MODE,
    ticket = "",
    nonce = "",
    challenge = "",
    difficulty = 0,
    method = "",
    path = "",
    antiCdp = DEFAULT_ANTI_CDP,
    includeInteraction = false,
  } = {}) {
    const effMode = normalizeClientMode(mode, DEFAULT_MODE);
    const threshold = thresholdFor(effMode);
    if (effMode === "off") {
      return { ok: true, blocked: false, mode: "off", threshold: Infinity, score: 0, flags: 0, reasons: [], details: {}, interaction: null, attest: null };
    }
    const probe = await getProbePromise(antiCdp);

    let totalScore = probe.score;
    let totalFlags = probe.flags;
    const allReasons = [...probe.reasons];
    let interactionVerdict = null;

    const freshClick = includeInteraction ? getFreshLastClick() : null;
    if (freshClick) {
      interactionVerdict = evaluateInteractionLocal(freshClick, effMode);
      if (interactionVerdict.score > 0) {
        totalScore += interactionVerdict.score;
        totalFlags |= 16384;
        allReasons.push(...interactionVerdict.reasons);
      }
    }

    const blocked = effMode !== "monitor" && totalScore >= threshold;
    const safeTicket = String(ticket || "").replace(/\\|/g, "");
    const safeNonce = String(nonce || "").replace(/\\|/g, "");
    const safeChallenge = String(challenge || "").replace(/\\|/g, "");
    const safeMethod = String(method || "").trim().toUpperCase().replace(/\\|/g, "");
    const safePath = path ? normalizeClientPath(String(path)).replace(/\\|/g, "") : "";

    let attest;
    if (safeChallenge) {
      const powNonce = solveTicketPow(safeTicket, safeChallenge, difficulty || 0);
      const d = await sha256Hex(
        "VB_ATTEST_V2|" + safeTicket + "|" + safeNonce + "|" + totalScore + "|" + totalFlags + "|" +
        probe.platform + "|" + safeChallenge + "|" + powNonce + "|" + safeMethod + "|" + safePath
      );
      attest = { v: 2, s: totalScore, f: totalFlags, p: probe.platform, w: powNonce, m: safeMethod, u: safePath, d };
    } else {
      const d = await sha256Hex("VB_ATTEST_V2|" + safeTicket + "|" + safeNonce + "|" + totalScore + "|" + totalFlags + "|" + probe.platform);
      attest = { v: 2, s: totalScore, f: totalFlags, p: probe.platform, d };
    }

    return {
      ok: !blocked,
      blocked,
      mode: effMode,
      threshold,
      score: totalScore,
      flags: totalFlags,
      reasons: allReasons,
      details: probe.details,
      interaction: interactionVerdict,
      attest,
    };
  }

  // Drop-in <veil-break mode="strict">...</veil-break> Closed Shadow DOM Web Component (React 18 reconnect-safe)
  if (typeof customElements !== "undefined" && !customElements.get("veil-break")) {
    class VeilBreakElement extends HTMLElement {
      async connectedCallback() {
        if (this._vbDone) return;
        const gen = (this._vbGen = (this._vbGen || 0) + 1);
        const mode = this.getAttribute("mode") || DEFAULT_MODE;
        const cdpAttr = this.getAttribute("anti-cdp");
        const cdpFlag = cdpAttr === null ? DEFAULT_ANTI_CDP : !/^(false|0)$/i.test(cdpAttr.trim());
        const denyMsg = this.getAttribute("deny-message") || "Access denied: automated or stealth browser integrity failure (VEILBREAK_DENIED).";
        const root = this._vbRoot || (this._vbRoot = this.attachShadow({ mode: "closed" }));
        const styleEl = document.createElement("style");
        styleEl.textContent = ":host{display:block;}";
        const stateDiv = document.createElement("div");
        stateDiv.id = "vb-state";
        stateDiv.style.cssText = "padding:12px;font-family:system-ui,sans-serif;color:#94a3b8;";
        stateDiv.textContent = "Verifying browser integrity...";
        root.replaceChildren(styleEl, stateDiv);

        let res;
        try {
          res = await verify({ mode, antiCdp: cdpFlag });
        } catch (_) {
          res = { ok: false, blocked: true, score: 6, threshold: thresholdFor(mode), mode: normalizeClientMode(mode, DEFAULT_MODE), reasons: ["VERIFY_ERROR"] };
        }
        if (!this.isConnected || this._vbGen !== gen) return;
        this._vbDone = true;
        this.dataset.veilbreakScore = String(res.score);
        this.dataset.veilbreakStatus = res.blocked ? "blocked" : "allowed";
        if (res.blocked) {
          if (!this.hasAttribute("preserve-dom")) this.replaceChildren();
          const box = document.createElement("div");
          box.id = "vb-denied";
          box.style.cssText = "padding:16px;border:1px solid #ef4444;border-radius:8px;background:#1f1215;color:#fecaca;font-family:system-ui,sans-serif;";
          const strong = document.createElement("strong");
          strong.textContent = "VEILBREAK_DENIED";
          box.appendChild(strong);
          box.appendChild(document.createTextNode(" (score " + res.score + "/" + res.threshold + "): " + denyMsg));
          root.replaceChildren(styleEl, box);
          this.dispatchEvent(new CustomEvent("veilbreak-denied", { detail: res, bubbles: true, composed: true }));
        } else {
          const slot = document.createElement("slot");
          root.replaceChildren(styleEl, slot);
          this.dispatchEvent(new CustomEvent("veilbreak-allowed", { detail: res, bubbles: true, composed: true }));
        }
      }
    }
    customElements.define("veil-break", VeilBreakElement);
  }

  function isGateControlPath(pathname) {
    const norm = normalizeClientPath(pathname);
    return norm === BASE || norm.startsWith(BASE + "/");
  }

  function isProtectedPath(pathname) {
    const raw = String(pathname || "/").split("?")[0];
    const candidates = new Set([normalizeClientPath(raw)]);
    let dec = raw;
    for (let pass = 0; pass < 2; pass++) {
      const next = decodePercentSafe(dec);
      if (next === dec) break;
      dec = next;
    }
    candidates.add(normalizeClientPath(dec));
    const q = dec.indexOf("?");
    if (q >= 0) candidates.add(normalizeClientPath(dec.slice(0, q)));
    const h = dec.indexOf("#");
    if (h >= 0) candidates.add(normalizeClientPath(dec.slice(0, h)));

    for (const cand of candidates) {
      const lower = cand.toLowerCase();
      for (let i = 0; i < RULES.length; i++) {
        const rule = RULES[i];
        if (rule instanceof RegExp) {
          rule.lastIndex = 0;
          if (rule.test(cand)) return true;
        } else if (rule === "*" || rule === "/" || lower === rule || lower.startsWith(rule.endsWith("/") ? rule : rule + "/")) {
          return true;
        }
      }
    }
    return false;
  }

  function baseHref() {
    return (typeof document !== "undefined" && document.baseURI) || window.location.href;
  }

  function resolveUrl(input) {
    const b = baseHref();
    if (typeof input === "string") return new URL(input, b);
    if (input instanceof URL) return new URL(input.href, b);
    if (input && typeof input.url === "string") return new URL(input.url, b);
    return new URL(String(input), b);
  }

  function randomNonceHex() {
    const nonceBytes = new Uint8Array(8);
    if (typeof crypto !== "undefined" && crypto.getRandomValues) crypto.getRandomValues(nonceBytes);
    else for (let i = 0; i < 8; i++) nonceBytes[i] = Math.floor(Math.random() * 256);
    return toHex(nonceBytes);
  }

  async function buildRequestAttestationHeaders(method, reqPath, signal) {
    const tkResp = await origFetch(BASE + "/ticket", { method: "GET", credentials: "same-origin", cache: "no-store", signal });
    if (!tkResp.ok) {
      return { ok: false, response: tkResp };
    }
    let tkData = { ticket: "", challenge: "", difficulty: 0 };
    try { tkData = await tkResp.json(); } catch (_) {}
    const nonce = randomNonceHex();
    const res = await verify({
      mode: DEFAULT_MODE,
      ticket: tkData.ticket || "",
      nonce,
      challenge: tkData.challenge || "",
      difficulty: tkData.difficulty || 0,
      method,
      path: reqPath,
      includeInteraction: Boolean(getFreshLastClick()),
    });
    return {
      ok: true,
      headers: {
        "X-VB-Ticket": tkData.ticket || "",
        "X-VB-Nonce": nonce,
        ...(res.attest ? { "X-VB-Attest": JSON.stringify(res.attest) } : {}),
      },
    };
  }

  if (origFetch && DEFAULT_MODE !== "off") {
    window.fetch = async function veilBreakFetch(input, init) {
      const safeInit = init && typeof init === "object" ? init : {};
      let reqUrl;
      try { reqUrl = resolveUrl(input); } catch { return origFetch(input, init); }
      if (reqUrl.origin !== window.location.origin || isGateControlPath(reqUrl.pathname) || !isProtectedPath(reqUrl.pathname)) {
        return origFetch(input, init);
      }
      const isReq = typeof Request !== "undefined" && input instanceof Request;
      const method = (safeInit.method || (isReq ? input.method : "GET") || "GET").toUpperCase();
      const signal = safeInit.signal !== undefined ? safeInit.signal : (isReq ? input.signal : undefined);

      let attRes;
      try {
        attRes = await buildRequestAttestationHeaders(method, reqUrl.pathname, signal);
      } catch (err) {
        if (DEFAULT_MODE === "monitor") return origFetch(input, init);
        throw err;
      }
      if (!attRes.ok) {
        if (DEFAULT_MODE === "strict" || DEFAULT_MODE === "balanced") {
          return attRes.response;
        }
        return origFetch(input, init);
      }

      const headers = new Headers(safeInit.headers !== undefined ? safeInit.headers : (isReq ? input.headers : undefined));
      for (const [k, v] of Object.entries(attRes.headers)) headers.set(k, v);

      const resp = isReq
        ? await origFetch(new Request(input, { ...safeInit, headers }))
        : await origFetch(reqUrl.toString(), { ...safeInit, headers });

      if (resp.redirected && resp.status === 403 && (method === "GET" || method === "HEAD") && resp.url) {
        let finalUrl = null;
        try { finalUrl = new URL(resp.url, baseHref()); } catch (_) {}
        if (finalUrl && finalUrl.origin === window.location.origin && isProtectedPath(finalUrl.pathname)) {
          try {
            const retryAtt = await buildRequestAttestationHeaders(method, finalUrl.pathname, signal);
            if (retryAtt.ok) {
              const retryHdrs = new Headers(safeInit.headers !== undefined ? safeInit.headers : (isReq ? input.headers : undefined));
              for (const [k, v] of Object.entries(retryAtt.headers)) retryHdrs.set(k, v);
              const retryInit = {
                ...(isReq ? {
                  credentials: input.credentials,
                  cache: input.cache,
                  mode: input.mode,
                  referrer: input.referrer,
                  referrerPolicy: input.referrerPolicy,
                  signal: input.signal,
                } : {}),
                ...safeInit,
                method,
                headers: retryHdrs,
              };
              delete retryInit.body;
              return origFetch(finalUrl.toString(), retryInit);
            }
          } catch (_) {}
        }
      }
      return resp;
    };
  }

  // Transparently instrument async XMLHttpRequest (Axios, jQuery, HTMX, Angular HttpClient)
  if (typeof XMLHttpRequest !== "undefined" && origFetch && DEFAULT_MODE !== "off") {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    const origAbort = XMLHttpRequest.prototype.abort;
    const origSetHdr = XMLHttpRequest.prototype.setRequestHeader;
    const xhrMeta = new WeakMap();

    function clearShadowedXhrProps(xhr) {
      try { delete xhr.readyState; } catch (_) {}
      try { delete xhr.status; } catch (_) {}
    }

    function failXhrCleanly(xhr, statusCode = 0) {
      try { origAbort.call(xhr); } catch (_) {}
      try {
        Object.defineProperty(xhr, "readyState", { value: 4, configurable: true });
        Object.defineProperty(xhr, "status", { value: statusCode, configurable: true });
      } catch (_) {}
      try { xhr.dispatchEvent(new Event("readystatechange")); } catch (_) {}
      if (typeof ProgressEvent !== "undefined") {
        try {
          xhr.dispatchEvent(new ProgressEvent("error"));
          xhr.dispatchEvent(new ProgressEvent("loadend"));
        } catch (_) {}
      }
    }

    XMLHttpRequest.prototype.open = function veilBreakXhrOpen(method, url, asyncFlag = true) {
      clearShadowedXhrProps(this);
      const prev = xhrMeta.get(this);
      if (prev && prev.abortController) {
        try { prev.abortController.abort(); } catch (_) {}
        prev.abortController = null;
      }
      const opId = (prev ? prev.opId : 0) + 1;
      let resolvedUrl = null;
      try { resolvedUrl = new URL(String(url || ""), baseHref()); } catch (_) {}
      xhrMeta.set(this, {
        opId,
        method: String(method || "GET").toUpperCase(),
        url: resolvedUrl,
        asyncFlag: Boolean(asyncFlag),
        queued: false,
        abortController: null,
      });
      return origOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.abort = function veilBreakXhrAbort() {
      clearShadowedXhrProps(this);
      const m = xhrMeta.get(this);
      const wasQueued = Boolean(m && m.queued);
      if (m) {
        m.opId += 1;
        m.queued = false;
        if (m.abortController) {
          try { m.abortController.abort(); } catch (_) {}
          m.abortController = null;
        }
      }
      const res = origAbort.call(this);
      if (wasQueued && typeof ProgressEvent !== "undefined") {
        try {
          this.dispatchEvent(new ProgressEvent("abort"));
          this.dispatchEvent(new ProgressEvent("loadend"));
        } catch (_) {}
      }
      return res;
    };

    XMLHttpRequest.prototype.send = function veilBreakXhrSend(body) {
      const meta = xhrMeta.get(this);
      if (!meta || !meta.url) return origSend.call(this, body);
      const reqUrl = meta.url;
      if (reqUrl.origin !== window.location.origin || isGateControlPath(reqUrl.pathname) || !isProtectedPath(reqUrl.pathname)) {
        return origSend.call(this, body);
      }
      if (!meta.asyncFlag) {
        try { console.warn("[VeilBreak] Synchronous XMLHttpRequest to protected route cannot attach async ticket:", reqUrl.pathname); } catch (_) {}
        return origSend.call(this, body);
      }

      const opId = meta.opId;
      const self = this;
      const ac = typeof AbortController !== "undefined" ? new AbortController() : null;
      meta.abortController = ac;
      meta.queued = true;

      buildRequestAttestationHeaders(meta.method, reqUrl.pathname, ac ? ac.signal : undefined)
        .then((attRes) => {
          meta.queued = false;
          meta.abortController = null;
          if (xhrMeta.get(self)?.opId !== opId || self.readyState !== 1) return;
          if (!attRes.ok) {
            if (DEFAULT_MODE === "strict" || DEFAULT_MODE === "balanced") {
              failXhrCleanly(self, attRes.response ? attRes.response.status : 0);
              return;
            }
            origSend.call(self, body);
            return;
          }
          for (const [k, v] of Object.entries(attRes.headers)) origSetHdr.call(self, k, v);
          origSend.call(self, body);
        })
        .catch(() => {
          meta.queued = false;
          meta.abortController = null;
          if (xhrMeta.get(self)?.opId === opId && self.readyState === 1) {
            if (DEFAULT_MODE === "monitor") {
              try { origSend.call(self, body); } catch (_) {}
              return;
            }
            failXhrCleanly(self, 0);
          }
        });
    };
  }

  if (AUTO_BLOCK && DEFAULT_MODE !== "off" && DEFAULT_MODE !== "monitor") {
    const runPageBlock = async () => {
      try {
        const res = await verify({ mode: DEFAULT_MODE, antiCdp: DEFAULT_ANTI_CDP });
        window.__VEILBREAK_RESULT__ = res;
        if (res.blocked && document.body) {
          const box = document.createElement("div");
          box.id = "veilbreak-blocked";
          box.style.cssText = "max-width:540px;padding:28px;border:1px solid #ef4444;border-radius:12px;background:#111827;";
          const h2 = document.createElement("h2");
          h2.style.cssText = "margin-top:0;color:#fca5a5;";
          h2.textContent = "Access Denied: VEILBREAK_DENIED";
          const p = document.createElement("p");
          p.textContent = "VeilBreak detected automated or anti-detect browser anomalies (score " + res.score + " / threshold " + res.threshold + ").";
          const pre = document.createElement("pre");
          pre.style.cssText = "background:#090d16;padding:12px;border-radius:8px;overflow:auto;";
          pre.textContent = res.reasons.join("\\n");
          box.append(h2, p, pre);
          document.body.style.cssText = "background:#0b0f19;color:#f8fafc;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;";
          document.body.replaceChildren(box);
        }
      } catch (_) {}
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", runPageBlock, { once: true });
    else runPageBlock();
  }

  window.VeilBreak = {
    verify,
    evaluateClick: (ev, el, mode) => evaluateInteractionLocal(captureInteraction(ev, el, true), mode || DEFAULT_MODE),
    getLastInteraction: getFreshLastClick,
    version: VERSION,
    mode: DEFAULT_MODE,
  };
})();
`;
}

function escapeHtmlAttr(s) {
  return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function buildPlaygroundHtml({ basePath = "/__veilbreak", mode = "strict", antiCdp = true } = {}) {
  const normBase = String(basePath || "/__veilbreak").replace(/\/+$/, "") || "/__veilbreak";
  const safeBase = escapeHtmlAttr(normBase);
  const safeMode = escapeHtmlAttr(mode);
  const cdpAttr = antiCdp === false ? ' data-anti-cdp="false"' : "";
  const modeJs = escapeInlineJson(mode);
  const cdpJs = escapeInlineJson(antiCdp !== false);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VeilBreak — Live 14-Invariant Browser Integrity Diagnostics</title>
  <script src="${safeBase}/gate.js" data-mode="${safeMode}" data-block-page="false"${cdpAttr}></script>
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
    <veil-break id="demo-gate" mode="${safeMode}" anti-cdp="${antiCdp === false ? "false" : "true"}">
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
    const sum = document.getElementById("summary");
    if (!window.VeilBreak) {
      sum.textContent = "Error: VeilBreak gate.js failed to load.";
      return;
    }
    try {
      const res = await window.VeilBreak.verify({ mode: ${modeJs}, antiCdp: ${cdpJs} });
      sum.replaceChildren();
      const sLbl = document.createElement("strong"); sLbl.textContent = "Verdict: ";
      const sVal = document.createElement("span"); sVal.className = res.blocked ? "fail" : "pass";
      sVal.textContent = res.mode === "off" ? "DISABLED (MODE=OFF)" : (res.blocked ? "VEILBREAK_DENIED (BLOCKED)" : "ALLOWED (CLEAN BROWSER)");
      sum.append(sLbl, sVal, document.createTextNode(" | Score: " + res.score + " / threshold " + res.threshold + " | Mode: " + res.mode + " | Platform: " + ((res.details && res.details.platform) || "unknown")));

      const tbody = document.getElementById("rows");
      tbody.replaceChildren();
      if (res.mode === "off") {
        const tr = document.createElement("tr");
        const td = document.createElement("td"); td.colSpan = 3; td.textContent = "SKIPPED (mode=off)";
        tr.appendChild(td); tbody.appendChild(tr);
      } else {
        const d = res.details || {};
        const checks = [
          ["1. WebDriver Flag (Main + Fresh Iframe)", "main=" + d.webdriver + " iframe=" + d.freshIframeWebdriver, !(d.webdriver || d.freshIframeWebdriver)],
          ["2. Automation Global Artifacts (cdc_*, __playwright*, etc.)", String(d.automationGlobalArtifact), !d.automationGlobalArtifact],
          ["3. CDP Runtime.enable Trap", String(d.cdpRuntimeEnable), !d.cdpRuntimeEnable],
          ["4. WebDriver Getter Integrity", d.webdriverGetterSpoofed ? "spoofed" : "native", !d.webdriverGetterSpoofed],
          ["5. Cross-Realm Native Function Integrity", d.nativeFunctionTampered ? "tampered" : "native", !d.nativeFunctionTampered],
          ["6. Web Worker Cross-Realm Consistency", d.workerRealmContradiction ? "mismatch" : "coherent", !d.workerRealmContradiction],
          ["7. Canvas2D / OffscreenCanvas Determinism", "uniq=" + d.canvas2dUniqueColors + " oc=" + d.offscreenCanvasUniqueColors + " rep=" + d.canvas2dRepeatDiff, d.canvas2dUniqueColors <= 1 && d.offscreenCanvasUniqueColors <= 1 && d.canvas2dRepeatDiff === 0],
          ["8. WebGL gl.clear(128/255) Readback", d.webglClearUniqueColors + " unique color(s)", d.webglClearUniqueColors <= 1],
          ["9. WebGL GPU Hardware Coherence", d.webglHardwareLie ? "lie (" + d.webglRenderer + ")" : (d.webglRenderer || "clean"), !d.webglHardwareLie],
          ["10. Silent OfflineAudioContext Zero-Invariance", d.silentAudioNonZeroSamples + " non-zero sample(s)", d.silentAudioNonZeroSamples === 0],
          ["11. Integer-DPR DOMRect Sub-Pixel Physics", "delta=" + d.domRectDelta + "px", !d.domRectSubpixelDrift],
          ["12. OS Platform vs. Core System Fonts", d.osFontLie ? "missing OS core fonts" : "coherent", !d.osFontLie],
          ["13. Viewport / Screen Euclidean Geometry", d.viewportGeometryImpossibility ? "impossible" : "valid", !d.viewportGeometryImpossibility],
          ["14. Permissions & Engine Coherence", d.engineCoherenceLie ? "contradiction" : "coherent", !d.engineCoherenceLie],
        ];
        for (const [name, val, ok] of checks) {
          const tr = document.createElement("tr");
          const td1 = document.createElement("td"); td1.textContent = name;
          const td2 = document.createElement("td"); const code = document.createElement("code"); code.textContent = val; td2.appendChild(code);
          const td3 = document.createElement("td"); td3.className = ok ? "pass" : "fail"; td3.textContent = ok ? "CLEAN" : "TRIGGERED";
          tr.append(td1, td2, td3);
          tbody.appendChild(tr);
        }
      }

      document.getElementById("vb-action-btn").addEventListener("click", async (ev) => {
        const k = window.VeilBreak.evaluateClick(ev, ev.currentTarget);
        const kd = k.details || {};
        let apiStatus = "skipped";
        try {
          const r = await fetch("/api/secret");
          apiStatus = "HTTP " + r.status;
        } catch (e) {
          apiStatus = String(e.message || e);
        }
        document.getElementById("kin-out").textContent =
          "Kinematics: " + (k.blocked ? "BLOCKED" : "CLEAN") +
          " (score=" + k.score + ", moves=" + (kd.pointerMoves ?? "n/a") +
          ", dwellMs=" + (kd.dwellMs ?? "n/a") + ", trusted=" + (kd.isTrusted ?? "n/a") +
          ", reasons=" + (k.reasons.join(",") || "none") + ") | API=" + apiStatus;
      });
    } catch (err) {
      sum.textContent = "VeilBreak diagnostic error: " + String(err && err.message ? err.message : err);
    }
  })();
  </script>
</body>
</html>`;
}

module.exports = { buildBrowserGateScript, buildPlaygroundHtml };
