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

function compactGeneratedJs(src) {
  const lines = String(src || "").split("\n");
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith("//")) continue;
    out.push(trimmed);
  }
  return out.join("\n");
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
  allowDevTools = false,
  unified = false,
  embedded = false,
  _shareBaseRealm = false,
  includeTicketPow = !unified,
  sri = false,
  userGestureWindowMs = 15_000,
  allowBlockPageOverridePath = "",
} = {}) {
  const normBase = String(basePath || "/__veilbreak").replace(/\/+$/, "") || "/__veilbreak";
  const normPlayPath = allowBlockPageOverridePath
    ? String(allowBlockPageOverridePath).split("?")[0].replace(/\/+$/, "") || "/"
    : "";
  const susClickTtl = Number.isFinite(userGestureWindowMs) && userGestureWindowMs > 1_500 ? Math.round(userGestureWindowMs) : 15_000;
  const policyLocked = Boolean(unified || sri);
  const needFullPathAndPow = !unified || Boolean(includeTicketPow);
  const omitFallbackSha256 = Boolean(unified && embedded && !needFullPathAndPow);
  const rules = serializeRulesForScript(
    Array.isArray(protectedRules) && protectedRules.length > 0 ? protectedRules : protectedPaths
  );
  const standalonePathHelpers = !needFullPathAndPow ? `
  function normalizeClientPath(raw) {
    let s = String(raw || "/").split("?")[0].replace(/\\\\/g, "/");
    if (!s.startsWith("/")) s = "/" + s;
    let end = s.length;
    while (end > 1 && s.charCodeAt(end - 1) === 47) end--;
    return end === s.length ? s : s.slice(0, end);
  }
` : `
  function hexNib(c) {
    if (c >= 48 && c <= 57) return c - 48;
    if (c >= 65 && c <= 70) return c - 55;
    if (c >= 97 && c <= 102) return c - 87;
    return -1;
  }
  function hexByte(s, idx) {
    return (hexNib(s.charCodeAt(idx + 1)) << 4) | hexNib(s.charCodeAt(idx + 2));
  }
  function decodePercentSafe(s) {
    if (s.indexOf("%") < 0) return s;
    return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
      let out = "";
      let i = 0;
      const len = run.length;
      while (i < len) {
        const b = hexByte(run, i);
        if (b === 0) { out += "\\0"; i += 3; continue; }
        if (b <= 0x7f) { out += String.fromCharCode(b); i += 3; continue; }
        if (b >= 0xc2 && b <= 0xdf && i + 6 <= len) {
          const b2 = hexByte(run, i + 3);
          if ((b2 & 0xc0) === 0x80) { out += String.fromCharCode(((b & 0x1f) << 6) | (b2 & 0x3f)); i += 6; continue; }
        } else if (b >= 0xe0 && b <= 0xef && i + 9 <= len) {
          const b2 = hexByte(run, i + 3);
          const b3 = hexByte(run, i + 6);
          const ok2 = b === 0xe0 ? (b2 >= 0xa0 && b2 <= 0xbf) : b === 0xed ? (b2 >= 0x80 && b2 <= 0x9f) : ((b2 & 0xc0) === 0x80);
          if (ok2 && (b3 & 0xc0) === 0x80) { out += String.fromCharCode(((b & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f)); i += 9; continue; }
        } else if (b >= 0xf0 && b <= 0xf4 && i + 12 <= len) {
          const b2 = hexByte(run, i + 3);
          const b3 = hexByte(run, i + 6);
          const b4 = hexByte(run, i + 9);
          const ok2 = b === 0xf0 ? (b2 >= 0x90 && b2 <= 0xbf) : b === 0xf4 ? (b2 >= 0x80 && b2 <= 0x8f) : ((b2 & 0xc0) === 0x80);
          if (ok2 && (b3 & 0xc0) === 0x80 && (b4 & 0xc0) === 0x80) {
            out += String.fromCodePoint(((b & 0x07) << 18) | ((b2 & 0x3f) << 12) | ((b3 & 0x3f) << 6) | (b4 & 0x3f));
            i += 12;
            continue;
          }
        }
        out += run.slice(i, i + 3);
        i += 3;
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
    return ("/" + stack.join("/")).replace(/\\?/g, "%3F").replace(/\\|/g, "%7C");
  }
`;
  const standaloneRulesAndFetch = unified ? "" : `
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
`;
  const openBaseRealmCode = embedded && _shareBaseRealm
    ? `
  function openBaseFreshRealm() {
    if (typeof __PS_OPEN_BASE_REALM__ === "function") return __PS_OPEN_BASE_REALM__();
    return { ok: false, tampered: true, frame: null, host: null, win: null, fToStr: null, fExec: null, createElFn: null, appendFn: null, cwGet: null, cleanup: () => {} };
  }`
    : `
  function openBaseFreshRealm() {
    let host = null;
    let frame = null;
    const cleanup = () => {
      if (host) {
        try { if (_elRemove) _reflectApply(_elRemove, host, []); else host.remove(); } catch (_) {}
        host = null;
      }
      if (frame) {
        try { if (_elRemove) _reflectApply(_elRemove, frame, []); else frame.remove(); } catch (_) {}
        frame = null;
      }
    };
    try {
      const parent = _docElGet ? (_reflectApply(_docElGet, document, []) || document.body) : (document.documentElement || document.body);
      const createElFn = _docCreateElement || document.createElement;
      const appendFn = _nodeAppendChild || (parent && parent.appendChild);
      if (!parent || typeof createElFn !== "function" || typeof appendFn !== "function") {
        return { ok: false, tampered: true, frame: null, host: null, win: null, fToStr: null, fExec: null, createElFn: null, appendFn: null, cwGet: null, cleanup };
      }
      if (
        !isNativeNamed(createElFn, "createElement") ||
        !isNativeNamed(appendFn, "appendChild") ||
        (_elAttachShadow && !isNativeNamed(_elAttachShadow, "attachShadow"))
      ) {
        return { ok: false, tampered: true, frame: null, host: null, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
      }
      frame = _reflectApply(createElFn, document, ["iframe"]);
      if (_elAttachShadow) {
        host = _reflectApply(createElFn, document, ["div"]);
        const sd = _objCreate(null);
        sd.mode = "closed";
        const shadow = _reflectApply(_elAttachShadow, host, [sd]);
        if (!shadow || host.shadowRoot) {
          return { ok: false, tampered: true, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
        }
        _reflectApply(appendFn, parent, [host]);
        _reflectApply(appendFn, shadow, [frame]);
      } else {
        _reflectApply(appendFn, parent, [frame]);
      }
      if (_reflectApply(_hasOwn, frame, ["contentWindow"])) {
        return { ok: false, tampered: true, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
      }
      if (
        (_Document && (typeof Document !== "function" || Document !== _Document)) ||
        (_Node && (typeof Node !== "function" || Node !== _Node)) ||
        (_Element && (typeof Element !== "function" || Element !== _Element)) ||
        (_HTMLIFrameElement && (typeof HTMLIFrameElement !== "function" || HTMLIFrameElement !== _HTMLIFrameElement))
      ) {
        return { ok: false, tampered: true, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
      }
      const frameProto = _getProto(frame);
      if (_iframeProto && frameProto !== _iframeProto) {
        return { ok: false, tampered: true, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
      }
      const cwDesc = frameProto ? _getOwnPropertyDescriptor(frameProto, "contentWindow") : null;
      const cwGet = _iframeCwGet || (cwDesc && cwDesc.get) || null;
      if (typeof cwGet !== "function" || !cwDesc || cwDesc.get !== cwGet) {
        return { ok: false, tampered: true, frame, host, win: null, fToStr: null, fExec: null, createElFn, appendFn, cwGet: null, cleanup };
      }
      const win = _reflectApply(cwGet, frame, []);
      const fToStr = win && win.Function && win.Function.prototype && win.Function.prototype.toString;
      const fExec = win && win.RegExp && win.RegExp.prototype && win.RegExp.prototype.exec;
      if (!win || win === window || typeof fToStr !== "function" || typeof fExec !== "function" || fToStr === _fnToString || fExec === _regexExec) {
        return { ok: false, tampered: true, frame, host, win, fToStr: null, fExec: null, createElFn, appendFn, cwGet, cleanup };
      }
      if (
        (win.HTMLIFrameElement && (!_HTMLIFrameElement || typeof HTMLIFrameElement !== "function")) ||
        (win.Element && (!_Element || typeof Element !== "function")) ||
        (win.Element && win.Element.prototype && typeof win.Element.prototype.attachShadow === "function" && !_elAttachShadow)
      ) {
        return { ok: false, tampered: true, frame, host, win, fToStr: null, fExec: null, createElFn, appendFn, cwGet, cleanup };
      }
      if (!_elAttachShadow) {
        const probeDiv = _reflectApply(createElFn, document, ["div"]);
        if (probeDiv && typeof probeDiv.attachShadow === "function") {
          return { ok: false, tampered: true, frame, host, win, fToStr: null, fExec: null, createElFn, appendFn, cwGet, cleanup };
        }
      }
      if (!isNativeNamed(fToStr, "toString") || !isNativeNamed(fExec, "exec")) {
        return { ok: false, tampered: true, frame, host, win, fToStr, fExec, createElFn, appendFn, cwGet, cleanup };
      }
      return { ok: true, tampered: false, frame, host, win, fToStr, fExec, createElFn, appendFn, cwGet, cleanup };
    } catch (_) {
      return { ok: false, tampered: true, frame, host, win: null, fToStr: null, fExec: null, createElFn: null, appendFn: null, cwGet: null, cleanup };
    }
  }`;
  return compactGeneratedJs(`(() => {
  "use strict";
  if (typeof window === "undefined" || typeof document === "undefined") return;
  const _isEmbeddedUnified = typeof __VB_PRIVATE_REGISTER__ === "function";

  // Capture native intrinsics, constructors, prototypes & well-known Symbols at load time before any page/console code can tamper with them
  const _Object = Object;
  const _objProto = _Object.prototype;
  const _Array = Array;
  const _arrProto = _Array.prototype;
  const _RegExp = RegExp;
  const _regExpProto = _RegExp.prototype;
  const _Function = Function;
  const _fnProto = _Function.prototype;
  const _Reflect = Reflect;
  const _Date = Date;
  const _Math = Math;
  const _JSON = JSON;
  const _Symbol = typeof Symbol === "function" ? Symbol : null;
  const _symReplace = _Symbol ? _Symbol.replace : null;
  const _symSplit = _Symbol ? _Symbol.split : null;
  const _symMatch = _Symbol ? _Symbol.match : null;
  const _Error = Error;
  const _String = String;
  const _NativePromise = Promise;
  const _nativePromiseThen = _NativePromise.prototype.then;
  const _nativePromiseResolve = _NativePromise.resolve;
  const _Uint8Array = Uint8Array;
  const _Int32Array = Int32Array;
  const _MathAbs = _Math.abs;
  const _MathFloor = _Math.floor;
  const _MathRound = _Math.round;
  const _MathMin = _Math.min;
  const _MathMax = _Math.max;
  const _MathClz32 = _Math.clz32;
  const _Event = typeof Event === "function" ? Event : null;
  const _reflectApply = _Reflect.apply;
  const _fnCall = _fnProto.call;
  const _fnApply = _fnProto.apply;
  const _fnBind = _fnProto.bind;
  const _hasOwn = _objProto.hasOwnProperty;
  const _defineProperty = _Object.defineProperty;
  const _objCreate = _Object.create;
  const _defData = (obj, k, val, writable, configurable, enumerable) => {
    const d = _objCreate(null);
    d.value = val;
    if (writable !== undefined) d.writable = writable;
    if (configurable !== undefined) d.configurable = configurable;
    if (enumerable !== undefined) d.enumerable = enumerable;
    return _defineProperty(obj, k, d);
  };
  const _defGet = (obj, k, getter, configurable) => {
    const d = _objCreate(null);
    d.get = getter;
    if (configurable !== undefined) d.configurable = configurable;
    return _defineProperty(obj, k, d);
  };
  const _getOwnPropertyNames = _Object.getOwnPropertyNames;
  const _getOwnPropertyDescriptor = _Object.getOwnPropertyDescriptor;
  const _getProto = _Object.getPrototypeOf;
  const _isFrozen = _Object.isFrozen;
  const _fnToString = _fnProto.toString;
  const _regexTest = _regExpProto.test;
  const _regexExec = _regExpProto.exec;
  const _regexSymReplace = _symReplace ? _regExpProto[_symReplace] : null;
  const _strProto = _getProto("");
  const _strToLower = _strProto.toLowerCase;
  const _strToUpper = _strProto.toUpperCase;
  const _strStartsWith = _strProto.startsWith;
  const _strEndsWith = _strProto.endsWith;
  const _strTrim = _strProto.trim;
  const _strSplit = _strProto.split;
  const _strReplace = _strProto.replace;
  const _strSlice = _strProto.slice;
  const _strIncludes = _strProto.includes;
  const _strIndexOf = _strProto.indexOf;
  const _strCharCodeAt = _strProto.charCodeAt;
  const _strCharAt = _strProto.charAt;
  const rxTest = (re, s) => _reflectApply(_regexExec, re, [s]) !== null;
  const stripPipes = (raw) => {
    const s = _String(raw || "");
    if (_reflectApply(_strIndexOf, s, ["|"]) < 0) return s;
    let out = "";
    for (let i = 0; i < s.length; i++) {
      if (_reflectApply(_strCharCodeAt, s, [i]) !== 124) out += _reflectApply(_strCharAt, s, [i]);
    }
    return out;
  };
  const stripQueryHash = (raw) => {
    const s = _String(raw || "");
    const h = _reflectApply(_strIndexOf, s, ["#"]);
    const noHash = h >= 0 ? _reflectApply(_strSlice, s, [0, h]) : s;
    const q = _reflectApply(_strIndexOf, noHash, ["?"]);
    return q >= 0 ? _reflectApply(_strSlice, noHash, [0, q]) : noHash;
  };
  const _SymbolFor = _Symbol && typeof _Symbol.for === "function" ? _Symbol.for : null;
  const _textEncoder = new TextEncoder();
  const _encode = typeof TextEncoder !== "undefined" && TextEncoder.prototype ? TextEncoder.prototype.encode : null;
  const _encodeUtf8 = (s) => (_encode ? _reflectApply(_encode, _textEncoder, [_String(s)]) : _textEncoder.encode(_String(s)));
  const _jsonStringify = _JSON.stringify;
  const _jsonParse = _JSON.parse;
  const _Headers = typeof Headers === "function" ? Headers : null;
  const _hdrSet = _Headers && _Headers.prototype ? _Headers.prototype.set : null;
  const _hdrGet = _Headers && _Headers.prototype ? _Headers.prototype.get : null;
  const _hdrDelete = _Headers && _Headers.prototype ? _Headers.prototype.delete : null;
  const _subtle = typeof crypto !== "undefined" && crypto && crypto.subtle ? crypto.subtle : null;
  const _subtleDigest = _subtle && typeof _subtle.digest === "function" ? _subtle.digest : null;
  const _OacCtor = typeof OfflineAudioContext === "function" ? OfflineAudioContext : (typeof webkitOfflineAudioContext === "function" ? webkitOfflineAudioContext : null);
  const _oacStartRendering = _OacCtor && _OacCtor.prototype && typeof _OacCtor.prototype.startRendering === "function" ? _OacCtor.prototype.startRendering : null;
  const _Document = typeof Document === "function" ? Document : null;
  const _Node = typeof Node === "function" ? Node : null;
  const _HTMLIFrameElement = typeof HTMLIFrameElement === "function" ? HTMLIFrameElement : null;
  const _iframeProto = _HTMLIFrameElement ? _HTMLIFrameElement.prototype : null;
  const _Element = typeof Element === "function" ? Element : null;
  const _Navigator = typeof Navigator === "function" ? Navigator : null;
  const _HTMLCanvasElement = typeof HTMLCanvasElement === "function" ? HTMLCanvasElement : null;
  const _Canvas2D = typeof CanvasRenderingContext2D === "function" ? CanvasRenderingContext2D : null;
  const _WebGL1 = typeof WebGLRenderingContext === "function" ? WebGLRenderingContext : null;
  const _WebGL2 = typeof WebGL2RenderingContext === "function" ? WebGL2RenderingContext : null;
  const _docCreateElement = _Document && _Document.prototype ? _Document.prototype.createElement : null;
  const _nodeAppendChild = _Node && _Node.prototype ? _Node.prototype.appendChild : null;
  const _docElGet = _Document && _Document.prototype ? (_getOwnPropertyDescriptor(_Document.prototype, "documentElement")?.get || null) : null;
  const _iframeCwGet = _iframeProto ? (_getOwnPropertyDescriptor(_iframeProto, "contentWindow")?.get || null) : null;
  const _elGetAttr = _Element && _Element.prototype ? _Element.prototype.getAttribute : null;
  const _elAttachShadow = _Element && _Element.prototype && typeof _Element.prototype.attachShadow === "function" ? _Element.prototype.attachShadow : null;
  const _elRemove = _Element && _Element.prototype && typeof _Element.prototype.remove === "function" ? _Element.prototype.remove : null;
  const _isTrustedGet = _Event && _Event.prototype ? (_getOwnPropertyDescriptor(_Event.prototype, "isTrusted")?.get || null) : null;
  const _rawDateNow = Date.now;
  const _rawPerfNow =
    typeof Performance !== "undefined" && Performance.prototype && typeof Performance.prototype.now === "function"
      ? Performance.prototype.now
      : (typeof performance !== "undefined" && typeof performance.now === "function" ? performance.now : null);
  const _perfNow = () => (_rawPerfNow ? _reflectApply(_rawPerfNow, performance, []) : _reflectApply(_rawDateNow, Date, []));
  // Unified native-code regex pair (replaces ~58 per-method RegExp literals; immune to .bind(null) & RegExp hooks!)
  const _NATIVE_FN_RE = /^function\\s+(\\[Symbol\\.[A-Za-z]+\\]|[A-Za-z0-9_$]+)\\s*\\(\\s*\\)\\s*\\{\\s*\\[native code\\]\\s*\\}$/;
  const _NATIVE_GET_RE = /^function\\s+(?:get\\s+)?(\\[Symbol\\.[A-Za-z]+\\]|[A-Za-z0-9_$]+)\\s*\\(\\s*\\)\\s*\\{\\s*\\[native code\\]\\s*\\}$/;
  const _ARR_IDX_RE = /^(?:0|[1-9]\\d*)$/;
  const isNativeNamed = (fn, name, toStrFn = _fnToString, execFn = _regexExec, applyFn = _reflectApply, isGetter = false) => {
    if (typeof fn !== "function") return false;
    const m = applyFn(execFn, isGetter ? _NATIVE_GET_RE : _NATIVE_FN_RE, [applyFn(toStrFn, fn, [])]);
    return m !== null && m[1] === name;
  };
  const hasProtoIndexPollution = (getNamesFn = _getOwnPropertyNames, execFn = _regexExec, applyFn = _reflectApply) => {
    const ap = getNamesFn(_arrProto);
    for (let i = 0; i < ap.length; i++) {
      if (applyFn(execFn, _ARR_IDX_RE, [ap[i]]) !== null) return true;
    }
    const op = getNamesFn(_objProto);
    for (let i = 0; i < op.length; i++) {
      if (applyFn(execFn, _ARR_IDX_RE, [op[i]]) !== null) return true;
    }
    return false;
  };
  const _SUS_AUTOMATION_RE = /^(\\$?cdc_|__playwright|__pw_manual|__pwInitScripts|__puppeteer|__webdriver|_selenium|_Selenium|__fxdriver|__driver_|domAutomation|callPhantom|_phantom|__nightmare|__lastWatir)/i;
  const _FAST_AUTOMATION_KEYS = [
    "__playwright", "__pw_manual", "__pwInitScripts", "__puppeteer_evaluation_script__",
    "__webdriver_evaluate", "__selenium_evaluate", "__webdriver_script_function",
    "__fxdriver_evaluate", "__driver_evaluate", "domAutomation", "domAutomationController",
    "callPhantom", "_phantom", "__nightmare", "__lastWatirAlert", "_Selenium_IDE_Recorder",
  ];
  const _rawConsoleDebug = typeof console !== "undefined" && typeof console.debug === "function" ? console.debug : null;
  const _consoleDebug = _rawConsoleDebug && _rawConsoleDebug.name === "debug" && (() => {
    try { return isNativeNamed(_rawConsoleDebug, "debug"); } catch (_) { return false; }
  })() ? _reflectApply(_fnBind, _rawConsoleDebug, [console]) : null;
  const _symbolForTampered = !_SymbolFor || _SymbolFor.name !== "for" || (() => {
    try { return !isNativeNamed(_SymbolFor, "for"); } catch (_) { return true; }
  })();
  let _bridgeTampered = _symbolForTampered;

  const BASE = ${escapeInlineJson(normBase)};
  const VERSION = ${escapeInlineJson(pkgVersion)};
  const POLICY_LOCKED = ${escapeInlineJson(policyLocked)};
  const PLAYGROUND_PATH = ${escapeInlineJson(normPlayPath)};
  const SUSPICIOUS_CLICK_TTL_MS = ${susClickTtl};

  const _readAttr = (el, name) => {
    if (!el) return null;
    try {
      if (_elGetAttr) return _reflectApply(_elGetAttr, el, [name]);
      return typeof el.getAttribute === "function" ? el.getAttribute(name) : null;
    } catch (_) { return null; }
  };
  const scriptEl = document.currentScript;
  const BRIDGE_TOKEN = _readAttr(scriptEl, "data-vb-bridge") || "";
  const attrUni = _readAttr(scriptEl, "data-unified");
  const UNIFIED_MODE = ${escapeInlineJson(Boolean(unified))} || (attrUni !== null && /^(true|1)$/i.test(String(attrUni).trim()));
  let _legitPreloadedStandaloneGate = false;

  // Fail-closed pre-existing global & customElement check (runs in BOTH standalone AND embedded unified bundles!)
  // Benign coexistence cases:
  // (1) Standalone unified /__veilbreak/gate.js (or data-unified="true") running AFTER unified guard.js mounted frozen VeilBreak(unified:true) + ProxySnare -> clean exit!
  // (2) Embedded unified bundle running AFTER a verified same-origin /gate.js (confirmed via Resource Timing) mounted matching frozen VeilBreak + __VEILBREAK_INTERNAL__ (unified:true)!
  try {
    const existingVbDesc = _getOwnPropertyDescriptor(window, "VeilBreak");
    const existingCe = typeof customElements !== "undefined" ? customElements.get("veil-break") : null;
    const existingIntDesc = _SymbolFor ? _getOwnPropertyDescriptor(window, _SymbolFor("__VEILBREAK_INTERNAL__")) : null;
    if (
      !_isEmbeddedUnified &&
      UNIFIED_MODE &&
      existingVbDesc &&
      existingVbDesc.configurable === false &&
      existingVbDesc.writable === false &&
      existingVbDesc.value &&
      _isFrozen(existingVbDesc.value) &&
      existingVbDesc.value.unified === true &&
      _getOwnPropertyDescriptor(window, "ProxySnare")
    ) {
      return;
    }
    if (existingVbDesc || existingCe || existingIntDesc) {
      let legitCoexist = false;
      if (
        _isEmbeddedUnified &&
        existingVbDesc &&
        existingVbDesc.configurable === false &&
        existingVbDesc.writable === false &&
        existingVbDesc.value &&
        _isFrozen(existingVbDesc.value) &&
        existingVbDesc.value.unified === true &&
        existingIntDesc &&
        existingIntDesc.configurable === false &&
        existingIntDesc.writable === false &&
        existingIntDesc.value === existingVbDesc.value
      ) {
        try {
          const perfGet =
            typeof Performance !== "undefined" && Performance.prototype && typeof Performance.prototype.getEntriesByType === "function"
              ? Performance.prototype.getEntriesByType
              : (typeof performance !== "undefined" && typeof performance.getEntriesByType === "function" ? performance.getEntriesByType : null);
          const curOrig = window.location && window.location.origin ? window.location.origin : "";
          const ents = perfGet && typeof performance !== "undefined" ? (_reflectApply(perfGet, performance, ["resource"]) || []) : [];
          const hasSameOrigGateScriptEl = () => {
            try {
              if (typeof document === "undefined" || typeof document.querySelectorAll !== "function") return false;
              const els = document.querySelectorAll("script[src]");
              for (let j = 0; j < els.length; j++) {
                const rawSrc = _elGetAttr ? _reflectApply(_elGetAttr, els[j], ["src"]) : els[j].getAttribute("src");
                if (!rawSrc) continue;
                try {
                  const u = new URL(rawSrc, (document.baseURI || (window.location && window.location.href) || ""));
                  const cu = stripQueryHash(u.href);
                  if (curOrig && _reflectApply(_strStartsWith, cu, [curOrig + "/"]) && _reflectApply(_strEndsWith, cu, ["/gate.js"])) return true;
                } catch (_) {}
              }
            } catch (_) {}
            return false;
          };
          for (let i = 0; i < ents.length; i++) {
            const e = ents[i];
            if (!e || typeof e.name !== "string") continue;
            const it = typeof e.initiatorType === "string" ? e.initiatorType : "";
            // Match ProxySnare's isVerifiedGateResourceEntry: allow empty initiatorType (Safari cached scripts), require executed <script src=".../gate.js"> for link preloads, reject 3xx!
            if (it && it !== "script" && it !== "link" && it !== "other") continue;
            if (it === "link" && !hasSameOrigGateScriptEl()) continue;
            const n = stripQueryHash(e.name);
            if (curOrig && _reflectApply(_strStartsWith, n, [curOrig + "/"]) && _reflectApply(_strEndsWith, n, ["/gate.js"])) {
              const stOk = typeof e.responseStatus === "number" ? ((e.responseStatus >= 200 && e.responseStatus < 300) || e.responseStatus === 304) : true;
              if (stOk && (typeof e.decodedBodySize !== "number" || e.decodedBodySize > 0 || e.transferSize > 0 || e.encodedBodySize > 0 || e.responseStatus === 200 || e.responseStatus === 304 || (typeof e.responseStatus !== "number" && typeof e.responseEnd === "number" && e.responseEnd > 0 && typeof e.duration === "number" && e.duration >= 0))) {
                legitCoexist = true;
                break;
              }
            }
          }
        } catch (_) {}
      }
      if (legitCoexist) {
        // NEVER register untrusted global window.VeilBreak into private __VB_PRIVATE_REGISTER__ or return early!
        // Always execute embedded lexical probes and register our freshly created lexical vbApi (only suppress global redefine tamper!).
        _legitPreloadedStandaloneGate = true;
        try {
          if (typeof console !== "undefined" && typeof console.warn === "function") {
            console.warn("[VeilBreak] Duplicate /__veilbreak/gate.js detected alongside unified /__proxysnare/guard.js — remove the standalone gate.js <script> tag to avoid duplicate probes and split evaluateClick() state.");
          }
        } catch (_) {}
      } else {
        _bridgeTampered = true;
        if (_SymbolFor) {
          try { _defData(window, _SymbolFor("__VB_BRIDGE_TAMPERED__"), true, false, false, false); } catch (_) {}
        }
      }
    }
  } catch (_) {
    _bridgeTampered = true;
  }

  const VALID_MODES = _objCreate(null);
  VALID_MODES.off = 1;
  VALID_MODES.monitor = 1;
  VALID_MODES.balanced = 1;
  VALID_MODES.strict = 1;
  VALID_MODES.paranoid = 1;
  const MODE_RANK = _objCreate(null);
  MODE_RANK.off = 0;
  MODE_RANK.monitor = 1;
  MODE_RANK.balanced = 2;
  MODE_RANK.strict = 3;
  MODE_RANK.paranoid = 4;

  function normalizeClientMode(m, fallback = "strict") {
    const s = _reflectApply(_strToLower, _reflectApply(_strTrim, _String(m || fallback), []), []);
    if (s === "observe") return "monitor";
    return _reflectApply(_hasOwn, VALID_MODES, [s]) && VALID_MODES[s] === 1 ? s : fallback;
  }

  const SERVER_MODE = normalizeClientMode(${escapeInlineJson(defaultMode)}, "strict");
  const attrModeRaw = _readAttr(scriptEl, "data-mode");
  const attrMode = attrModeRaw ? normalizeClientMode(attrModeRaw, SERVER_MODE) : SERVER_MODE;
  // In SRI / unified bundles, untrusted <script data-*> attributes may tighten policy but NEVER weaken server-compiled policy!
  const DEFAULT_MODE = POLICY_LOCKED && MODE_RANK[attrMode] < MODE_RANK[SERVER_MODE] ? SERVER_MODE : attrMode;

  const SERVER_AUTO_BLOCK = ${escapeInlineJson(Boolean(autoBlockPage))};
  const attrBlock = _readAttr(scriptEl, "data-block-page");
  const normBlock = attrBlock === null ? "" : _reflectApply(_strToLower, _reflectApply(_strTrim, _String(attrBlock), []), []);
  const rawCurPath = (window.location && window.location.pathname) || "/";
  let curPathEnd = rawCurPath.length;
  while (curPathEnd > 1 && rawCurPath.charCodeAt(curPathEnd - 1) === 47) curPathEnd--;
  const curNormPath = (curPathEnd === rawCurPath.length ? rawCurPath : rawCurPath.slice(0, curPathEnd)) || "/";
  const allowBlockDisable = !POLICY_LOCKED || (Boolean(PLAYGROUND_PATH) && curNormPath === PLAYGROUND_PATH);
  const AUTO_BLOCK =
    (normBlock === "false" || normBlock === "0") && allowBlockDisable
      ? false
      : (normBlock === "true" || normBlock === "1" || SERVER_AUTO_BLOCK);

  const SERVER_ANTI_CDP = ${escapeInlineJson(antiCdp !== false)};
  const attrCdp = _readAttr(scriptEl, "data-anti-cdp");
  const normCdp = attrCdp === null ? "" : _reflectApply(_strToLower, _reflectApply(_strTrim, _String(attrCdp), []), []);
  const DEFAULT_ANTI_CDP =
    (normCdp === "false" || normCdp === "0") && !(POLICY_LOCKED && SERVER_ANTI_CDP)
      ? false
      : (normCdp === "true" || normCdp === "1" ? true : SERVER_ANTI_CDP);

  const SERVER_ALLOW_DEVTOOLS = ${escapeInlineJson(Boolean(allowDevTools))};
  const attrDev = _readAttr(scriptEl, "data-allow-devtools");
  const normDev = attrDev === null ? "" : _reflectApply(_strToLower, _reflectApply(_strTrim, _String(attrDev), []), []);
  const DEFAULT_ALLOW_DEVTOOLS =
    (normDev === "true" || normDev === "1") && !(POLICY_LOCKED && !SERVER_ALLOW_DEVTOOLS)
      ? true
      : (normDev === "false" || normDev === "0" ? false : SERVER_ALLOW_DEVTOOLS);
  ${standalonePathHelpers}

  function toAsciiJson(obj) {
    return _reflectApply(_jsonStringify, JSON, [obj]).replace(/[\\u0080-\\uffff]/g, (c) => "\\\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  }

  ${standaloneRulesAndFetch}
  const _WeakRef = typeof WeakRef === "function" ? WeakRef : null;

  // Stage-2 pointer kinematics observer (WeakMap-cached per MouseEvent; VoiceOver/NVDA/JAWS screen-reader safe!)
  const kin = { moves: 0, zeroMoves: 0, downTs: 0, pointerType: "mouse", lastClick: null, lastTrustedAnyTs: 0, consecutiveTeleports: 0, lastTeleportTs: 0, lastTeleportEl: null };
  const capturedEvents = new WeakMap();
  window.addEventListener("pointermove", (e) => {
    kin.pointerType = e.pointerType || kin.pointerType;
    kin.moves++;
    if (e.movementX === 0 && e.movementY === 0) kin.zeroMoves++;
  }, { capture: true, passive: true });
  const _fwdPsGesture = _isEmbeddedUnified && typeof __PS_MARK_GESTURE__ === "function" ? __PS_MARK_GESTURE__ : null;
  window.addEventListener("pointerdown", (e) => {
    if (_fwdPsGesture) _fwdPsGesture(e);
    if (e && e.isTrusted === true) kin.lastTrustedAnyTs = _perfNow();
    kin.pointerType = e.pointerType || "mouse";
    kin.downTs = _perfNow();
  }, { capture: true, passive: true });
  window.addEventListener("keydown", (e) => {
    if (_fwdPsGesture) _fwdPsGesture(e);
    if (e && e.isTrusted === true) {
      kin.lastTrustedAnyTs = _perfNow();
      kin.lastClick = null;
    }
    kin.consecutiveTeleports = 0;
  }, { capture: true, passive: true });
  window.addEventListener("focusin", () => {
    kin.consecutiveTeleports = 0;
  }, { capture: true, passive: true });
  for (const gestEvt of ["change", "input", "submit", "touchstart", "pointerup", "keyup", "compositionend"]) {
    window.addEventListener(gestEvt, (e) => {
      if (_fwdPsGesture) _fwdPsGesture(e);
      if (e && e.isTrusted === true) {
        const nowTs = _perfNow();
        // Preserve recent click kinematics across click-derived form submit / checkbox-radio change+input events
        // so form onSubmit/onChange handlers still report teleport clicks (ik=1), while independent typing/keyboard still clears stale clicks!
        const isClickDerived =
          (gestEvt === "submit" || gestEvt === "change" || gestEvt === "input") &&
          Boolean(kin.lastClick && (nowTs - kin.lastClick.ts) < 250);
        if (!isClickDerived) {
          kin.lastTrustedAnyTs = nowTs;
          if (gestEvt !== "pointerup") kin.lastClick = null;
        }
      }
    }, { capture: true, passive: true });
  }

  function isInteractiveControl(el) {
    if (!el || typeof el.closest !== "function") return false;
    return Boolean(el.closest('button, a, [role="button"], input[type="submit"], input[type="button"]'));
  }

  function isElementVisible(el) {
    if (!el || typeof el.getClientRects !== "function" || typeof el.getBoundingClientRect !== "function") return false;
    try {
      const st = window.getComputedStyle(el);
      if (st) {
        if (st.visibility === "hidden" || st.display === "none") return false;
        if (st.opacity === "0" || parseFloat(st.opacity) === 0) return false;
        if (st.clip === "rect(0px, 0px, 0px, 0px)" || (st.clipPath && st.clipPath.includes("50%"))) return false;
      }
      if (el.getClientRects().length === 0) return false;
      const r = el.getBoundingClientRect();
      if (r.width <= 1 && r.height <= 1) return false;
      if (r.right <= 0 || r.bottom <= 0 || r.left >= window.innerWidth || r.top >= window.innerHeight) return false;
      return true;
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
            _MathAbs(e.clientX - (r.left + r.width / 2)) < 0.75 &&
            _MathAbs(e.clientY - (r.top + r.height / 2)) < 0.75
          );
        }
      }
    } catch (_) {}
    return false;
  }

  function captureInteraction(e, targetEl, explicit = false) {
    const el = targetEl || (e && e.currentTarget) || (e && e.target);
    const isGenuineEvent = Boolean(_Event && e instanceof _Event);
    let base = e && typeof e === "object" ? capturedEvents.get(e) : null;
    const wasCaptured = Boolean(base);
    if (!base) {
      const upTs = _perfNow();
      let trustedFlag = false;
      if (isGenuineEvent) {
        try {
          trustedFlag = _isTrustedGet ? Boolean(_reflectApply(_isTrustedGet, e, [])) : Boolean(e.isTrusted);
        } catch (_) {
          trustedFlag = false;
        }
      }
      base = {
        isTrusted: trustedFlag,
        detail: Number((e && e.detail) ?? 0),
        pointerType: (e && e.pointerType) || kin.pointerType || "mouse",
        pointerMoves: kin.moves,
        zeroMoveCount: kin.zeroMoves,
        dwellMs: kin.downTs > 0 ? Number((upTs - kin.downTs).toFixed(2)) : -1,
        ts: upTs,
      };
      if (isGenuineEvent) capturedEvents.set(e, base);
      if (!explicit || isGenuineEvent) {
        kin.moves = 0;
        kin.zeroMoves = 0;
        kin.downTs = 0;
      }
    }
    const hitCenter = computeHitCenter(e, el);
    const pTypeBase = _reflectApply(_strToLower, _String(base.pointerType || "mouse"), []);
    const isTeleportLike =
      base.isTrusted === true &&
      base.detail >= 1 &&
      pTypeBase !== "touch" &&
      pTypeBase !== "pen" &&
      hitCenter &&
      ((base.pointerMoves <= 3 && base.dwellMs > 0 && base.dwellMs < 12) ||
       (base.pointerMoves === 0 && base.dwellMs > 0 && base.dwellMs < 8));
    if (!explicit) {
      if (isTeleportLike) {
        const prevEl = kin.lastTeleportEl ? (_WeakRef ? kin.lastTeleportEl.deref() : kin.lastTeleportEl) : null;
        if (kin.lastTeleportTs > 0 && base.ts - kin.lastTeleportTs > 4_000) {
          kin.consecutiveTeleports = 1;
        } else if (el && el !== prevEl) {
          kin.consecutiveTeleports++;
        } else if (kin.consecutiveTeleports === 0) {
          kin.consecutiveTeleports = 1;
        }
        kin.lastTeleportTs = base.ts;
        kin.lastTeleportEl = el ? (_WeakRef ? new _WeakRef(el) : el) : null;
      } else if (base.isTrusted) {
        kin.consecutiveTeleports = 0;
        kin.lastTeleportTs = 0;
        kin.lastTeleportEl = null;
      }
    }
    const info = {
      ...base,
      hitExactCenter: hitCenter,
      passive: !explicit,
      consecutiveTeleports: kin.consecutiveTeleports,
    };
    // Only capture-phase native trusted events may advance lastTrustedAnyTs (never public VeilBreak.evaluateClick() calls!)
    if (!explicit && info.isTrusted) {
      kin.lastTrustedAnyTs = info.ts;
      // Any genuine non-teleport trusted click (even on <div onClick>, <label>, <input>) clears any prior stale suspicious click!
      if (!isTeleportLike && !isInteractiveControl(el)) {
        kin.lastClick = null;
      }
    }
    const precededByHumanGesture = !info.isTrusted && kin.lastTrustedAnyTs > 0 && (info.ts - kin.lastTrustedAnyTs) <= 1_500;
    const prevWasSuspicious = Boolean(kin.lastClick && (!kin.lastClick.isTrusted || kin.lastClick.consecutiveTeleports > 0));
    if (
      (explicit && (wasCaptured || isGenuineEvent) && (!prevWasSuspicious || !info.isTrusted)) ||
      (!explicit && info.isTrusted && isInteractiveControl(el)) ||
      (!explicit && !info.isTrusted && !precededByHumanGesture && isInteractiveControl(el) && isElementVisible(el))
    ) {
      kin.lastClick = info;
    }
    return info;
  }

  function getFreshLastClick(consume = false) {
    if (!kin.lastClick) return null;
    // If any newer genuine human gesture fired AFTER the stored click, it supersedes stale programmatic clicks!
    if (kin.lastTrustedAnyTs > (kin.lastClick.ts || 0)) {
      kin.lastClick = null;
      return null;
    }
    // Scope passive programmatic .click() correlation tightly (250ms) so UI-library mount clicks never taint unrelated SPA hydration POSTs;
    // retain full SUSPICIOUS_CLICK_TTL_MS (15s) for repeated teleports (>= 2) or explicit evaluateClick() verdicts!
    const isPassiveUntrustedOnly = Boolean(kin.lastClick.passive && kin.lastClick.isTrusted === false && (kin.lastClick.consecutiveTeleports || 0) < 2);
    const isLongSuspicious = (!kin.lastClick.passive && kin.lastClick.isTrusted === false) || (kin.lastClick.consecutiveTeleports || 0) >= 2;
    const ttlMs = isPassiveUntrustedOnly ? 250 : (isLongSuspicious ? SUSPICIOUS_CLICK_TTL_MS : 1_500);
    if (_perfNow() - (kin.lastClick.ts || 0) > ttlMs) {
      kin.lastClick = null;
      if (!_WeakRef && kin.lastTeleportEl && _perfNow() - kin.lastTeleportTs > 4_000) kin.lastTeleportEl = null;
      return null;
    }
    const snap = Object.freeze({ ...kin.lastClick });
    if (consume) kin.lastClick = null;
    return snap;
  }

  function thresholdFor(mode) {
    const m = normalizeClientMode(mode, "strict");
    if (m === "off" || m === "monitor") return Infinity;
    if (m === "balanced") return 4;
    return 2;
  }

  function evaluateInteractionLocal(info, mode, evalTs = null) {
    const m = normalizeClientMode(mode, DEFAULT_MODE);
    const threshold = thresholdFor(m);
    if (m === "off" || !info) return { ok: true, blocked: false, score: 0, threshold, mode: m, reasons: [], details: info || null };
    let score = 0;
    const reasons = [];
    const pType = _reflectApply(_strToLower, _String(info.pointerType || "mouse"), []);
    const refTs = typeof evalTs === "number" && Number.isFinite(evalTs) ? evalTs : _perfNow();
    if (info.isTrusted === false) {
      const untrustedFresh = !info.passive || !info.ts || (refTs >= info.ts && (refTs - info.ts) <= 250);
      if (untrustedFresh) {
        score += 6;
        reasons.push("UNTRUSTED_SYNTHETIC_CLICK");
      }
    } else if (info.isTrusted === true && info.detail >= 1 && pType !== "touch" && pType !== "pen") {
      // Passive global capture skips solo-blocking in balanced mode, skips AXPress/NVDA dwellMs<=0, and requires >= 2 rapid distinct-target teleports without keyboard/focus navigation
      const allowTeleport = !info.passive || (m !== "balanced" && (info.consecutiveTeleports || 0) >= 2 && info.dwellMs > 0);
      if (allowTeleport && info.pointerMoves <= 3 && info.dwellMs > 0 && info.dwellMs < 12 && info.hitExactCenter) {
        score += 4;
        reasons.push("TELEPORT_CLICK_PHYSICS");
      }
    }
    const blocked = m !== "monitor" && score >= threshold;
    return { ok: !blocked, blocked, score, threshold, mode: m, reasons, details: info };
  }

  window.addEventListener("click", (e) => {
    if (_fwdPsGesture) _fwdPsGesture(e);
    captureInteraction(e, e.target, false);
  }, { capture: true, passive: true });

  const _HEX = "0123456789abcdef";
  function toHex(buf) {
    const u = buf instanceof _Uint8Array ? buf : new _Uint8Array(buf);
    let out = "";
    for (let i = 0; i < u.length; i++) {
      const b = u[i];
      out += _HEX[b >>> 4] + _HEX[b & 15];
    }
    return out;
  }

  ` + (omitFallbackSha256 ? `
  function sha256FallbackHex(str) {
    return typeof __PS_SHA256_HEX__ === "function" ? __PS_SHA256_HEX__(str) : "";
  }` : `
  // Single DataView-free, _Uint8Array/_Int32Array-only FIPS 180-4 SHA-256 kernel (zero DataView/Uint8Array tamper surface!)
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
  const SHA256_W = new _Int32Array(64);
  const SHA256_OUT = new _Int32Array(8);
  function padSha256Into(buf, byteLen) {
    const padLen = ((byteLen + 9 + 63) >> 6) << 6;
    buf[byteLen] = 0x80;
    for (let z = byteLen + 1; z < padLen - 8; z++) buf[z] = 0;
    const bitLen = byteLen * 8;
    const hi = _MathFloor(bitLen / 0x100000000) >>> 0;
    const lo = bitLen >>> 0;
    buf[padLen - 8] = (hi >>> 24) & 255;
    buf[padLen - 7] = (hi >>> 16) & 255;
    buf[padLen - 6] = (hi >>> 8) & 255;
    buf[padLen - 5] = hi & 255;
    buf[padLen - 4] = (lo >>> 24) & 255;
    buf[padLen - 3] = (lo >>> 16) & 255;
    buf[padLen - 2] = (lo >>> 8) & 255;
    buf[padLen - 1] = lo & 255;
    return padLen;
  }
  function sha256CompressPadded(buf, padLen) {
    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    for (let o = 0; o < padLen; o += 64) {
      for (let i = 0; i < 16; i++) {
        const p = o + (i << 2);
        SHA256_W[i] = (buf[p] << 24) | (buf[p + 1] << 16) | (buf[p + 2] << 8) | buf[p + 3];
      }
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
    SHA256_OUT[0] = h0; SHA256_OUT[1] = h1; SHA256_OUT[2] = h2; SHA256_OUT[3] = h3;
    SHA256_OUT[4] = h4; SHA256_OUT[5] = h5; SHA256_OUT[6] = h6; SHA256_OUT[7] = h7;
    return SHA256_OUT;
  }
  function sha256Words(str) {
    const bytes = _encodeUtf8(str);
    const padLen = ((bytes.length + 9 + 63) >> 6) << 6;
    const m = new _Uint8Array(padLen);
    for (let i = 0; i < bytes.length; i++) m[i] = bytes[i];
    padSha256Into(m, bytes.length);
    return sha256CompressPadded(m, padLen);
  }

  function sha256FallbackHex(str) {
    const w = sha256Words(str);
    let out = "";
    for (let i = 0; i < 8; i++) {
      const v = w[i] >>> 0;
      out += _HEX[(v >>> 28) & 15] + _HEX[(v >>> 24) & 15] + _HEX[(v >>> 20) & 15] + _HEX[(v >>> 16) & 15]
           + _HEX[(v >>> 12) & 15] + _HEX[(v >>> 8) & 15] + _HEX[(v >>> 4) & 15] + _HEX[v & 15];
    }
    return out;
  }`) + `

  async function sha256Hex(str) {
    if (_subtle && _subtleDigest) {
      try {
        const box = await new _NativePromise((resolve, reject) => {
          _reflectApply(_nativePromiseThen, _reflectApply(_subtleDigest, _subtle, ["SHA-256", _encodeUtf8(str)]), [
            (ab) => { const b = _objCreate(null); b.v = ab; resolve(b); },
            reject,
          ]);
        });
        return toHex(box.v);
      } catch (_) {}
    }
    return typeof __PS_SHA256_HEX__ === "function" ? __PS_SHA256_HEX__(str) : sha256FallbackHex(str);
  }` + (!needFullPathAndPow ? `
  function solveTicketPow() { return "0"; }` : `

  function hasLeadingZeroBits(words, bits) {
    let rem = bits;
    for (let i = 0; i < words.length && rem > 0; i++) {
      const w = words[i] >>> 0;
      if (rem >= 32) {
        if (w !== 0) return false;
        rem -= 32;
      } else {
        return _MathClz32(w) >= rem;
      }
    }
    return true;
  }

  const _POW_SCRATCH = new _Uint8Array(128);
  const _B36_CODES = [
    48,49,50,51,52,53,54,55,56,57,
    97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122
  ];
  const _B36_TMP = new _Uint8Array(12);
  function solveTicketPow(ticket, challenge, difficulty) {
    if (!difficulty || difficulty <= 0 || !ticket || !challenge) return "0";
    const prefix = "VB_POW_V2|" + ticket + "|" + challenge + "|";
    const pLen = prefix.length;
    let asciiPrefix = pLen <= 104;
    if (asciiPrefix) {
      for (let j = 0; j < pLen; j++) {
        const ch = _reflectApply(_strCharCodeAt, prefix, [j]);
        if (ch > 0x7f) { asciiPrefix = false; break; }
        _POW_SCRATCH[j] = ch;
      }
    }
    if (asciiPrefix && difficulty <= 32) {
      for (let i = 0; i < 5_000_000; i++) {
        let n = i;
        let nLen = 0;
        if (n === 0) {
          _POW_SCRATCH[pLen] = 48;
          nLen = 1;
        } else {
          while (n > 0) {
            const q = (n / 36) | 0;
            _B36_TMP[nLen++] = _B36_CODES[n - q * 36];
            n = q;
          }
          if (pLen + nLen > 119) {
            const nonce = i.toString(36);
            if (hasLeadingZeroBits(sha256Words(prefix + nonce), difficulty)) return nonce;
            continue;
          }
          for (let j = 0; j < nLen; j++) _POW_SCRATCH[pLen + j] = _B36_TMP[nLen - 1 - j];
        }
        const padLen = padSha256Into(_POW_SCRATCH, pLen + nLen);
        const h0 = sha256CompressPadded(_POW_SCRATCH, padLen)[0] >>> 0;
        if (_MathClz32(h0) >= difficulty) return i.toString(36);
      }
      return "0";
    }
    for (let i = 0; i < 5_000_000; i++) {
      const nonce = i.toString(36);
      if (hasLeadingZeroBits(sha256Words(prefix + nonce), difficulty)) return nonce;
    }
    return "0";
  }`) + `

  function withTimeout(promise, ms, fallback = null) {
    return new _NativePromise((resolve) => {
      let done = false;
      const box = (v) => { const b = _objCreate(null); b.v = v; return b; };
      const tm = setTimeout(() => { if (!done) { done = true; resolve(box(fallback)); } }, ms);
      _reflectApply(_nativePromiseThen, _reflectApply(_nativePromiseResolve, _NativePromise, [promise]), [
        (v) => { if (!done) { done = true; clearTimeout(tm); resolve(box(v)); } },
        () => { if (!done) { done = true; clearTimeout(tm); resolve(box(fallback)); } },
      ]);
    });
  }

  let _lastIframeConsoleTs = -1;
  let _lastIframeConsoleRes = { tripped: false, consoleTampered: false };
  // Lightweight 6-intrinsic fresh iframe helper isolated inside a closed ShadowRoot (defeats synchronous Chromium/WebKit
  // about:blank capture-phase 'load' listeners because load has composed:false, and avoids unverified frame.style access!).
${openBaseRealmCode}

  // Full cold-boot cross-realm verification (reuses openBaseFreshRealm + checks ~75 JS/DOM/Symbol intrinsics using untouched fWin.Reflect.apply!)
  function openVerifiedFreshRealm() {
    const base = openBaseFreshRealm();
    if (!base.ok) return base;
    const { frame, host, win, fToStr, fExec, createElFn, appendFn, cwGet, cleanup } = base;
    try {
      if (
        Object !== _Object ||
        Array !== _Array ||
        RegExp !== _RegExp ||
        Function !== _Function ||
        Reflect !== _Reflect ||
        Date !== _Date ||
        Math !== _Math ||
        JSON !== _JSON ||
        String !== _String ||
        Uint8Array !== _Uint8Array ||
        Int32Array !== _Int32Array ||
        _Object.prototype !== _objProto ||
        _Array.prototype !== _arrProto ||
        _RegExp.prototype !== _regExpProto ||
        _Function.prototype !== _fnProto ||
        (_Symbol && (typeof Symbol !== "function" || Symbol !== _Symbol)) ||
        (win && win.Event && (!_Event || typeof Event !== "function" || Event !== _Event))
      ) {
        return { ok: false, tampered: true, frame, host, win, fToStr, fExec, cleanup };
      }
      if (("then" in _objProto) || ("get" in _objProto) || ("set" in _objProto) || ("value" in _objProto) || ("writable" in _objProto)) {
        return { ok: false, tampered: true, frame, host, win, fToStr, fExec, cleanup };
      }
      if (_symSplit && (_Symbol.split !== _symSplit || (_symSplit in _strProto))) {
        return { ok: false, tampered: true, frame, host, win, fToStr, fExec, cleanup };
      }
      if (_symReplace && (_Symbol.replace !== _symReplace || (_symReplace in _strProto))) {
        return { ok: false, tampered: true, frame, host, win, fToStr, fExec, cleanup };
      }
      if (_symMatch && (_Symbol.match !== _symMatch || (_symMatch in _strProto))) {
        return { ok: false, tampered: true, frame, host, win, fToStr, fExec, cleanup };
      }
      const fApply = win && win.Reflect && typeof win.Reflect.apply === "function" ? win.Reflect.apply : _reflectApply;
      if (win && win.Reflect && typeof win.Reflect.apply === "function") {
        if (fApply === _reflectApply || !isNativeNamed(fApply, "apply", fToStr, fExec, fApply)) {
          return { ok: false, tampered: true, frame, host, win, fToStr, fExec, cleanup };
        }
      }
      if (hasProtoIndexPollution(_getOwnPropertyNames, fExec, fApply)) {
        return { ok: false, tampered: true, frame, host, win, fToStr, fExec, cleanup };
      }
      const baseNative = [
        [_reflectApply, "apply"],
        [Reflect.apply, "apply"],
        [_Error, "Error"],
        [_String, "String"],
        [String, "String"],
        [_NativePromise, "Promise"],
        [_nativePromiseThen, "then"],
        [_nativePromiseResolve, "resolve"],
        [_objCreate, "create"],
        [Object.create, "create"],
        [_Uint8Array, "Uint8Array"],
        [Uint8Array, "Uint8Array"],
        [_Int32Array, "Int32Array"],
        [_rawDateNow, "now"],
        [Date.now, "now"],
        [_strToLower, "toLowerCase"],
        [String.prototype.toLowerCase, "toLowerCase"],
        [_strToUpper, "toUpperCase"],
        [String.prototype.toUpperCase, "toUpperCase"],
        [_strStartsWith, "startsWith"],
        [String.prototype.startsWith, "startsWith"],
        [_strEndsWith, "endsWith"],
        [String.prototype.endsWith, "endsWith"],
        [_strTrim, "trim"],
        [String.prototype.trim, "trim"],
        [_strSplit, "split"],
        [String.prototype.split, "split"],
        [_strReplace, "replace"],
        [String.prototype.replace, "replace"],
        [_strSlice, "slice"],
        [String.prototype.slice, "slice"],
        [_strIncludes, "includes"],
        [String.prototype.includes, "includes"],
        [_strIndexOf, "indexOf"],
        [String.prototype.indexOf, "indexOf"],
        [_strCharCodeAt, "charCodeAt"],
        [String.prototype.charCodeAt, "charCodeAt"],
        [_strCharAt, "charAt"],
        [String.prototype.charAt, "charAt"],
        [_MathAbs, "abs"],
        [Math.abs, "abs"],
        [_MathFloor, "floor"],
        [_MathRound, "round"],
        [_MathMax, "max"],
        [_MathClz32, "clz32"],
        [_fnCall, "call"],
        [Function.prototype.call, "call"],
        [_fnApply, "apply"],
        [Function.prototype.apply, "apply"],
        [_fnBind, "bind"],
        [Function.prototype.bind, "bind"],
        [_regexExec, "exec"],
        [RegExp.prototype.exec, "exec"],
        [_regexTest, "test"],
        [RegExp.prototype.test, "test"],
        [_defineProperty, "defineProperty"],
        [Object.defineProperty, "defineProperty"],
        [_getOwnPropertyNames, "getOwnPropertyNames"],
        [Object.getOwnPropertyNames, "getOwnPropertyNames"],
        [_getOwnPropertyDescriptor, "getOwnPropertyDescriptor"],
        [Object.getOwnPropertyDescriptor, "getOwnPropertyDescriptor"],
        [_hasOwn, "hasOwnProperty"],
        [Object.prototype.hasOwnProperty, "hasOwnProperty"],
        [_getProto, "getPrototypeOf"],
        [Object.getPrototypeOf, "getPrototypeOf"],
        [_fnToString, "toString"],
        [Function.prototype.toString, "toString"],
        [_jsonStringify, "stringify"],
        [JSON.stringify, "stringify"],
        [createElFn, "createElement"],
        [appendFn, "appendChild"],
      ];
      const mnF = _objCreate(null);
      const mnN = _objCreate(null);
      const mnG = _objCreate(null);
      let mnLen = 0;
      const addNative = (fn, name, isGet = false) => {
        mnF[mnLen] = fn;
        mnN[mnLen] = name;
        mnG[mnLen] = Boolean(isGet);
        mnLen += 1;
      };
      for (let i = 0; i < baseNative.length; i++) {
        addNative(baseNative[i][0], baseNative[i][1], false);
      }
      if (_rawPerfNow) {
        addNative(_rawPerfNow, "now");
        if (typeof performance !== "undefined" && typeof performance.now === "function") addNative(performance.now, "now");
        if (typeof Performance !== "undefined" && Performance.prototype && typeof Performance.prototype.now === "function") addNative(Performance.prototype.now, "now");
      }
      if (_encode) {
        addNative(_encode, "encode");
        if (typeof TextEncoder !== "undefined" && TextEncoder.prototype) addNative(TextEncoder.prototype.encode, "encode");
      }
      // Check load-time captured _hdrSet (catches pre-load hooks while staying 0-FP on post-load RUM/APM wrappers!)
      if (_hdrSet) addNative(_hdrSet, "set");
      if (_hdrGet) addNative(_hdrGet, "get");
      if (!cwGet) return { ok: false, tampered: true, frame, host, win, fToStr, fExec, cleanup };
      addNative(cwGet, "contentWindow", true);
      if (_docElGet) addNative(_docElGet, "documentElement", true);
      if (_elGetAttr) addNative(_elGetAttr, "getAttribute");
      if (_Event) addNative(_Event, "Event");
      if (_isTrustedGet) addNative(_isTrustedGet, "isTrusted", true);
      if (_elAttachShadow) addNative(_elAttachShadow, "attachShadow");
      if (_regexSymReplace) {
        addNative(_regexSymReplace, "[Symbol.replace]");
        if (_symReplace) addNative(_regExpProto[_symReplace], "[Symbol.replace]");
      }
      if (_oacStartRendering) {
        addNative(_oacStartRendering, "startRendering");
        if (_OacCtor && _OacCtor.prototype && typeof _OacCtor.prototype.startRendering === "function") {
          addNative(_OacCtor.prototype.startRendering, "startRendering");
        }
      }
      for (let i = 0; i < mnLen; i++) {
        if (!isNativeNamed(mnF[i], mnN[i], fToStr, fExec, fApply, mnG[i])) {
          return { ok: false, tampered: true, frame, host, win, fToStr, fExec, cleanup };
        }
      }
      // In unified embedded mode, let ProxySnare reuse this verified startup iframe synchronously (1 iframe instead of 2 on cold boot!)
      if (_isEmbeddedUnified && typeof __PS_ON_FRESH_REALM__ === "function") {
        try { __PS_ON_FRESH_REALM__(fToStr, fExec, win); } catch (_) {}
      }
      return { ok: true, tampered: false, frame, host, win, fToStr, fExec, cleanup };
    } catch (_) {
      return { ok: false, tampered: true, frame, host, win: null, fToStr: null, fExec: null, cleanup };
    }
  }

  // Borrow a clean native console.debug from an untouched about:blank iframe if main window.console.debug was wrapped
  // (zero FP on Sentry/Datadog RUM breadcrumbs while defeating console.debug = () => {} / .bind(null) preloads!)
  function probeCdpWithConsole(existingRealm, force = false) {
    const runProbe = (fn, ctx) => {
      let tripped = false;
      try {
        const e = new _Error();
        _defGet(e, "stack", () => { tripped = true; return ""; });
        _reflectApply(fn, ctx, [e]);
        return { ok: true, tripped };
      } catch (_) {
        return { ok: false, tripped: false };
      }
    };
    if (_consoleDebug && !existingRealm) {
      const rp = runProbe(_consoleDebug, console);
      return rp.ok
        ? { tripped: rp.tripped, consoleTampered: false }
        : { tripped: !DEFAULT_ALLOW_DEVTOOLS, consoleTampered: true };
    }
    const checkRealm = (realm) => {
      try {
        const fw = realm && realm.win;
        const fToStr = realm && realm.fToStr;
        const fExec = realm && realm.fExec;
        const fDbg = fw && fw.console && fw.console.debug;
        if (realm && realm.ok && typeof fToStr === "function" && typeof fExec === "function" && typeof fDbg === "function" && fDbg.name === "debug" && isNativeNamed(fDbg, "debug", fToStr, fExec)) {
          return runProbe(fDbg, fw.console);
        }
      } catch (_) {}
      return { ok: false, tripped: false };
    };
    if (existingRealm) {
      if (_consoleDebug && existingRealm.ok && existingRealm.fExec && existingRealm.fToStr) {
        try {
          if (isNativeNamed(_rawConsoleDebug, "debug", existingRealm.fToStr, existingRealm.fExec)) {
            const rp = runProbe(_consoleDebug, console);
            return rp.ok
              ? { tripped: rp.tripped, consoleTampered: false }
              : { tripped: !DEFAULT_ALLOW_DEVTOOLS, consoleTampered: true };
          }
        } catch (_) {}
      }
      const r = checkRealm(existingRealm);
      if (r.ok) return { tripped: r.tripped, consoleTampered: false };
      return { tripped: !DEFAULT_ALLOW_DEVTOOLS, consoleTampered: true };
    }
    const now = _perfNow();
    const iframeThrottleMs = DEFAULT_ALLOW_DEVTOOLS ? 30_000 : 2_500;
    if (!force && !_lastIframeConsoleRes.consoleTampered && _lastIframeConsoleTs >= 0 && (now - _lastIframeConsoleTs) < iframeThrottleMs) {
      return _lastIframeConsoleRes;
    }
    const realm = openBaseFreshRealm();
    try {
      const r = checkRealm(realm);
      if (r.ok) {
        _lastIframeConsoleTs = now;
        _lastIframeConsoleRes = { tripped: r.tripped, consoleTampered: false };
        return _lastIframeConsoleRes;
      }
      return { tripped: !DEFAULT_ALLOW_DEVTOOLS, consoleTampered: true };
    } finally {
      if (realm && realm.cleanup) realm.cleanup();
    }
  }

  let _cdpCache = null;
  let _cdpCacheTs = 0;
  let _lastFullAutoScanTs = -1;
  function scanAutomationGlobals(fullScan) {
    try {
      for (let i = 0; i < _FAST_AUTOMATION_KEYS.length; i++) {
        const k = _FAST_AUTOMATION_KEYS[i];
        if (k in window || k in document) return true;
      }
      if (!fullScan) return false;
      const winKeys = _getOwnPropertyNames(window);
      for (let i = 0; i < winKeys.length; i++) {
        if (rxTest(_SUS_AUTOMATION_RE, winKeys[i])) return true;
      }
      const docKeys = _getOwnPropertyNames(document);
      for (let i = 0; i < docKeys.length; i++) {
        if (rxTest(_SUS_AUTOMATION_RE, docKeys[i])) return true;
      }
    } catch (_) {}
    return false;
  }

  function detectCdpActive(opts = false) {
    const isObj = opts && typeof opts === "object";
    const force = isObj ? Boolean(opts.skipCache) : Boolean(opts);
    const allowFull = isObj ? Boolean(opts.allowFullScan) : Boolean(opts);
    const now = _perfNow();
    if (!force && _cdpCache) {
      const ttl = (_cdpCache.active || DEFAULT_ALLOW_DEVTOOLS) ? 15_000 : 2_000;
      if (now - _cdpCacheTs < ttl) return Object.freeze({ ..._cdpCache });
    }
    const probe = probeCdpWithConsole(null, force);
    const runtimeEnable = probe.tripped;
    const needFull = allowFull || _lastFullAutoScanTs < 0 || (now - _lastFullAutoScanTs) >= 30_000;
    if (needFull) _lastFullAutoScanTs = now;
    const automationGlobals = scanAutomationGlobals(needFull);
    const webdriver = Boolean(navigator.webdriver);
    _cdpCache = Object.freeze({
      active: runtimeEnable || automationGlobals || webdriver || probe.consoleTampered,
      runtimeEnable,
      automationGlobals,
      webdriver,
      consoleTampered: probe.consoleTampered,
    });
    _cdpCacheTs = now;
    if (_isEmbeddedUnified && typeof __PS_SYNC_CDP__ === "function") {
      try { __PS_SYNC_CDP__(_cdpCache.active, _cdpCacheTs); } catch (_) {}
    }
    return _cdpCache;
  }

  function cdpWeightFor(mode, antiCdp, allowDevTools) {
    const m = normalizeClientMode(mode, DEFAULT_MODE);
    if (!antiCdp || m === "off") return 0;
    if (allowDevTools && (m === "strict" || m === "paranoid")) return 1;
    if (!allowDevTools && m === "balanced") return 4;
    if (m === "paranoid") return 6;
    if (m === "strict") return 4;
    return 1;
  }

  function probeWebWorker(timeoutMs = 900) {
    return new _NativePromise((resolve) => {
      const doneBox = (v) => { const b = _objCreate(null); b.v = v; resolve(b); };
      if (typeof Worker === "undefined" || typeof Blob === "undefined") {
        doneBox(null);
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
        doneBox(val);
      };
      try {
        const src = [
          "self.onmessage=()=>{",
          "const o={ua:navigator.userAgent,pl:navigator.platform,hw:navigator.hardwareConcurrency,wd:Boolean(navigator.webdriver),oc:1,wr:''};",
          "try{if(typeof OffscreenCanvas!=='undefined'){",
          "const c=new OffscreenCanvas(32,32),x=c.getContext('2d');",
          "if(x){x.fillStyle='#808080';x.fillRect(0,0,32,32);const d=x.getImageData(0,0,32,32).data,u=new Set();for(let i=0;i<d.length;i+=4)u.add((d[i]<<16)|(d[i+1]<<8)|d[i+2]);o.oc=u.size;}",
          "const c2=new OffscreenCanvas(32,32),g=c2.getContext('webgl2',{powerPreference:'default'})||c2.getContext('webgl',{powerPreference:'default'});",
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

  async function runHardwareProbes({ antiCdp = DEFAULT_ANTI_CDP, mode = DEFAULT_MODE, allowDevTools = DEFAULT_ALLOW_DEVTOOLS } = {}) {
    const tStart = _perfNow();
    const workerPromise = probeWebWorker(900);
    const rawPlatform = String(navigator.platform || "");
    const cdpW = cdpWeightFor(mode, antiCdp, allowDevTools);
    const details = {
      webdriver: Boolean(navigator.webdriver),
      freshIframeWebdriver: false,
      automationGlobalArtifact: false,
      cdpRuntimeEnable: false,
      softwareWebglHeadless: false,
      webdriverGetterSpoofed: false,
      nativeFunctionTampered: false,
      workerRealmContradiction: false,
      workerOk: false,
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
      platform: _reflectApply(_strSlice, stripPipes(rawPlatform), [0, 48]),
      probeMs: 0,
    };

    let score = 0;
    let flags = 0;
    const reasons = [];
    let isGecko = /Firefox\\//.test(navigator.userAgent);
    let isBrave = false;

    // Fresh untouched iframe realm for cross-realm native & webdriver inspection
    let freshRealm = null;
    try {
      freshRealm = openVerifiedFreshRealm();
      const freshWin = freshRealm.win;
      const freshToStr = freshRealm.fToStr || _fnToString;
      const freshExec = freshRealm.fExec || _regexExec;

      // Cross-realm verified CSS.supports (isGecko) & navigator.brave (isBrave) checks — defeats 1-line JS spoofing of privacy exemptions!
      try {
        const freshCssSup = freshWin && freshWin.CSS && typeof freshWin.CSS.supports === "function" ? freshWin.CSS.supports : null;
        const mainCssSup = typeof CSS !== "undefined" && CSS && typeof CSS.supports === "function" ? CSS.supports : null;
        if (freshCssSup && (!mainCssSup || !isNativeNamed(mainCssSup, "supports", freshToStr, freshExec, _reflectApply))) {
          details.nativeFunctionTampered = true;
        } else if (!freshCssSup && mainCssSup && !isNativeNamed(mainCssSup, "supports", freshToStr, freshExec, _reflectApply)) {
          details.nativeFunctionTampered = true;
        }
        if (!isGecko && freshCssSup && isNativeNamed(freshCssSup, "supports", freshToStr, freshExec, _reflectApply)) {
          isGecko = Boolean(_reflectApply(freshCssSup, freshWin.CSS, ["-moz-appearance", "none"]));
        }
      } catch (_) {
        details.nativeFunctionTampered = true;
      }
      try {
        const mainBraveOwn = _getOwnPropertyDescriptor(navigator, "brave");
        const freshBraveOwn = freshWin && freshWin.navigator ? _getOwnPropertyDescriptor(freshWin.navigator, "brave") : null;
        const mainBraveObj = navigator.brave;
        const freshBraveObj = freshWin && freshWin.navigator ? freshWin.navigator.brave : undefined;
        if (freshBraveObj && typeof freshBraveObj.isBrave === "function") {
          const freshBraveOk = isNativeNamed(freshBraveObj.isBrave, "isBrave", freshToStr, freshExec, _reflectApply);
          const mainBraveOk = Boolean(mainBraveObj && typeof mainBraveObj.isBrave === "function" && isNativeNamed(mainBraveObj.isBrave, "isBrave", freshToStr, freshExec, _reflectApply));
          if (!freshBraveOk || !mainBraveOk || Boolean(mainBraveOwn) !== Boolean(freshBraveOwn)) {
            details.nativeFunctionTampered = true;
          } else {
            isBrave = true;
          }
        } else if (mainBraveOwn || mainBraveObj !== undefined) {
          // navigator.brave injected on main realm while untouched iframe has no navigator.brave
          details.nativeFunctionTampered = true;
        }
      } catch (_) {
        details.nativeFunctionTampered = true;
      }

      try {
        if (freshWin && freshWin.navigator) {
          if (_getOwnPropertyDescriptor(freshWin.navigator, "webdriver")) {
            details.webdriverGetterSpoofed = true;
            details.nativeFunctionTampered = true;
          }
          const fNavProto = _getProto(freshWin.navigator);
          if (freshWin.Navigator && freshWin.Navigator.prototype && fNavProto !== freshWin.Navigator.prototype) {
            details.webdriverGetterSpoofed = true;
            details.nativeFunctionTampered = true;
          }
          const fObjProto = freshWin.Object ? freshWin.Object.prototype : null;
          if ((freshWin.Navigator && freshWin.Navigator.prototype) || (fNavProto && fNavProto !== fObjProto)) {
            const fWdDesc = _getOwnPropertyDescriptor(fNavProto, "webdriver");
            if (!fWdDesc || typeof fWdDesc.get !== "function" || !isNativeNamed(fWdDesc.get, "webdriver", freshToStr, freshExec, _reflectApply, true)) {
              details.webdriverGetterSpoofed = true;
              details.nativeFunctionTampered = true;
            }
          }
          details.freshIframeWebdriver = Boolean(freshWin.navigator.webdriver);
        }
      } catch (_) {
        details.webdriverGetterSpoofed = true;
        details.nativeFunctionTampered = true;
      }

      // 1. WebDriver flag (+4)
      if (antiCdp && (details.webdriver || details.freshIframeWebdriver)) {
        score += 4; flags |= 64; reasons.push("WEBDRIVER_FLAG");
      }

      // 2. Global / Document automation artifacts (+4)
      try {
        const winKeys = _getOwnPropertyNames(window);
        const docKeys = _getOwnPropertyNames(document);
        for (let i = 0; i < winKeys.length; i++) {
          if (_reflectApply(freshExec, _SUS_AUTOMATION_RE, [winKeys[i]]) !== null) { details.automationGlobalArtifact = true; break; }
        }
        if (!details.automationGlobalArtifact) {
          for (let i = 0; i < docKeys.length; i++) {
            if (_reflectApply(freshExec, _SUS_AUTOMATION_RE, [docKeys[i]]) !== null) { details.automationGlobalArtifact = true; break; }
          }
        }
        if (antiCdp && details.automationGlobalArtifact) {
          score += 4; flags |= 256; reasons.push("AUTOMATION_GLOBAL_ARTIFACT");
        }
      } catch (_) {}

      // 3. CDP Runtime.enable using verified freshRealm fallback (preset-aware weight; catches console.debug = () => {} / .bind(null) with zero Sentry FP!)
      const cdpProbeRes = antiCdp ? probeCdpWithConsole(freshRealm, true) : { tripped: false, consoleTampered: false };
      details.cdpRuntimeEnable = cdpProbeRes.tripped;
      if (antiCdp && details.cdpRuntimeEnable && cdpW > 0) {
        score += cdpW; flags |= 128; reasons.push("CDP_RUNTIME_ENABLE");
      }
      // Populate _cdpCache ONLY when antiCdp is enabled, and never downgrade a previously-latched active CDP reading within the TTL window!
      if (antiCdp) {
        const nowCdp = _perfNow();
        const newActive = details.cdpRuntimeEnable || details.automationGlobalArtifact || details.webdriver || details.freshIframeWebdriver || cdpProbeRes.consoleTampered;
        const prevLatched = Boolean(_cdpCache && _cdpCache.active && _cdpCacheTs >= 0 && nowCdp >= _cdpCacheTs && (nowCdp - _cdpCacheTs) < 15_000);
        _lastFullAutoScanTs = nowCdp;
        if (newActive || !prevLatched) {
          _cdpCache = Object.freeze({
            active: newActive,
            runtimeEnable: details.cdpRuntimeEnable,
            automationGlobals: details.automationGlobalArtifact,
            webdriver: details.webdriver || details.freshIframeWebdriver,
            consoleTampered: cdpProbeRes.consoleTampered,
          });
          _cdpCacheTs = nowCdp;
          if (_isEmbeddedUnified && typeof __PS_SYNC_CDP__ === "function") {
            try { __PS_SYNC_CDP__(_cdpCache.active, _cdpCacheTs); } catch (_) {}
          }
        }
      }

      // 4 & 5. Prototype / Getter Spoofing & Cross-Realm Native Integrity (+4 each, Proxy-throw & .bind(null) aware!)
      if (!freshRealm.ok || freshRealm.tampered || cdpProbeRes.consoleTampered || _bridgeTampered) {
        details.nativeFunctionTampered = true;
      }
      // Verify untouched iframe console.debug via verified freshToStr + freshExec!
      if (!details.nativeFunctionTampered && freshWin && freshWin.console) {
        try {
          if (typeof freshWin.console.debug !== "function" || freshWin.console.debug.name !== "debug" || !isNativeNamed(freshWin.console.debug, "debug", freshToStr, freshExec)) {
            details.nativeFunctionTampered = true;
          }
        } catch (_) {
          details.nativeFunctionTampered = true;
        }
      }
      let mainNavProto = null;
      let hasNavProto = false;
      try {
        mainNavProto = _getProto(navigator);
        const navGlobalMissing =
          (freshWin && freshWin.Navigator && (typeof Navigator !== "function" || !_Navigator || Navigator !== _Navigator)) ||
          (_Navigator && (typeof Navigator !== "function" || Navigator !== _Navigator));
        if (navGlobalMissing || (_Navigator && _Navigator.prototype && mainNavProto !== _Navigator.prototype)) {
          details.webdriverGetterSpoofed = true;
          details.nativeFunctionTampered = true;
        }
        const navProtoTarget = (mainNavProto && mainNavProto !== _objProto) ? mainNavProto : (_Navigator ? _Navigator.prototype : null);
        hasNavProto = Boolean(navProtoTarget);
        const wdOwn = _getOwnPropertyDescriptor(navigator, "webdriver");
        const wdProto = hasNavProto ? _getOwnPropertyDescriptor(navProtoTarget, "webdriver") : null;
        if (wdOwn) {
          details.webdriverGetterSpoofed = true;
        } else if (hasNavProto && (!wdProto || typeof wdProto.get !== "function")) {
          // Deleted or converted to data property on Navigator.prototype (even if window.Navigator was deleted in both realms!)
          details.webdriverGetterSpoofed = true;
        } else if (wdProto && typeof wdProto.get === "function") {
          try {
            if (!isNativeNamed(wdProto.get, "webdriver", freshToStr, freshExec, _reflectApply, true)) {
              details.webdriverGetterSpoofed = true;
            }
          } catch (_) {
            // Proxy-wrapped getter throws TypeError in untouched Function.prototype.toString!
            details.webdriverGetterSpoofed = true;
          }
        }
      } catch (_) {
        details.webdriverGetterSpoofed = true;
        details.nativeFunctionTampered = true;
      }
      if (details.webdriverGetterSpoofed) {
        score += 4; flags |= 512; reasons.push("WEBDRIVER_GETTER_SPOOFED");
      }

      try {
        const navProtoTarget2 = (mainNavProto && mainNavProto !== _objProto) ? mainNavProto : (_Navigator ? _Navigator.prototype : null);
        const hasNavProto2 = Boolean(navProtoTarget2);
        const navPlatDesc = hasNavProto2 ? _getOwnPropertyDescriptor(navProtoTarget2, "platform") : null;
        const navUaDesc = hasNavProto2 ? _getOwnPropertyDescriptor(navProtoTarget2, "userAgent") : null;
        if (hasNavProto2) {
          // Catch own-property shadowing on navigator or deleted/data-property conversion on Navigator.prototype (even if window.Navigator was deleted!)
          if (
            _getOwnPropertyDescriptor(navigator, "platform") ||
            _getOwnPropertyDescriptor(navigator, "userAgent") ||
            _getOwnPropertyDescriptor(navigator, "permissions") ||
            !navPlatDesc || typeof navPlatDesc.get !== "function" ||
            !navUaDesc || typeof navUaDesc.get !== "function"
          ) {
            details.nativeFunctionTampered = true;
          }
        }
        // Fail closed if WebIDL canvas/WebGL globals were deleted or replaced with decoys (never throw into empty catch!)
        if (
          (freshWin && freshWin.HTMLCanvasElement && (!_HTMLCanvasElement || typeof HTMLCanvasElement !== "function" || HTMLCanvasElement !== _HTMLCanvasElement)) ||
          (_HTMLCanvasElement && (typeof HTMLCanvasElement !== "function" || HTMLCanvasElement !== _HTMLCanvasElement)) ||
          (freshWin && freshWin.CanvasRenderingContext2D && (!_Canvas2D || typeof CanvasRenderingContext2D !== "function" || CanvasRenderingContext2D !== _Canvas2D)) ||
          (_Canvas2D && (typeof CanvasRenderingContext2D !== "function" || CanvasRenderingContext2D !== _Canvas2D)) ||
          (freshWin && freshWin.WebGLRenderingContext && (!_WebGL1 || typeof WebGLRenderingContext !== "function" || WebGLRenderingContext !== _WebGL1)) ||
          (_WebGL1 && (typeof WebGLRenderingContext !== "function" || WebGLRenderingContext !== _WebGL1)) ||
          (freshWin && freshWin.WebGL2RenderingContext && (!_WebGL2 || typeof WebGL2RenderingContext !== "function" || WebGL2RenderingContext !== _WebGL2)) ||
          (_WebGL2 && (typeof WebGL2RenderingContext !== "function" || WebGL2RenderingContext !== _WebGL2))
        ) {
          details.nativeFunctionTampered = true;
        }
        let canvasToDataUrl = _HTMLCanvasElement && _HTMLCanvasElement.prototype ? _HTMLCanvasElement.prototype.toDataURL : null;
        let ctxGetImgData = _Canvas2D && _Canvas2D.prototype ? _Canvas2D.prototype.getImageData : null;
        if (!canvasToDataUrl && document && typeof document.createElement === "function") {
          const cProbe = document.createElement("canvas");
          const cProto = cProbe ? _getProto(cProbe) : null;
          if (cProto && cProto !== _objProto && typeof cProto.toDataURL === "function") {
            details.nativeFunctionTampered = true;
            canvasToDataUrl = cProto.toDataURL;
          }
        }
        // Single native-code regex + verified freshExec + null-prototype tables defeat fn.bind(null), RegExp hooks & Array.prototype index setters!
        const cfF = _objCreate(null);
        const cfN = _objCreate(null);
        const cfG = _objCreate(null);
        let cfLen = 0;
        const addCheck = (fn, name, isGet = false) => {
          cfF[cfLen] = fn;
          cfN[cfLen] = name;
          cfG[cfLen] = Boolean(isGet);
          cfLen += 1;
        };
        const addFreshRequiredCheck = (mainFn, freshFn, name, isGet = false) => {
          if (typeof freshFn === "function" && typeof mainFn !== "function") {
            details.nativeFunctionTampered = true;
            return;
          }
          if (typeof mainFn === "function") addCheck(mainFn, name, isGet);
        };
        addCheck(_fnProto.toString, "toString");
        addCheck(_regexExec, "exec");
        addCheck(_regExpProto.exec, "exec");
        addCheck(_regExpProto.test, "test");
        addCheck(_Object.defineProperty, "defineProperty");
        addCheck(_Object.getOwnPropertyDescriptor, "getOwnPropertyDescriptor");
        addCheck(_Symbol ? _Symbol.for : null, "for");
        addFreshRequiredCheck(canvasToDataUrl, freshWin?.HTMLCanvasElement?.prototype?.toDataURL, "toDataURL");
        addFreshRequiredCheck(ctxGetImgData, freshWin?.CanvasRenderingContext2D?.prototype?.getImageData, "getImageData");
        addCheck(navPlatDesc?.get, "platform", true);
        addCheck(navUaDesc?.get, "userAgent", true);
        addFreshRequiredCheck(
          navigator.permissions && navigator.permissions.query,
          freshWin?.Permissions?.prototype?.query || freshWin?.navigator?.permissions?.query,
          "query"
        );
        addFreshRequiredCheck(_WebGL1 && _WebGL1.prototype && _WebGL1.prototype.getParameter, freshWin?.WebGLRenderingContext?.prototype?.getParameter, "getParameter");
        addFreshRequiredCheck(_WebGL1 && _WebGL1.prototype && _WebGL1.prototype.readPixels, freshWin?.WebGLRenderingContext?.prototype?.readPixels, "readPixels");
        addFreshRequiredCheck(_WebGL2 && _WebGL2.prototype && _WebGL2.prototype.getParameter, freshWin?.WebGL2RenderingContext?.prototype?.getParameter, "getParameter");
        addFreshRequiredCheck(_WebGL2 && _WebGL2.prototype && _WebGL2.prototype.readPixels, freshWin?.WebGL2RenderingContext?.prototype?.readPixels, "readPixels");
        addFreshRequiredCheck(_Element && _Element.prototype && _Element.prototype.getBoundingClientRect, freshWin?.Element?.prototype?.getBoundingClientRect, "getBoundingClientRect");
        for (let i = 0; i < cfLen && !details.nativeFunctionTampered; i++) {
          const fn = cfF[i];
          const expName = cfN[i];
          const isGet = cfG[i];
          if (typeof fn !== "function") continue;
          try {
            const sMain = _reflectApply(_fnToString, fn, []);
            const sFresh = _reflectApply(freshToStr, fn, []);
            const re = isGet ? _NATIVE_GET_RE : _NATIVE_FN_RE;
            const m1 = _reflectApply(freshExec, re, [sMain]);
            const m2 = _reflectApply(freshExec, re, [sFresh]);
            if (m1 === null || m2 === null || m1[1] !== expName || m2[1] !== expName || sMain !== sFresh) {
              details.nativeFunctionTampered = true;
              break;
            }
          } catch (_) {
            // Calling untouched Function.prototype.toString on a Proxy throws TypeError!
            details.nativeFunctionTampered = true;
            break;
          }
        }
      } catch (_) {
        details.nativeFunctionTampered = true;
      }
      if (details.nativeFunctionTampered) {
        score += 4; flags |= 1024; reasons.push("NATIVE_FUNCTION_TAMPERED");
      }
    } catch (_) {
      details.nativeFunctionTampered = true;
      score += 4; flags |= 1024; reasons.push("NATIVE_FUNCTION_TAMPERED");
    } finally {
      if (freshRealm && freshRealm.cleanup) {
        freshRealm.cleanup();
      }
    }

    const _uaStr = navigator.userAgent || "";
    // Recognize both Safari AND iOS WKWebView in-app browsers (O(N) zero-backtracking literal checks)
    const isSafariBrowser =
      (/safari/i.test(_uaStr) && !/chrome|android/i.test(_uaStr)) ||
      (/AppleWebKit\\//i.test(_uaStr) && /iPhone|iPad|iPod/i.test(_uaStr) && !/Chrome|Android/i.test(_uaStr));
    const cleanNativeBrowser =
      !details.webdriver &&
      !details.freshIframeWebdriver &&
      !details.automationGlobalArtifact &&
      !details.webdriverGetterSpoofed &&
      !details.nativeFunctionTampered;
    const isUtcTz = (() => { try { return new Date().getTimezoneOffset() === 0; } catch (_) { return false; } })();
    const cleanGeckoFpp = isGecko && cleanNativeBrowser && (!details.cdpRuntimeEnable || allowDevTools);
    const cleanSafariAtp = isSafariBrowser && cleanNativeBrowser && (!details.cdpRuntimeEnable || allowDevTools);

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
      const gl2 = c.getContext("webgl2", { powerPreference: "default" });
      gl = gl2 || c.getContext("webgl", { powerPreference: "default" });
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
        if (uniq.size > 1 && !((isBrave || cleanGeckoFpp || cleanSafariAtp) && cleanNativeBrowser)) { score += 2; flags |= 2; reasons.push("WEBGL_CLEAR_SYNTHETIC_NOISE"); }

        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        const renderer = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "") : "";
        details.webglRenderer = renderer;
        const exts = gl.getSupportedExtensions() || [];
        const maxTex = Number(gl.getParameter(gl.MAX_TEXTURE_SIZE) || 0);
        const pl = details.platform;
        const claimsWin = pl.startsWith("Win") || /Windows NT/i.test(navigator.userAgent);
        const claimsLinux = pl.startsWith("Linux") && !/Android/i.test(navigator.userAgent);
        const claimsMac = (pl === "MacIntel" || /Macintosh/i.test(navigator.userAgent)) && (navigator.maxTouchPoints || 0) <= 1;

        const claimsDiscreteOrD3D = /NVIDIA|GeForce|RTX|GTX|Radeon|Direct3D11|D3D11/i.test(renderer);
        const minExts = gl2 ? 12 : 19;
        const lowExtDiscreteLie = claimsDiscreteOrD3D && exts.length > 0 && exts.length <= minExts;
        const maxwellTexLie = /GTX\\s*(6|7|9)\\d{2}/i.test(renderer) && maxTex >= 32768;
        const d3d11ParallelLie = !isGecko && /(Direct3D11|D3D11)/i.test(renderer) && /(NVIDIA|RTX)/i.test(renderer) && !exts.includes("KHR_parallel_shader_compile") && exts.length < 30;
        const osGpuImpossibility =
          (claimsWin && (/Intel Iris OpenGL Engine|Apple GPU|Apple M\\d/i.test(renderer))) ||
          ((claimsLinux || claimsMac) && /Direct3D11|D3D11|Direct3D9/i.test(renderer));

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

    // 10. Silent OfflineAudioContext zero-invariance (captured startRendering + 300ms cap / 60ms Safari pre-gesture cap)
    try {
      if (_OacCtor) {
        const ac = new _OacCtor(1, 512, 44100);
        const buf = ac.createBuffer(1, 512, 44100);
        const src = ac.createBufferSource();
        src.buffer = buf;
        src.connect(ac.destination);
        src.start(0);
        const renderP = _oacStartRendering ? _reflectApply(_oacStartRendering, ac, []) : ac.startRendering();
        const oacTimeoutMs = isSafariBrowser && ac.state === "suspended" ? 60 : 300;
        const renderedBox = await withTimeout(renderP, oacTimeoutMs, null);
        const rendered = renderedBox ? renderedBox.v : null;
        if (rendered) {
          const ch = rendered.getChannelData(0);
          let nonZero = 0;
          for (let i = 0; i < ch.length; i++) if (_MathAbs(ch[i]) > 1e-12) nonZero++;
          details.silentAudioNonZeroSamples = nonZero;
          if (nonZero > 0) { score += 2; flags |= 4; reasons.push("SILENT_AUDIO_SYNTHETIC_NOISE"); }
        }
      }
    } catch (_) {}

    const root = document.documentElement || document.body;

    // 11. Integer-DPR DOMRect sub-pixel poisoning (Safari zoom & CSS html zoom/transform safe!)
    try {
      const dpr = window.devicePixelRatio || 1;
      const isSafari = isSafariBrowser;
      const vvScale = window.visualViewport && typeof window.visualViewport.scale === "number" ? window.visualViewport.scale : 1;
      const rootStyle = root && typeof window.getComputedStyle === "function" ? window.getComputedStyle(root) : null;
      const rootZoomed = Boolean(
        _MathAbs(vvScale - 1) > 1e-3 ||
        (rootStyle && rootStyle.transform && rootStyle.transform !== "none") ||
        (rootStyle && rootStyle.zoom && _MathAbs(parseFloat(rootStyle.zoom) - 1) > 1e-3)
      );
      if (_MathAbs(dpr - _MathRound(dpr)) < 1e-6 && root && !rootZoomed) {
        const mkBox = (topPx) => {
          const el = document.createElement("div");
          el.style.all = "initial";
          el.style.position = "fixed";
          el.style.left = "10px";
          el.style.top = topPx + "px";
          el.style.width = "100px";
          el.style.height = "50px";
          el.style.margin = "0";
          el.style.padding = "0";
          el.style.border = "0";
          el.style.visibility = "hidden";
          return el;
        };
        const dv = mkBox(20);
        const useSiblingDiff = isSafari || isGecko;
        const dv2 = useSiblingDiff ? mkBox(80) : null;
        root.appendChild(dv);
        if (dv2) root.appendChild(dv2);
        try {
          const r = dv.getBoundingClientRect();
          if (useSiblingDiff && dv2) {
            const r2 = dv2.getBoundingClientRect();
            const siblingDrift = _MathMax(_MathAbs(r.width - r2.width), _MathAbs(r.left - r2.left));
            details.domRectDelta = Number(siblingDrift.toFixed(6));
            if (siblingDrift > 1e-3 && siblingDrift < 1.5) {
              details.domRectSubpixelDrift = true;
              score += 2; flags |= 8; reasons.push("DOMRECT_SUBPIXEL_POISONING");
            }
          } else if (_MathAbs(r.width - 100) < 2 && _MathAbs(r.height - 50) < 2 && _MathAbs(r.left - 10) < 2 && _MathAbs(r.top - 20) < 2) {
            const delta = _MathMax(_MathAbs(r.left - 10), _MathAbs(r.top - 20), _MathAbs(r.width - 100), _MathAbs(r.height - 50));
            details.domRectDelta = Number(delta.toFixed(6));
            if (delta > 1e-3 && delta < 1.5) {
              details.domRectSubpixelDrift = true;
              score += 2; flags |= 8; reasons.push("DOMRECT_SUBPIXEL_POISONING");
            }
          }
        } finally {
          dv.remove();
          if (dv2) dv2.remove();
        }
      }
    } catch (_) {}

    // 12. OS platform vs mandatory core system fonts (Firefox custom-font accessibility & modern RFP/LibreWolf safe!)
    // Compute likelyFirefoxRfp AFTER WebGL probe 8/9 so stripped WEBGL_debug_renderer_info + UTC + hardwareConcurrency===4 (Mozilla Bug 1984333) are recognized!
    const likelyFirefoxRfp = Boolean(
      isGecko &&
      cleanNativeBrowser &&
      (screen.width === window.innerWidth ||
        navigator.hardwareConcurrency === 2 ||
        (isUtcTz && (navigator.hardwareConcurrency === 4 || !details.webglRenderer)))
    );
    try {
      const pl = String(navigator.platform || "");
      const up = String((navigator.userAgentData && navigator.userAgentData.platform) || "");
      const claimsWin = pl.startsWith("Win") || up === "Windows";
      const claimsMac = (pl === "MacIntel" || up === "macOS") && (navigator.maxTouchPoints || 0) <= 1;
      if (root && (claimsWin || claimsMac) && !(likelyFirefoxRfp || (cleanGeckoFpp && details.canvas2dRepeatDiff > 0))) {
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
          const userForcedFonts = mw('"Arial",monospace') === base && mw('"Times New Roman",monospace') === base;
          if (base > 0 && sansW > 0 && sansW !== base && !userForcedFonts) {
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

    // 13. Viewport / Screen Euclidean Geometry Impossibility (Wayland, compact browsers, F11, macOS notch, PWA safe)
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
        const fillsAvail =
          (screen.availWidth && window.outerWidth >= screen.availWidth - 4 &&
           screen.availHeight && window.outerHeight >= screen.availHeight - 4);
        const defaultAutomationViewport =
          window.screenX === 0 && window.screenY === 0 &&
          ((window.innerWidth === 1280 && window.innerHeight === 720) || (window.innerWidth === 800 && window.innerHeight === 600));
        const zeroChromeWindow =
          !fillsAvail &&
          window.outerWidth > 0 &&
          window.outerWidth === window.innerWidth &&
          window.outerHeight === window.innerHeight &&
          (window.outerWidth < screen.width - 80 || window.outerHeight < screen.height - 120) &&
          (defaultAutomationViewport || details.webdriver || (!allowDevTools && details.cdpRuntimeEnable) || details.automationGlobalArtifact);
        if (zeroChromeWindow) {
          details.viewportGeometryImpossibility = true;
          score += 2; flags |= 4096; reasons.push("VIEWPORT_GEOMETRY_IMPOSSIBILITY");
        }
      }
    } catch (_) {}

    // 14. Permissions & Engine Coherence
    try {
      let permLie = false;
      if (typeof Notification !== "undefined" && navigator.permissions && navigator.permissions.query) {
        const stBox = await withTimeout(navigator.permissions.query({ name: "notifications" }), 900, null);
        const st = stBox ? stBox.v : null;
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

    // 6. Await Web Worker cross-realm comparison (+4) — Brave & dual-GPU laptop safe!
    let workerWr = "";
    try {
      const wBox = await workerPromise;
      const w = wBox ? wBox.v : null;
      if (w) {
        details.workerOk = true;
        workerWr = typeof w.wr === "string" ? w.wr : "";
        details.offscreenCanvasUniqueColors = w.oc || 1;
        const platDiff = Boolean(w.pl && rawPlatform && w.pl !== rawPlatform);
        const hwDiff = !(isBrave && cleanNativeBrowser) && Boolean(w.hw && navigator.hardwareConcurrency && w.hw !== navigator.hardwareConcurrency);
        const uaDiff = Boolean(w.ua && navigator.userAgent && w.ua !== navigator.userAgent);
        // On dual-GPU laptops (Optimus/switchable), only flag cross-OS GPU contradiction between main & Worker!
        const mainD3d = /Direct3D11|D3D11|Direct3D9/i.test(details.webglRenderer);
        const workD3d = /Direct3D11|D3D11|Direct3D9/i.test(workerWr);
        const mainApple = /Apple GPU|Apple M\\d|Intel Iris OpenGL Engine/i.test(details.webglRenderer);
        const workApple = /Apple GPU|Apple M\\d|Intel Iris OpenGL Engine/i.test(workerWr);
        const wrOsContradiction =
          !(isBrave && cleanNativeBrowser) &&
          Boolean(workerWr && details.webglRenderer) &&
          ((mainD3d !== workD3d) || (mainApple !== workApple));
        if (platDiff || hwDiff || uaDiff || wrOsContradiction || (antiCdp && w.wd && !details.webdriver)) {
          details.workerRealmContradiction = true;
          score += 4; flags |= 2048; reasons.push("WORKER_REALM_CONTRADICTION");
        }
      }
    } catch (_) {}

    // 15. Corroborated headless software WebGL renderer (+3; Firecrawl / Browserless / Docker headless; allowDevTools safe!)
    try {
      const effWebglRenderer = details.webglRenderer || workerWr;
      if (antiCdp && /SwiftShader|llvmpipe|Mesa OffScreen|Software Rasterizer/i.test(effWebglRenderer)) {
        const missingChromeObj = /Chrome\\//.test(navigator.userAgent) && typeof window.chrome === "undefined";
        const cdpCorr = !allowDevTools && details.cdpRuntimeEnable;
        if (cdpCorr || details.webdriver || details.automationGlobalArtifact || missingChromeObj || details.viewportGeometryImpossibility) {
          details.softwareWebglHeadless = true;
          score += 3; flags |= 32768; reasons.push("HEADLESS_SOFTWARE_WEBGL");
        }
      }
    } catch (_) {}

    // Finalize Canvas2D / OffscreenCanvas score (exempt Brave, Firefox Private/ETP FPP, Safari 17+/iOS 17+ Private Browsing ATP, and clean native LibreWolf/Firefox RFP placeholder randomization when uncorroborated!)
    const deterministicPrivacyFarble =
      cleanNativeBrowser &&
      details.canvas2dRepeatDiff === 0 &&
      (isBrave || ((cleanGeckoFpp || cleanSafariAtp) && !details.workerRealmContradiction));
    const cleanRfpPlaceholder =
      cleanGeckoFpp &&
      !details.workerRealmContradiction &&
      !details.webglHardwareLie &&
      !details.domRectSubpixelDrift &&
      !details.engineCoherenceLie &&
      !details.viewportGeometryImpossibility &&
      !details.softwareWebglHeadless &&
      details.silentAudioNonZeroSamples === 0;
    if (!deterministicPrivacyFarble && !cleanRfpPlaceholder && (details.canvas2dUniqueColors > 1 || details.offscreenCanvasUniqueColors > 1 || details.canvas2dRepeatDiff > 0)) {
      const nonDet = details.canvas2dRepeatDiff > 0;
      score += nonDet ? 4 : 2;
      flags |= 1;
      reasons.push(nonDet ? "CANVAS2D_NON_DETERMINISTIC" : "CANVAS2D_SYNTHETIC_NOISE");
    }

    details.probeMs = _MathMax(0, _MathMin(60_000, _MathRound(_perfNow() - tStart)));
    if (("then" in _objProto || Object !== _Object || Array !== _Array || RegExp !== _RegExp || (_Symbol && Symbol !== _Symbol)) && !details.nativeFunctionTampered) {
      details.nativeFunctionTampered = true;
      score += 4; flags |= 1024; reasons.push("NATIVE_FUNCTION_TAMPERED");
    }
    const probeOut = _objCreate(null);
    probeOut.score = score;
    probeOut.flags = flags;
    probeOut.platform = details.platform;
    probeOut.reasons = reasons;
    probeOut.details = details;
    return probeOut;
  }

  const probeCache = new Map();
  function getProbePromise(antiCdp, mode = DEFAULT_MODE, allowDevTools = DEFAULT_ALLOW_DEVTOOLS) {
    const key = normalizeClientMode(mode, DEFAULT_MODE) + ":" + (antiCdp ? "1" : "0") + ":" + (allowDevTools ? "1" : "0");
    if (!probeCache.has(key)) {
      const p = _reflectApply(_nativePromiseThen, runHardwareProbes({ antiCdp, mode, allowDevTools }), [
        undefined,
        (err) => {
          probeCache.delete(key);
          throw err;
        },
      ]);
      probeCache.set(key, p);
    }
    return probeCache.get(key);
  }

  // Re-evaluate lightweight dynamic CDP/automation signals (with monotonic TTL cache) on every verify() / collectHandshakeProof()
  function mergeLiveDynamicSignals(probe, { antiCdp = DEFAULT_ANTI_CDP, mode = DEFAULT_MODE, allowDevTools = DEFAULT_ALLOW_DEVTOOLS, forceCdp = false } = {}) {
    if (normalizeClientMode(mode, DEFAULT_MODE) === "off") return probe;
    const objProtoThenTampered =
      ("then" in _objProto) ||
      Object !== _Object ||
      Array !== _Array ||
      RegExp !== _RegExp ||
      (_Symbol && Symbol !== _Symbol);
    if (!antiCdp) {
      if ((_bridgeTampered || objProtoThenTampered) && (probe.flags & 1024) === 0) {
        const out = _objCreate(null);
        out.score = probe.score + 4;
        out.flags = probe.flags | 1024;
        out.platform = probe.platform;
        out.reasons = [...probe.reasons, "NATIVE_FUNCTION_TAMPERED"];
        out.details = { ...probe.details, nativeFunctionTampered: true };
        return out;
      }
      return probe;
    }
    const live = detectCdpActive(forceCdp);
    let score = probe.score;
    let flags = probe.flags;
    const reasons = [...probe.reasons];
    const details = { ...probe.details };
    if ((_bridgeTampered || objProtoThenTampered || live.consoleTampered) && (flags & 1024) === 0) {
      details.nativeFunctionTampered = true;
      score += 4; flags |= 1024; reasons.push("NATIVE_FUNCTION_TAMPERED");
    }
    if (live.webdriver && (flags & 64) === 0) {
      details.webdriver = true;
      score += 4; flags |= 64; reasons.push("WEBDRIVER_FLAG");
    }
    if (live.automationGlobals && (flags & 256) === 0) {
      details.automationGlobalArtifact = true;
      score += 4; flags |= 256; reasons.push("AUTOMATION_GLOBAL_ARTIFACT");
    }
    const cdpW = cdpWeightFor(mode, antiCdp, allowDevTools);
    if (live.runtimeEnable && (flags & 128) === 0 && cdpW > 0) {
      details.cdpRuntimeEnable = true;
      score += cdpW; flags |= 128; reasons.push("CDP_RUNTIME_ENABLE");
    }
    const out = _objCreate(null);
    out.score = score;
    out.flags = flags;
    out.platform = probe.platform;
    out.reasons = reasons;
    out.details = details;
    return out;
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
    allowDevTools = DEFAULT_ALLOW_DEVTOOLS,
    includeInteraction = false,
    interactionSnap = undefined,
    callTs = null,
  } = {}) {
    const reqMode = normalizeClientMode(mode, DEFAULT_MODE);
    const effMode = POLICY_LOCKED && MODE_RANK[reqMode] < MODE_RANK[DEFAULT_MODE] ? DEFAULT_MODE : reqMode;
    const effAntiCdp = POLICY_LOCKED && DEFAULT_ANTI_CDP ? true : Boolean(antiCdp);
    const effAllowDevTools = POLICY_LOCKED && !DEFAULT_ALLOW_DEVTOOLS ? false : Boolean(allowDevTools);
    const threshold = thresholdFor(effMode);
    if (effMode === "off") {
      return { ok: true, blocked: false, mode: "off", threshold: Infinity, score: 0, flags: 0, reasons: [], details: {}, interaction: null, attest: null };
    }
    const baseProbe = await getProbePromise(effAntiCdp, effMode, effAllowDevTools);
    const probe = mergeLiveDynamicSignals(baseProbe, { antiCdp: effAntiCdp, mode: effMode, allowDevTools: effAllowDevTools });

    let totalScore = probe.score;
    let totalFlags = probe.flags;
    const allReasons = [...probe.reasons];
    let interactionVerdict = null;

    const freshClick = interactionSnap !== undefined ? interactionSnap : (includeInteraction ? getFreshLastClick() : null);
    if (freshClick) {
      interactionVerdict = evaluateInteractionLocal(freshClick, effMode, callTs);
      if (interactionVerdict.score > 0) {
        totalScore += interactionVerdict.score;
        totalFlags |= 16384;
        allReasons.push(...interactionVerdict.reasons);
      }
    }

    const blocked = effMode !== "monitor" && totalScore >= threshold;
    const safeTicket = stripPipes(ticket);
    const safeNonce = stripPipes(nonce);
    const safeChallenge = stripPipes(challenge);
    const safeMethod = stripPipes(_reflectApply(_strToUpper, _reflectApply(_strTrim, _String(method || ""), []), []));
    const safePath = path ? normalizeClientPath(_String(path)) : "";

    const attest = _objCreate(null);
    attest.v = 2;
    attest.s = totalScore;
    attest.f = totalFlags;
    attest.p = probe.platform;
    if (safeChallenge) {
      const powNonce = solveTicketPow(safeTicket, safeChallenge, difficulty || 0);
      const d = await sha256Hex(
        "VB_ATTEST_V2|" + safeTicket + "|" + safeNonce + "|" + totalScore + "|" + totalFlags + "|" +
        probe.platform + "|" + safeChallenge + "|" + powNonce + "|" + safeMethod + "|" + safePath
      );
      attest.w = powNonce;
      attest.m = safeMethod;
      attest.u = safePath;
      attest.d = d;
    } else {
      const d = await sha256Hex("VB_ATTEST_V2|" + safeTicket + "|" + safeNonce + "|" + totalScore + "|" + totalFlags + "|" + probe.platform);
      attest.d = d;
    }

    const vOut = _objCreate(null);
    vOut.ok = !blocked;
    vOut.blocked = blocked;
    vOut.mode = effMode;
    vOut.threshold = threshold;
    vOut.score = totalScore;
    vOut.flags = totalFlags;
    vOut.reasons = allReasons;
    vOut.details = probe.details;
    vOut.interaction = interactionVerdict;
    vOut.attest = attest;
    return vOut;
  }

  // Drop-in <veil-break mode="strict">...</veil-break> Closed Shadow DOM Web Component (React 18 reconnect-safe)
  if (typeof customElements !== "undefined" && !customElements.get("veil-break")) {
    class VeilBreakElement extends HTMLElement {
      async connectedCallback() {
        if (this._vbDone) return;
        const gen = (this._vbGen = (this._vbGen || 0) + 1);
        const rawElMode = this.getAttribute("mode");
        const reqElMode = rawElMode ? normalizeClientMode(rawElMode, DEFAULT_MODE) : DEFAULT_MODE;
        const mode = POLICY_LOCKED && MODE_RANK[reqElMode] < MODE_RANK[DEFAULT_MODE] ? DEFAULT_MODE : reqElMode;
        const cdpAttr = this.getAttribute("anti-cdp");
        const reqCdpFlag = cdpAttr === null ? DEFAULT_ANTI_CDP : !/^(false|0)$/i.test(cdpAttr.trim());
        const cdpFlag = POLICY_LOCKED && DEFAULT_ANTI_CDP ? true : reqCdpFlag;
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
  }` + (unified ? "" : `

  const BASE_SLASH = BASE + "/";
  const _CLEAN_CLIENT_PATH_RE = /^\\/(?:[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*(?:\\/[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*)*)?\\/?$/;
  function isGateControlPath(pathname) {
    const raw = _String(pathname || "/");
    if (
      raw !== BASE &&
      !_reflectApply(_strStartsWith, raw, [BASE_SLASH]) &&
      raw.indexOf("%") < 0 &&
      raw.indexOf("..") < 0 &&
      raw.indexOf("\\\\") < 0 &&
      raw.indexOf("//") < 0 &&
      raw.indexOf("/.") < 0 &&
      raw.indexOf(";") < 0
    ) {
      return false;
    }
    const norm = normalizeClientPath(raw);
    return norm === BASE || _reflectApply(_strStartsWith, norm, [BASE_SLASH]);
  }

  function matchClientRules(cand) {
    const lower = _reflectApply(_strToLower, cand, []);
    for (let i = 0; i < RULES.length; i++) {
      const rule = RULES[i];
      if (rule instanceof RegExp) {
        rule.lastIndex = 0;
        if (_reflectApply(_regexExec, rule, [cand]) !== null) return true;
      } else if (
        rule === "*" ||
        rule === "/" ||
        lower === rule ||
        _reflectApply(_strStartsWith, lower, [_reflectApply(_strEndsWith, rule, ["/"]) ? rule : rule + "/"])
      ) {
        return true;
      }
    }
    return false;
  }

  function isProtectedPath(pathname) {
    const rawFull = _String(pathname || "/");
    const qRaw = rawFull.indexOf("?");
    const raw = qRaw >= 0 ? rawFull.slice(0, qRaw) : rawFull;
    if (rxTest(_CLEAN_CLIENT_PATH_RE, raw)) {
      const clean = raw.length > 1 && raw[raw.length - 1] === "/" ? raw.slice(0, -1) : (raw || "/");
      return matchClientRules(clean);
    }
    const candidates = new Set([normalizeClientPath(raw)]);
    let dec = raw;
    for (let pass = 0; pass < 2; pass++) {
      const next = decodePercentSafe(dec);
      if (next === dec) break;
      dec = next;
    }
    if (dec !== raw) candidates.add(normalizeClientPath(dec));
    const q = dec.indexOf("?");
    if (q >= 0) candidates.add(normalizeClientPath(dec.slice(0, q)));
    const h = dec.indexOf("#");
    if (h >= 0) candidates.add(normalizeClientPath(dec.slice(0, h)));

    for (const cand of candidates) {
      if (matchClientRules(cand)) return true;
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

  async function buildRequestAttestationHeaders(method, reqPath, signal, interactionSnap = undefined, callTs = null) {
    const tkResp = await origFetch(BASE + "/ticket", { method: "GET", credentials: "same-origin", cache: "no-store", signal });
    if (!tkResp.ok) {
      const failOut = _objCreate(null);
      failOut.ok = false;
      failOut.response = tkResp;
      return failOut;
    }
    let tkData = { ticket: "", challenge: "", difficulty: 0 };
    try { tkData = await tkResp.json(); } catch (_) {}
    const nonce = randomNonceHex();
    const isMutating = method !== "GET" && method !== "HEAD";
    const res = await verify({
      mode: DEFAULT_MODE,
      ticket: tkData.ticket || "",
      nonce,
      challenge: tkData.challenge || "",
      difficulty: tkData.difficulty || 0,
      method,
      path: reqPath,
      includeInteraction: isMutating && Boolean(interactionSnap !== undefined ? interactionSnap : getFreshLastClick()),
      interactionSnap: isMutating ? interactionSnap : null,
      callTs,
    });
    const outHdrs = _objCreate(null);
    outHdrs["X-VB-Ticket"] = tkData.ticket || "";
    outHdrs["X-VB-Nonce"] = nonce;
    if (res.attest) outHdrs["X-VB-Attest"] = toAsciiJson(res.attest);
    const okOut = _objCreate(null);
    okOut.ok = true;
    okOut.headers = outHdrs;
    return okOut;
  }`) + `

  async function collectHandshakeProof(challenge = "") {
    if (DEFAULT_MODE === "off") return null;
    const baseProbe = await getProbePromise(DEFAULT_ANTI_CDP, DEFAULT_MODE, DEFAULT_ALLOW_DEVTOOLS);
    const needFreshCdp = !_cdpCache || (_perfNow() - _cdpCacheTs) > 250;
    const probe = mergeLiveDynamicSignals(baseProbe, { antiCdp: DEFAULT_ANTI_CDP, mode: DEFAULT_MODE, allowDevTools: DEFAULT_ALLOW_DEVTOOLS, forceCdp: needFreshCdp ? { skipCache: true, allowFullScan: false } : false });
    const d0 = probe.details || _objCreate(null);
    let score = probe.score;
    let flags = probe.flags;
    if ((("then" in _objProto) || Object !== _Object || Array !== _Array || RegExp !== _RegExp || (_Symbol && Symbol !== _Symbol)) && (flags & 1024) === 0) {
      score += 4;
      flags |= 1024;
    }
    const ch = _reflectApply(_strSlice, stripPipes(challenge), [0, 64]);
    const wr = _reflectApply(_strSlice, stripPipes(d0.webglRenderer), [0, 64]);
    const cdp = (d0.cdpRuntimeEnable || d0.automationGlobalArtifact || d0.webdriver || d0.freshIframeWebdriver) ? 1 : 0;
    const wk = d0.workerOk ? 1 : 0;
    const ms = Number.isFinite(d0.probeMs) ? _MathMax(0, _MathMin(60_000, _MathRound(d0.probeMs))) : 0;
    const d = await sha256Hex("VB_HS_V3|" + ch + "|" + score + "|" + flags + "|" + probe.platform + "|" + cdp + "|" + wr + "|" + wk + "|" + ms);
    const out = _objCreate(null);
    out.v = 3;
    out.ch = ch;
    out.s = score;
    out.f = flags;
    out.p = probe.platform;
    out.cdp = cdp;
    out.wr = wr;
    out.wk = wk;
    out.ms = ms;
    out.d = d;
    return out;
  }` + (unified ? "" : `

  if (origFetch && DEFAULT_MODE !== "off" && !UNIFIED_MODE) {
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
      // Freeze passive click snapshot & timestamp synchronously BEFORE /ticket RTT + probes!
      const isMutatingCall = method !== "GET" && method !== "HEAD";
      const clickSnapAtCall = isMutatingCall ? getFreshLastClick() : null;
      const callTs = _perfNow();

      let attRes;
      try {
        attRes = await buildRequestAttestationHeaders(method, reqUrl.pathname, signal, clickSnapAtCall, callTs);
      } catch (err) {
        if (DEFAULT_MODE === "monitor") return origFetch(input, init);
        throw err;
      }
      if (!attRes.ok) {
        if (DEFAULT_MODE === "strict" || DEFAULT_MODE === "balanced" || DEFAULT_MODE === "paranoid") {
          return attRes.response;
        }
        return origFetch(input, init);
      }

      const _setAttestHeaders = (hObj, attH) => {
        if (_hdrSet) {
          _reflectApply(_hdrSet, hObj, ["X-VB-Ticket", attH["X-VB-Ticket"]]);
          _reflectApply(_hdrSet, hObj, ["X-VB-Nonce", attH["X-VB-Nonce"]]);
          if (attH["X-VB-Attest"] !== undefined) _reflectApply(_hdrSet, hObj, ["X-VB-Attest", attH["X-VB-Attest"]]);
        } else {
          hObj.set("X-VB-Ticket", attH["X-VB-Ticket"]);
          hObj.set("X-VB-Nonce", attH["X-VB-Nonce"]);
          if (attH["X-VB-Attest"] !== undefined) hObj.set("X-VB-Attest", attH["X-VB-Attest"]);
        }
      };
      const headers = new _Headers(safeInit.headers !== undefined ? safeInit.headers : (isReq ? input.headers : undefined));
      _setAttestHeaders(headers, attRes.headers);
      // Clone Request BEFORE first fetch so mobile Wi-Fi<->5G roaming retry never throws TypeError on consumed body!
      const retryInput = isReq ? (() => { try { return input.clone(); } catch (_) { return null; } })() : null;

      const resp = isReq
        ? await origFetch(new Request(input, { ...safeInit, headers }))
        : await origFetch(reqUrl.toString(), { ...safeInit, headers });

      const retryTickHdr = _hdrGet ? _reflectApply(_hdrGet, resp.headers, ["x-vb-retry-ticket"]) : resp.headers.get("x-vb-retry-ticket");
      if (resp.status === 403 && retryTickHdr === "1" && (!isReq || retryInput)) {
        try {
          const retryAtt = await buildRequestAttestationHeaders(method, reqUrl.pathname, signal, clickSnapAtCall, callTs);
          if (retryAtt.ok) {
            const retryHdrs = new _Headers(safeInit.headers !== undefined ? safeInit.headers : (retryInput ? retryInput.headers : undefined));
            _setAttestHeaders(retryHdrs, retryAtt.headers);
            return isReq
              ? origFetch(new Request(retryInput, { ...safeInit, headers: retryHdrs }))
              : origFetch(reqUrl.toString(), { ...safeInit, headers: retryHdrs });
          }
        } catch (_) {}
      }

      if (resp.redirected && resp.status === 403 && resp.url) {
        const redirectGetHint = (_hdrGet ? _reflectApply(_hdrGet, resp.headers, ["x-vb-redirect-get"]) : resp.headers.get("x-vb-redirect-get")) === "1";
        const vbModeHdr = _hdrGet ? _reflectApply(_hdrGet, resp.headers, ["x-veilbreak-mode"]) : resp.headers.get("x-veilbreak-mode");
        let isVb403 = redirectGetHint || Boolean(vbModeHdr);
        if (!isVb403) {
          const rCt = ((_hdrGet ? _reflectApply(_hdrGet, resp.headers, ["content-type"]) : resp.headers.get("content-type")) || "").toLowerCase();
          if (rCt.includes("json")) {
            try {
              const j = await resp.clone().json();
              if (j && j.error === "VEILBREAK_DENIED") isVb403 = true;
            } catch (_) {}
          }
        }
        const isMutatingOrig = method !== "GET" && method !== "HEAD";
        const preserveMutate = isMutatingOrig && !redirectGetHint;
        if (isVb403 && (method === "GET" || method === "HEAD" || redirectGetHint || resp.url !== reqUrl.toString())) {
          let finalUrl = null;
          try { finalUrl = new URL(resp.url, baseHref()); } catch (_) {}
          const destProtected = Boolean(finalUrl && isProtectedPath(finalUrl.pathname));
          if (finalUrl && finalUrl.origin === window.location.origin && !isGateControlPath(finalUrl.pathname) && (redirectGetHint || destProtected)) {
            if (preserveMutate && isReq && !retryInput) return resp;
            const retryMethod = preserveMutate ? method : (method === "HEAD" ? "HEAD" : "GET");
            const retryHdrs = new _Headers(safeInit.headers !== undefined ? safeInit.headers : ((preserveMutate && retryInput ? retryInput.headers : null) || (isReq ? input.headers : undefined)));
            if (_hdrDelete) {
              _reflectApply(_hdrDelete, retryHdrs, ["x-vb-ticket"]);
              _reflectApply(_hdrDelete, retryHdrs, ["x-vb-nonce"]);
              _reflectApply(_hdrDelete, retryHdrs, ["x-vb-attest"]);
            } else {
              retryHdrs.delete("x-vb-ticket");
              retryHdrs.delete("x-vb-nonce");
              retryHdrs.delete("x-vb-attest");
            }
            const retryInit = {
              ...(isReq ? {
                credentials: input.credentials,
                cache: input.cache,
                ...(input.mode && input.mode !== "navigate" ? { mode: input.mode } : {}),
                referrer: input.referrer,
                referrerPolicy: input.referrerPolicy,
                signal: input.signal,
              } : {}),
              ...safeInit,
              method: retryMethod,
              headers: retryHdrs,
            };
            if (!preserveMutate) delete retryInit.body;
            const finalCanonUrl = finalUrl.origin + finalUrl.pathname + finalUrl.search;
            let retryBodyBuf = null;
            if (preserveMutate && isReq && retryInput) {
              try {
                retryBodyBuf = await retryInput.arrayBuffer();
              } catch (_) {
                return resp;
              }
            }
            const finalInit = retryBodyBuf !== null ? { ...retryInit, body: retryBodyBuf } : retryInit;
            if (isProtectedPath(finalUrl.pathname)) {
              try {
                const retryAtt = await buildRequestAttestationHeaders(retryMethod, finalUrl.pathname, signal);
                if (retryAtt.ok) {
                  _setAttestHeaders(retryHdrs, retryAtt.headers);
                  return origFetch(finalCanonUrl, finalInit);
                }
              } catch (_) {}
            } else {
              return origFetch(finalCanonUrl, finalInit);
            }
          }
        }
      }
      return resp;
    };
  }

  // Transparently instrument async XMLHttpRequest (Axios, jQuery, HTMX, Angular HttpClient)
  if (typeof XMLHttpRequest !== "undefined" && origFetch && DEFAULT_MODE !== "off" && !UNIFIED_MODE) {
    const OrigXHR = XMLHttpRequest;
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    const origAbort = XMLHttpRequest.prototype.abort;
    const origSetHdr = XMLHttpRequest.prototype.setRequestHeader;
    const origOverrideMime = XMLHttpRequest.prototype.overrideMimeType;
    const xhrMeta = new WeakMap();

    function clearShadowedXhrProps(xhr) {
      for (const p of ["readyState", "status", "statusText", "responseText", "responseXML", "response", "responseURL", "getResponseHeader", "getAllResponseHeaders"]) {
        try { delete xhr[p]; } catch (_) {}
      }
    }

    function failXhrCleanly(xhr, statusCode = 0, evName = "error") {
      try { origAbort.call(xhr); } catch (_) {}
      try {
        _defineProperty(xhr, "readyState", { value: 4, configurable: true });
        _defineProperty(xhr, "status", { value: statusCode, configurable: true });
      } catch (_) {}
      try { xhr.dispatchEvent(new Event("readystatechange")); } catch (_) {}
      if (typeof ProgressEvent !== "undefined") {
        try {
          xhr.dispatchEvent(new ProgressEvent(evName));
          xhr.dispatchEvent(new ProgressEvent("loadend"));
        } catch (_) {}
      }
    }

    function mirrorXhrHeaders(target, inner) {
      const def = (k, v) => { try { _defineProperty(target, k, { value: v, configurable: true }); } catch (_) {} };
      def("status", inner.status);
      def("statusText", inner.statusText);
      def("responseURL", inner.responseURL);
      def("getResponseHeader", (name) => { try { return inner.getResponseHeader(name); } catch (_) { return null; } });
      def("getAllResponseHeaders", () => { try { return inner.getAllResponseHeaders() || ""; } catch (_) { return ""; } });
    }

    function bindXhrBodyGetters(target, inner) {
      const defGet = (k, fn) => { try { _defineProperty(target, k, { get: fn, configurable: true }); } catch (_) {} };
      defGet("response", () => inner.response);
      if (!inner.responseType || inner.responseType === "text") {
        defGet("responseText", () => inner.responseText);
      }
      if (!inner.responseType || inner.responseType === "document") {
        defGet("responseXML", () => inner.responseXML);
      }
    }

    function mirrorXhrBody(target, inner) {
      const def = (k, v) => { try { _defineProperty(target, k, { value: v, configurable: true }); } catch (_) {} };
      try { def("response", inner.response); } catch (_) {}
      if (!inner.responseType || inner.responseType === "text") {
        try { def("responseText", inner.responseText); } catch (_) {}
      }
      if (!inner.responseType || inner.responseType === "document") {
        try { def("responseXML", inner.responseXML); } catch (_) {}
      }
    }

    function mirrorXhrAndFinish(target, inner, opId) {
      mirrorXhrHeaders(target, inner);
      mirrorXhrBody(target, inner);
      try { _defineProperty(target, "readyState", { value: 4, configurable: true }); } catch (_) {}
      try { target.dispatchEvent(new Event("readystatechange")); } catch (_) {}
      if (xhrMeta.get(target)?.opId !== opId) return;
      if (typeof ProgressEvent !== "undefined") {
        try {
          target.dispatchEvent(new ProgressEvent("load"));
          if (xhrMeta.get(target)?.opId === opId) target.dispatchEvent(new ProgressEvent("loadend"));
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
      if (prev && prev.innerXhr) {
        try { origAbort.call(prev.innerXhr); } catch (_) {}
        prev.innerXhr = null;
      }
      const opId = (prev ? prev.opId : 0) + 1;
      let resolvedUrl = null;
      try { resolvedUrl = new URL(String(url || ""), baseHref()); } catch (_) {}
      xhrMeta.set(this, {
        opId,
        method: String(method || "GET").toUpperCase(),
        url: resolvedUrl,
        asyncFlag: Boolean(asyncFlag),
        openArgs: Array.prototype.slice.call(arguments),
        overrideMime: null,
        headers: [],
        queued: false,
        abortController: null,
        innerXhr: null,
      });
      return origOpen.apply(this, arguments);
    };

    if (typeof origOverrideMime === "function") {
      XMLHttpRequest.prototype.overrideMimeType = function veilBreakXhrOverrideMime(mime) {
        const m = xhrMeta.get(this);
        if (m) m.overrideMime = String(mime);
        return origOverrideMime.call(this, mime);
      };
    }

    XMLHttpRequest.prototype.setRequestHeader = function veilBreakXhrSetHeader(name, value) {
      const m = xhrMeta.get(this);
      if (m && Array.isArray(m.headers)) m.headers.push([String(name), String(value)]);
      return origSetHdr.call(this, name, value);
    };

    XMLHttpRequest.prototype.abort = function veilBreakXhrAbort() {
      clearShadowedXhrProps(this);
      const m = xhrMeta.get(this);
      const wasActive = Boolean(m && (m.queued || m.innerXhr));
      if (m) {
        m.opId += 1;
        m.queued = false;
        if (m.abortController) {
          try { m.abortController.abort(); } catch (_) {}
          m.abortController = null;
        }
        if (m.innerXhr) {
          try { origAbort.call(m.innerXhr); } catch (_) {}
          m.innerXhr = null;
        }
      }
      const res = origAbort.call(this);
      if (wasActive && typeof ProgressEvent !== "undefined") {
        try {
          this.dispatchEvent(new ProgressEvent("abort"));
          this.dispatchEvent(new ProgressEvent("loadend"));
        } catch (_) {}
      }
      return res;
    };

    function runProtectedXhrAttempt(self, meta, opId, targetUrl, reqMethod, body, allowRetry, clickSnapAtCall = undefined, callTs = null) {
      const needsAttest =
        targetUrl.origin === window.location.origin &&
        !isGateControlPath(targetUrl.pathname) &&
        isProtectedPath(targetUrl.pathname);
      const ac = typeof AbortController !== "undefined" ? new AbortController() : null;
      meta.abortController = ac;
      meta.queued = true;
      const attPromise = needsAttest
        ? buildRequestAttestationHeaders(reqMethod, targetUrl.pathname, ac ? ac.signal : undefined, clickSnapAtCall, callTs)
        : Promise.resolve({ ok: true, headers: {} });
      attPromise
        .then((attRes) => {
          meta.queued = false;
          meta.abortController = null;
          if (xhrMeta.get(self)?.opId !== opId) return;
          if (!attRes.ok) {
            if (DEFAULT_MODE === "strict" || DEFAULT_MODE === "balanced" || DEFAULT_MODE === "paranoid") {
              failXhrCleanly(self, attRes.response ? attRes.response.status : 0, "error");
              return;
            }
            origSend.call(self, body);
            return;
          }
          const inner = new OrigXHR();
          meta.innerXhr = inner;
          const openCallArgs = [reqMethod, targetUrl.toString(), true];
          if (meta.openArgs && meta.openArgs.length > 3) openCallArgs.push(meta.openArgs[3]);
          if (meta.openArgs && meta.openArgs.length > 4) openCallArgs.push(meta.openArgs[4]);
          origOpen.apply(inner, openCallArgs);
          try { inner.withCredentials = self.withCredentials; } catch (_) {}
          try { if (self.responseType) inner.responseType = self.responseType; } catch (_) {}
          try { if (self.timeout) inner.timeout = self.timeout; } catch (_) {}
          if (meta.overrideMime && typeof origOverrideMime === "function") {
            try { origOverrideMime.call(inner, meta.overrideMime); } catch (_) {}
          }
          for (const [hk, hv] of meta.headers) {
            if (hk.toLowerCase().startsWith("x-vb-")) continue;
            try { origSetHdr.call(inner, hk, hv); } catch (_) {}
          }
          if (attRes.headers["X-VB-Ticket"] !== undefined) try { _reflectApply(origSetHdr, inner, ["X-VB-Ticket", attRes.headers["X-VB-Ticket"]]); } catch (_) {}
          if (attRes.headers["X-VB-Nonce"] !== undefined) try { _reflectApply(origSetHdr, inner, ["X-VB-Nonce", attRes.headers["X-VB-Nonce"]]); } catch (_) {}
          if (attRes.headers["X-VB-Attest"] !== undefined) try { _reflectApply(origSetHdr, inner, ["X-VB-Attest", attRes.headers["X-VB-Attest"]]); } catch (_) {}
          let headersMirrored = false;
          let bodyGettersBound = false;
          const ensureStreamMirrored = () => {
            if (!headersMirrored) { headersMirrored = true; mirrorXhrHeaders(self, inner); }
            if (!bodyGettersBound) { bodyGettersBound = true; bindXhrBodyGetters(self, inner); }
          };
          const proxyProg = (evName, srcTarget, dstTarget, guardRetry) => {
            if (!srcTarget || !dstTarget || typeof ProgressEvent === "undefined") return;
            srcTarget.addEventListener(evName, (ev) => {
              if (xhrMeta.get(self)?.opId !== opId) return;
              if (guardRetry && allowRetry && inner.status === 403) return;
              if (guardRetry) {
                ensureStreamMirrored();
              }
              try { dstTarget.dispatchEvent(new ProgressEvent(evName, { lengthComputable: ev.lengthComputable, loaded: ev.loaded, total: ev.total })); } catch (_) {}
            });
          };
          proxyProg("loadstart", inner, self, false);
          proxyProg("progress", inner, self, true);
          if (reqMethod !== "GET" && reqMethod !== "HEAD" && body != null && inner.upload && self.upload) {
            for (const uEv of ["loadstart", "progress", "load", "loadend", "error", "abort", "timeout"]) {
              proxyProg(uEv, inner.upload, self.upload, false);
            }
          }
          let emittedRs2 = false;
          let emittedRs3 = false;
          inner.onreadystatechange = () => {
            if (xhrMeta.get(self)?.opId !== opId) return;
            if (inner.readyState === 2 && !(allowRetry && inner.status === 403) && inner.status !== 0 && !emittedRs2) {
              emittedRs2 = true;
              if (!headersMirrored) { headersMirrored = true; mirrorXhrHeaders(self, inner); }
              try { _defineProperty(self, "readyState", { value: 2, configurable: true }); self.dispatchEvent(new Event("readystatechange")); } catch (_) {}
            } else if (inner.readyState === 3 && !(allowRetry && inner.status === 403) && inner.status !== 0 && !emittedRs3) {
              emittedRs3 = true;
              ensureStreamMirrored();
              try { _defineProperty(self, "readyState", { value: 3, configurable: true }); self.dispatchEvent(new Event("readystatechange")); } catch (_) {}
            }
          };
          // Completion mirroring exclusively in onload (so network errors/timeouts NEVER fire 'load' or duplicate readystatechange(4)!)
          inner.onload = () => {
            if (xhrMeta.get(self)?.opId !== opId) return;
            meta.innerXhr = null;
            if (allowRetry && inner.status === 403) {
              let retryHdr = "";
              let redirGetHdr = "";
              try {
                retryHdr = inner.getResponseHeader("X-VB-Retry-Ticket") || "";
                redirGetHdr = inner.getResponseHeader("X-VB-Redirect-Get") || "";
              } catch (_) {}
              if (retryHdr === "1") {
                runProtectedXhrAttempt(self, meta, opId, targetUrl, reqMethod, body, false, clickSnapAtCall, callTs);
                return;
              }
              const targetNoHash = targetUrl.origin + targetUrl.pathname + targetUrl.search;
              if (
                redirGetHdr === "1" ||
                (inner.responseURL && inner.responseURL !== targetNoHash)
              ) {
                let finalUrl = null;
                try { finalUrl = new URL(inner.responseURL || targetNoHash, baseHref()); } catch (_) {}
                let isVb403 = redirGetHdr === "1";
                if (!isVb403) {
                  try {
                    if (inner.getResponseHeader("X-VeilBreak-Mode")) isVb403 = true;
                    else if (inner.responseType === "json") isVb403 = Boolean(inner.response && inner.response.error === "VEILBREAK_DENIED");
                    else if (!inner.responseType || inner.responseType === "text") isVb403 = typeof inner.responseText === "string" && inner.responseText.includes('"VEILBREAK_DENIED"');
                    else if (finalUrl && isProtectedPath(finalUrl.pathname)) {
                      const ct403 = String(inner.getResponseHeader("content-type") || "").toLowerCase();
                      if (ct403.includes("json")) isVb403 = true;
                    }
                  } catch (_) {}
                }
                const destProtected = Boolean(finalUrl && isProtectedPath(finalUrl.pathname));
                if (isVb403 && finalUrl && finalUrl.origin === window.location.origin && !isGateControlPath(finalUrl.pathname) && (redirGetHdr === "1" || destProtected)) {
                  const isMutatingOrig = reqMethod !== "GET" && reqMethod !== "HEAD";
                  const preserveMutate = isMutatingOrig && redirGetHdr !== "1";
                  const nextMethod = preserveMutate ? reqMethod : (reqMethod === "HEAD" ? "HEAD" : "GET");
                  const nextBody = preserveMutate ? body : null;
                  runProtectedXhrAttempt(self, meta, opId, finalUrl, nextMethod, nextBody, false);
                  return;
                }
              }
            }
            mirrorXhrAndFinish(self, inner, opId);
          };
          inner.onerror = () => {
            if (xhrMeta.get(self)?.opId !== opId) return;
            meta.innerXhr = null;
            failXhrCleanly(self, 0, "error");
          };
          inner.ontimeout = () => {
            if (xhrMeta.get(self)?.opId !== opId) return;
            meta.innerXhr = null;
            failXhrCleanly(self, 0, "timeout");
          };
          origSend.call(inner, reqMethod !== "GET" && reqMethod !== "HEAD" ? body : null);
        })
        .catch(() => {
          meta.queued = false;
          meta.abortController = null;
          if (xhrMeta.get(self)?.opId === opId) {
            if (DEFAULT_MODE === "monitor") {
              try { origSend.call(self, body); } catch (_) {}
              return;
            }
            failXhrCleanly(self, 0, "error");
          }
        });
    }

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
      const isMutatingXhr = meta.method !== "GET" && meta.method !== "HEAD";
      const clickSnapAtCall = isMutatingXhr ? getFreshLastClick() : null;
      const callTs = _perfNow();
      runProtectedXhrAttempt(this, meta, meta.opId, reqUrl, meta.method, body, true, clickSnapAtCall, callTs);
    };
  }`) + `

  if (AUTO_BLOCK && DEFAULT_MODE !== "off" && DEFAULT_MODE !== "monitor") {
    const runPageBlock = async () => {
      try {
        const res = await verify({ mode: DEFAULT_MODE, antiCdp: DEFAULT_ANTI_CDP });
        window.__VEILBREAK_RESULT__ = res;
        // Require corroborating score >= 4 before destructive full-page DOM replacement so single +2 privacy quirks never wipe pages!
        if (res.blocked && res.score >= Math.max(4, res.threshold) && document.body) {
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
    else if (_isEmbeddedUnified) setTimeout(runPageBlock, 0);
    else runPageBlock();
  }

  const vbApi = Object.freeze({
    verify,
    collectHandshakeProof,
    detectCdpActive: () => detectCdpActive(true),
    evaluateClick: (ev, el, mode) => evaluateInteractionLocal(captureInteraction(ev, el, true), mode || DEFAULT_MODE),
    getLastInteraction: () => getFreshLastClick(false),
    version: VERSION,
    mode: DEFAULT_MODE,
    unified: UNIFIED_MODE,
    antiCdp: DEFAULT_ANTI_CDP,
  });
  // Private lexical closure registration when embedded inside ProxySnare's unified bundle (unreachable from window / Symbol.for / MutationObserver!)
  try {
    if (typeof __VB_PRIVATE_REGISTER__ === "function") __VB_PRIVATE_REGISTER__(vbApi);
  } catch (_) {}
  if (BRIDGE_TOKEN) {
    try {
      if (!_SymbolFor || _symbolForTampered) {
        _bridgeTampered = true;
      } else {
        const bridgeSym = _SymbolFor("__VB_CH_" + BRIDGE_TOKEN);
        if (_reflectApply(_hasOwn, window, [bridgeSym])) {
          _bridgeTampered = true;
          try { _defData(window, _SymbolFor("__VB_BRIDGE_TAMPERED__"), true, false, false, false); } catch (_) {}
        } else {
          _defData(window, bridgeSym, vbApi, false, false, false);
        }
      }
    } catch (_) {
      _bridgeTampered = true;
    }
  }
  try {
    if (_SymbolFor) {
      const intSym = _SymbolFor("__VEILBREAK_INTERNAL__");
      if (_reflectApply(_hasOwn, window, [intSym])) {
        if (!_legitPreloadedStandaloneGate) {
          _bridgeTampered = true;
          try { _defData(window, _SymbolFor("__VB_BRIDGE_TAMPERED__"), true, false, false, false); } catch (_) {}
        }
      } else {
        _defData(window, intSym, vbApi, false, false, false);
      }
    }
  } catch (_) {
    if (!_legitPreloadedStandaloneGate) {
      _bridgeTampered = true;
      try { if (_SymbolFor) _defData(window, _SymbolFor("__VB_BRIDGE_TAMPERED__"), true, false, false, false); } catch (_) {}
    }
  }
  try {
    _defData(window, "VeilBreak", vbApi, false, false, true);
  } catch (_) {
    if (!_legitPreloadedStandaloneGate) {
      _bridgeTampered = true;
    }
  }
  // Pre-warm hardware probes off the render-blocking <head> critical path (zero FCP stall while intrinsics & fetch/XHR are already locked!)
  if (UNIFIED_MODE && DEFAULT_MODE !== "off") {
    const prewarm = () => {
      try { _reflectApply(_nativePromiseThen, getProbePromise(DEFAULT_ANTI_CDP, DEFAULT_MODE, DEFAULT_ALLOW_DEVTOOLS), [() => {}, () => {}]); } catch (_) {}
    };
    if (typeof setTimeout === "function") setTimeout(prewarm, 0);
    else prewarm();
  }
})();
`);
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
