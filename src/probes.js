"use strict";

const crypto = require("node:crypto");
const path = require("node:path");

const VALID_MODES = new Set(["off", "monitor", "observe", "balanced", "strict"]);

const AUTOMATION_OR_CLI_UA_RE =
  /HeadlessChrome|Playwright|Puppeteer|PhantomJS|SlimerJS|curl\/|wget\/|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|httpie|libwww-perl|java\/|okhttp|axios\/|node-fetch|undici|burp|caido|mitmproxy|insomnia|postman|sqlmap|ffuf|nuclei/i;

const PROXY_LEAK_HEADERS = [
  "proxy-connection",
  "x-burp-header",
  "x-burp-collaborator",
  "x-caido-id",
  "x-caido-replay",
  "x-mitmproxy",
];

// Bitmask flags for compact wire telemetry envelope (VB_ATTEST_V2)
const FLAG = Object.freeze({
  CANVAS2D_NOISE: 1 << 0,            // 1
  WEBGL_CLEAR_NOISE: 1 << 1,         // 2
  SILENT_AUDIO_NOISE: 1 << 2,        // 4
  DOMRECT_POISONING: 1 << 3,         // 8
  OS_CORE_FONT_LIE: 1 << 4,          // 16
  WEBGL_HARDWARE_LIE: 1 << 5,        // 32
  WEBDRIVER_FLAG: 1 << 6,            // 64
  CDP_RUNTIME_ENABLE: 1 << 7,        // 128
  AUTOMATION_GLOBAL: 1 << 8,         // 256
  WEBDRIVER_GETTER_SPOOF: 1 << 9,    // 512
  NATIVE_FN_TAMPERED: 1 << 10,       // 1024
  WORKER_CONTRADICTION: 1 << 11,     // 2048
  VIEWPORT_IMPOSSIBILITY: 1 << 12,   // 4096
  ENGINE_COHERENCE_LIE: 1 << 13,     // 8192
  SYNTHETIC_INTERACTION: 1 << 14,    // 16384
});

const FLAG_REASON_MAP = Object.freeze([
  [FLAG.CANVAS2D_NOISE, "CANVAS2D_SYNTHETIC_NOISE"],
  [FLAG.WEBGL_CLEAR_NOISE, "WEBGL_CLEAR_SYNTHETIC_NOISE"],
  [FLAG.SILENT_AUDIO_NOISE, "SILENT_AUDIO_SYNTHETIC_NOISE"],
  [FLAG.DOMRECT_POISONING, "DOMRECT_SUBPIXEL_POISONING"],
  [FLAG.OS_CORE_FONT_LIE, "OS_CORE_FONT_LIE"],
  [FLAG.WEBGL_HARDWARE_LIE, "WEBGL_HARDWARE_COHERENCE_LIE"],
  [FLAG.WEBDRIVER_FLAG, "WEBDRIVER_FLAG"],
  [FLAG.CDP_RUNTIME_ENABLE, "CDP_RUNTIME_ENABLE"],
  [FLAG.AUTOMATION_GLOBAL, "AUTOMATION_GLOBAL_ARTIFACT"],
  [FLAG.WEBDRIVER_GETTER_SPOOF, "WEBDRIVER_GETTER_SPOOFED"],
  [FLAG.NATIVE_FN_TAMPERED, "NATIVE_FUNCTION_TAMPERED"],
  [FLAG.WORKER_CONTRADICTION, "WORKER_REALM_CONTRADICTION"],
  [FLAG.VIEWPORT_IMPOSSIBILITY, "VIEWPORT_GEOMETRY_IMPOSSIBILITY"],
  [FLAG.ENGINE_COHERENCE_LIE, "ENGINE_COHERENCE_LIE"],
  [FLAG.SYNTHETIC_INTERACTION, "SYNTHETIC_INTERACTION"],
]);

function decodeFlags(flags) {
  const out = [];
  for (const [bit, name] of FLAG_REASON_MAP) {
    if ((flags & bit) !== 0) out.push(name);
  }
  return out;
}

function normalizeMode(mode = "strict") {
  const m = String(mode || "strict").trim().toLowerCase();
  if (!VALID_MODES.has(m)) {
    throw new Error(`Invalid VeilBreak mode '${mode}': expected 'off', 'monitor', 'observe', 'balanced', or 'strict'`);
  }
  return m === "observe" ? "monitor" : m;
}

function thresholdForMode(mode) {
  const m = normalizeMode(mode);
  if (m === "strict") return 2;
  if (m === "balanced") return 4;
  return Number.POSITIVE_INFINITY;
}

function sha256Buf(s) {
  const data = Buffer.isBuffer(s) || ArrayBuffer.isView(s) ? s : Buffer.from(String(s || ""), "utf8");
  return crypto.createHash("sha256").update(data).digest();
}

function sha256Hex(s) {
  return sha256Buf(s).toString("hex");
}

function safeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length || a.length === 0) {
    return false;
  }
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function countLeadingZeroBits(buf) {
  let bits = 0;
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

function verifyPowSolution(ticket, challenge, powNonce, difficulty) {
  if (!Number.isInteger(difficulty) || difficulty <= 0) return true;
  if (typeof ticket !== "string" || !ticket || typeof challenge !== "string" || !challenge) return false;
  if (typeof powNonce !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(powNonce)) return false;
  const digest = sha256Buf(`VB_POW_V2|${ticket}|${challenge}|${powNonce}`);
  return countLeadingZeroBits(digest) >= difficulty;
}

function solvePowChallenge(ticket, challenge, difficulty) {
  if (!Number.isInteger(difficulty) || difficulty <= 0) return "0";
  for (let i = 0; i < 10_000_000; i++) {
    const nonce = i.toString(36);
    if (countLeadingZeroBits(sha256Buf(`VB_POW_V2|${ticket}|${challenge}|${nonce}`)) >= difficulty) {
      return nonce;
    }
  }
  throw new Error("VB_POW_SOLVE_EXCEEDED_LIMIT");
}

function getHeader(headers, name) {
  if (!headers || typeof headers !== "object") return "";
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) {
      return Array.isArray(v) ? v.join(", ") : String(v ?? "");
    }
  }
  return "";
}

function hasHeader(headers, name) {
  if (!headers || typeof headers !== "object") return false;
  const target = name.toLowerCase();
  return Object.keys(headers).some((k) => k.toLowerCase() === target);
}

function isAutomationOrCliUa(headers) {
  const ua = getHeader(headers, "user-agent").trim();
  const ch = getHeader(headers, "sec-ch-ua");
  if (!ua) return true;
  return AUTOMATION_OR_CLI_UA_RE.test(ua) || /HeadlessChrome/i.test(ch);
}

function decodePercentLenient(s) {
  return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
    let out = "";
    let i = 0;
    while (i < run.length) {
      const b = parseInt(run.slice(i + 1, i + 3), 16);
      if (b === 0x00) {
        out += "\0";
        i += 3;
        continue;
      }
      if (b >= 0x01 && b <= 0x7f) {
        out += String.fromCharCode(b);
        i += 3;
        continue;
      }
      let matched = false;
      for (const n of [2, 3, 4]) {
        if (i + n * 3 <= run.length) {
          const sub = run.slice(i, i + n * 3);
          try {
            out += decodeURIComponent(sub);
            i += n * 3;
            matched = true;
            break;
          } catch {}
        }
      }
      if (!matched) {
        out += run.slice(i, i + 3);
        i += 3;
      }
    }
    return out;
  });
}

function stripSchemeAndAuthority(rawUrl) {
  let s = String(rawUrl || "/").trimStart();
  if (!s) return "/";
  if (/^https?:\/\//i.test(s)) {
    const afterScheme = s.indexOf("://") + 3;
    const slashIdx = s.indexOf("/", afterScheme);
    const backslashIdx = s.indexOf("\\", afterScheme);
    const qIdx = s.indexOf("?", afterScheme);
    const hIdx = s.indexOf("#", afterScheme);
    const cuts = [slashIdx, backslashIdx, qIdx, hIdx].filter((i) => i >= 0);
    if (cuts.length === 0) return "/";
    const first = Math.min(...cuts);
    if (s[first] === "/") s = s.slice(first);
    else if (s[first] === "\\") s = "/" + s.slice(first + 1);
    else s = "/" + s.slice(first);
  }
  return s;
}

function cleanPathNoCollapse(rawPath) {
  let s = String(rawPath || "/").replace(/\\/g, "/").replace(/\0.*$/, "");
  if (!s.startsWith("/")) s = "/" + s;
  s = s
    .split("/")
    .map((seg) => seg.split(";")[0])
    .join("/")
    .replace(/\/+/g, "/");
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s || "/";
}

function trimSegmentNoise(normPath) {
  let s = String(normPath || "/")
    .split("/")
    .map((seg) => seg.replace(/[\s.]+$/, ""))
    .join("/")
    .replace(/\/+/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s || "/";
}

function normalizePathname(rawUrl) {
  let s = stripSchemeAndAuthority(rawUrl);
  const qIdx = s.indexOf("?");
  if (qIdx >= 0) s = s.slice(0, qIdx);
  if (!s) return "/";
  for (let pass = 0; pass < 2; pass++) {
    const dec = decodePercentLenient(s);
    if (dec === s) break;
    s = dec;
  }
  s = s.replace(/\0/g, "").replace(/\\/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  s = s
    .split("/")
    .map((seg) => seg.split(";")[0])
    .join("/");
  s = path.posix.normalize(s);
  if (!s.startsWith("/")) s = "/" + s;
  if (s.length > 1) s = s.replace(/\/+$/, "");
  s = s.replace(/\?/g, "%3F");
  return s;
}

function expandPathCandidates(rawUrl) {
  const raw = stripSchemeAndAuthority(rawUrl);
  const qIdx = raw.indexOf("?");
  const rawPath = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
  const set = new Set();

  const addAll = (val) => {
    const n1 = normalizePathname(val);
    const n2 = cleanPathNoCollapse(val);
    set.add(n1);
    set.add(n2);
    set.add(trimSegmentNoise(n1));
    set.add(trimSegmentNoise(n2));
  };

  addAll(rawPath);

  const rawHash = rawPath.indexOf("#");
  if (rawHash >= 0) {
    addAll(rawPath.slice(0, rawHash));
  }

  let dec = rawPath;
  for (let pass = 0; pass < 2; pass++) {
    const next = decodePercentLenient(dec);
    if (next === dec) break;
    dec = next;
  }
  addAll(dec);

  const nullIdx = dec.indexOf("\0");
  if (nullIdx >= 0) addAll(dec.slice(0, nullIdx));

  const decQ = dec.indexOf("?");
  if (decQ >= 0) addAll(dec.slice(0, decQ));
  const decH = dec.indexOf("#");
  if (decH >= 0) addAll(dec.slice(0, decH));

  return Array.from(set);
}

function isProtectedPath(rawUrl, protectedPaths) {
  const candidates = expandPathCandidates(rawUrl);
  for (const norm of candidates) {
    const normLower = norm.toLowerCase();
    for (const rule of protectedPaths) {
      if (rule instanceof RegExp) {
        rule.lastIndex = 0;
        if (rule.test(norm)) return true;
      } else {
        const rawRule = String(rule).trim();
        if (rawRule === "*") return true;
        const rNorm = normalizePathname(rawRule).toLowerCase();
        if (
          rNorm === "/" ||
          normLower === rNorm ||
          normLower.startsWith(rNorm.endsWith("/") ? rNorm : `${rNorm}/`)
        ) {
          return true;
        }
      }
    }
  }
  return false;
}

/**
 * Stage 1: Evaluates all 14 physics, graphics, audio, cross-realm, prototype,
 * geometry, and engine-coherence invariants.
 */
function evaluateTelemetry(telemetry = {}, { mode = "strict", antiCdp = true } = {}) {
  const m = normalizeMode(mode);
  const threshold = thresholdForMode(m);
  if (m === "off") {
    return { ok: true, blocked: false, score: 0, flags: 0, threshold, mode: m, platform: "", reasons: [] };
  }

  let score = 0;
  let flags = 0;
  const reasons = [];

  if (antiCdp && (telemetry.webdriver || telemetry.freshIframeWebdriver)) {
    score += 4;
    flags |= FLAG.WEBDRIVER_FLAG;
    reasons.push("WEBDRIVER_FLAG");
  }
  if (antiCdp && telemetry.automationGlobalArtifact) {
    score += 4;
    flags |= FLAG.AUTOMATION_GLOBAL;
    reasons.push("AUTOMATION_GLOBAL_ARTIFACT");
  }
  if (antiCdp && telemetry.cdpRuntimeEnable) {
    score += 4;
    flags |= FLAG.CDP_RUNTIME_ENABLE;
    reasons.push("CDP_RUNTIME_ENABLE");
  }
  if (telemetry.webdriverGetterSpoofed) {
    score += 4;
    flags |= FLAG.WEBDRIVER_GETTER_SPOOF;
    reasons.push("WEBDRIVER_GETTER_SPOOFED");
  }
  if (telemetry.nativeFunctionTampered) {
    score += 4;
    flags |= FLAG.NATIVE_FN_TAMPERED;
    reasons.push("NATIVE_FUNCTION_TAMPERED");
  }
  if (telemetry.workerRealmContradiction) {
    score += 4;
    flags |= FLAG.WORKER_CONTRADICTION;
    reasons.push("WORKER_REALM_CONTRADICTION");
  }

  const c2Uniq = telemetry.canvas2dUniqueColors ?? 1;
  const c2Rep = telemetry.canvas2dRepeatDiff ?? 0;
  const ocUniq = telemetry.offscreenCanvasUniqueColors ?? 1;
  if (c2Uniq > 1 || ocUniq > 1 || c2Rep > 0) {
    score += c2Rep > 0 ? 4 : 2;
    flags |= FLAG.CANVAS2D_NOISE;
    reasons.push(c2Rep > 0 ? "CANVAS2D_NON_DETERMINISTIC" : "CANVAS2D_SYNTHETIC_NOISE");
  }

  if ((telemetry.webglClearUniqueColors ?? 1) > 1) {
    score += 2;
    flags |= FLAG.WEBGL_CLEAR_NOISE;
    reasons.push("WEBGL_CLEAR_SYNTHETIC_NOISE");
  }

  if (telemetry.webglHardwareLie) {
    score += 2;
    flags |= FLAG.WEBGL_HARDWARE_LIE;
    reasons.push("WEBGL_HARDWARE_COHERENCE_LIE");
  }

  if ((telemetry.silentAudioNonZeroSamples ?? 0) > 0) {
    score += 2;
    flags |= FLAG.SILENT_AUDIO_NOISE;
    reasons.push("SILENT_AUDIO_SYNTHETIC_NOISE");
  }

  if (telemetry.domRectSubpixelDrift) {
    score += 2;
    flags |= FLAG.DOMRECT_POISONING;
    reasons.push("DOMRECT_SUBPIXEL_POISONING");
  }

  if (telemetry.osFontLie) {
    score += 2;
    flags |= FLAG.OS_CORE_FONT_LIE;
    reasons.push("OS_CORE_FONT_LIE");
  }

  if (telemetry.viewportGeometryImpossibility) {
    score += 2;
    flags |= FLAG.VIEWPORT_IMPOSSIBILITY;
    reasons.push("VIEWPORT_GEOMETRY_IMPOSSIBILITY");
  }

  if (telemetry.engineCoherenceLie) {
    score += 2;
    flags |= FLAG.ENGINE_COHERENCE_LIE;
    reasons.push("ENGINE_COHERENCE_LIE");
  }

  if (telemetry.interaction && typeof telemetry.interaction === "object") {
    const ik = evaluateInteraction(telemetry.interaction, { mode: m });
    if (ik.score > 0) {
      score += ik.score;
      flags |= FLAG.SYNTHETIC_INTERACTION;
      reasons.push(...ik.reasons);
    }
  }

  const blocked = m !== "monitor" && score >= threshold;
  return {
    ok: !blocked,
    blocked,
    score,
    flags,
    threshold,
    mode: m,
    platform: String(telemetry.platform || "").replace(/\|/g, "").slice(0, 48),
    reasons,
  };
}

/**
 * Stage 2: Biomechanical Interaction Kinematics Guard.
 */
function evaluateInteraction(interaction = {}, { mode = "strict" } = {}) {
  const m = normalizeMode(mode);
  const threshold = thresholdForMode(m);
  if (m === "off" || !interaction || typeof interaction !== "object") {
    return { ok: true, blocked: false, score: 0, threshold, mode: m, reasons: [] };
  }

  let score = 0;
  const reasons = [];
  const pType = String(interaction.pointerType || "mouse").toLowerCase();

  if (interaction.isTrusted === false) {
    score += 6;
    reasons.push("UNTRUSTED_SYNTHETIC_CLICK");
  } else if (interaction.isTrusted === true && pType !== "touch" && pType !== "pen") {
    const detail = Number(interaction.detail ?? 1);
    const moves = Number(interaction.pointerMoves ?? 99);
    const dwellMs = Number(interaction.dwellMs ?? 99);
    const hitCenter = Boolean(interaction.hitExactCenter);

    if (detail >= 1) {
      if (moves <= 3 && dwellMs >= 0 && dwellMs < 12 && hitCenter) {
        score += 4;
        reasons.push("TELEPORT_CLICK_PHYSICS");
      } else if (moves === 0 && dwellMs > 0 && dwellMs < 8 && hitCenter) {
        score += 4;
        reasons.push("ZERO_TRAJECTORY_INSTANT_CLICK");
      }
    }
  }

  const blocked = m !== "monitor" && score >= threshold;
  return { ok: !blocked, blocked, score, threshold, mode: m, reasons };
}

function buildAttestation({
  mode = "strict",
  ticket = "",
  nonce = "",
  telemetry = {},
  antiCdp = true,
  challenge = "",
  difficulty = 0,
  powNonce = null,
  method = "",
  path: reqPath = "",
} = {}) {
  const m = normalizeMode(mode);
  if (m === "off") return null;
  const ev = evaluateTelemetry(telemetry, { mode: m, antiCdp });
  const safeTicket = String(ticket || "").replace(/\|/g, "");
  const safeNonce = String(nonce || "").replace(/\|/g, "");
  const safeChallenge = String(challenge || "").replace(/\|/g, "");
  const safeMethod = String(method || "").trim().toUpperCase().replace(/\|/g, "");
  const safePath = reqPath ? normalizePathname(String(reqPath)).replace(/\|/g, "") : "";

  if (safeChallenge) {
    const solved =
      powNonce !== null && powNonce !== undefined
        ? String(powNonce).replace(/\|/g, "")
        : solvePowChallenge(safeTicket, safeChallenge, difficulty || 0);
    const digest = sha256Hex(
      `VB_ATTEST_V2|${safeTicket}|${safeNonce}|${ev.score}|${ev.flags}|${ev.platform}|${safeChallenge}|${solved}|${safeMethod}|${safePath}`
    );
    return {
      v: 2,
      s: ev.score,
      f: ev.flags,
      p: ev.platform,
      w: solved,
      m: safeMethod,
      u: safePath,
      d: digest,
      r: ev.reasons,
      blocked: ev.blocked,
    };
  }

  const digest = sha256Hex(`VB_ATTEST_V2|${safeTicket}|${safeNonce}|${ev.score}|${ev.flags}|${ev.platform}`);
  return {
    v: 2,
    s: ev.score,
    f: ev.flags,
    p: ev.platform,
    d: digest,
    r: ev.reasons,
    blocked: ev.blocked,
  };
}

function verifyAttestation({
  mode = "strict",
  headers = {},
  attest = null,
  ticket = "",
  nonce = "",
  expectedChallenge = "",
  expectedDifficulty = 0,
  expectedMethod = "",
  expectedPath = "",
  requireFetchMetadata = false,
} = {}) {
  const m = normalizeMode(mode);
  const threshold = thresholdForMode(m);
  if (m === "off") {
    return { ok: true, blocked: false, score: 0, threshold, mode: m, reasons: [] };
  }

  const reasons = [];
  let score = 0;
  const ua = getHeader(headers, "user-agent");
  const secChUa = getHeader(headers, "sec-ch-ua");
  const secChPlat = getHeader(headers, "sec-ch-ua-platform").replace(/"/g, "").toLowerCase();
  const sfs = getHeader(headers, "sec-fetch-site").trim().toLowerCase();
  const sfm = getHeader(headers, "sec-fetch-mode").trim().toLowerCase();
  const cl = getHeader(headers, "content-length");
  const te = getHeader(headers, "transfer-encoding");

  // 0. Smuggling & proxy header leak checks
  if (cl && te) {
    reasons.push("CL_TE_SMUGGLING");
    score += 10;
  }
  for (const ph of PROXY_LEAK_HEADERS) {
    if (hasHeader(headers, ph)) {
      reasons.push("PROXY_HEADER_LEAK");
      score += 6;
      break;
    }
  }

  // 1. Headless / automation / CLI / proxy User-Agent or Sec-CH-UA check (strict & balanced)
  if ((m === "strict" || m === "balanced") && isAutomationOrCliUa(headers)) {
    reasons.push("AUTOMATION_UA_DENIED");
    score += 6;
  }

  // 1b. Cross-site & Fetch Metadata coherence check
  if (sfs.includes("cross-site")) {
    reasons.push("CROSS_SITE_REQUEST_DENIED");
    score += 6;
  }
  const chromeMatch = /Chrome\/(\d+)/i.exec(ua);
  const ffMatch = /Firefox\/(\d+)/i.exec(ua);
  const claimsModern = (chromeMatch && Number(chromeMatch[1]) >= 80) || (ffMatch && Number(ffMatch[1]) >= 90);
  if (requireFetchMetadata && claimsModern && !isAutomationOrCliUa(headers)) {
    if (!sfs || (sfs !== "same-origin" && sfs !== "same-site") || !sfm) {
      reasons.push("FETCH_METADATA_MISSING");
      score += 4;
    }
  }

  // 2. OS header contradiction check
  const uaLinux = ua.includes("Linux") && !ua.includes("Android");
  const uaWin = ua.includes("Windows NT");
  const uaMac = ua.includes("Macintosh");
  if (secChPlat) {
    if (
      (uaLinux && (secChPlat === "windows" || secChPlat === "macos")) ||
      (uaWin && (secChPlat === "linux" || secChPlat === "macos")) ||
      (uaMac && (secChPlat === "windows" || secChPlat === "linux"))
    ) {
      reasons.push("OS_HEADER_CONTRADICTION");
      score += 4;
    }
  }

  // 3. Legacy GREASE / Chrome version contradiction
  if (chromeMatch && Number(chromeMatch[1]) >= 115 && secChUa.includes('" Not A;Brand";v="99"')) {
    reasons.push("SEC_CH_UA_GREASE_LIE");
    score += 2;
  }

  // 4. Parse & strictly validate VB_ATTEST_V2 telemetry envelope
  let attObj = attest;
  if (typeof attObj === "string") {
    const trimmed = attObj.trim();
    if (!trimmed) {
      attObj = null;
    } else {
      try {
        attObj = JSON.parse(trimmed);
      } catch {
        attObj = { invalid: true };
      }
    }
  }

  const tkStr = String(ticket ?? "");
  const nnStr = String(nonce ?? "");
  const expChal = String(expectedChallenge ?? "");
  const expDiff = Number.isInteger(expectedDifficulty) && expectedDifficulty > 0 ? expectedDifficulty : 0;
  const expMethod = String(expectedMethod || "").trim().toUpperCase();
  const expPath = expectedPath ? normalizePathname(String(expectedPath)) : "";

  if (attObj === null || attObj === undefined) {
    if (m === "strict" || m === "balanced") {
      reasons.push("ATTEST_REQUIRED");
      score += 6;
    }
  } else if (typeof attObj !== "object" || Array.isArray(attObj)) {
    reasons.push("ATTEST_INVALID");
    score += 6;
  } else {
    const v = attObj.v;
    const s = attObj.s;
    const f = attObj.f;
    const pRaw = attObj.p === null || attObj.p === undefined ? "" : String(attObj.p);
    const p = pRaw.slice(0, 48);
    const d = typeof attObj.d === "string" ? attObj.d : "";
    const w = attObj.w === undefined || attObj.w === null ? "" : String(attObj.w);
    const attM = attObj.m === undefined || attObj.m === null ? "" : String(attObj.m).trim().toUpperCase();
    const attU = attObj.u === undefined || attObj.u === null ? "" : String(attObj.u);

    const DEFINED_FLAG_MASK = 0x7fff;
    const minScoreForFlags = (bits) => {
      let minScore = 0;
      const weights = [2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 4, 4, 2, 2, 4];
      for (let i = 0; i < weights.length; i++) {
        if ((bits & (1 << i)) !== 0) minScore += weights[i];
      }
      return minScore;
    };

    const validNums =
      (v === undefined || v === 2) &&
      typeof s === "number" &&
      Number.isInteger(s) &&
      s >= 0 &&
      s <= 10_000 &&
      typeof f === "number" &&
      Number.isInteger(f) &&
      f >= 0 &&
      f <= DEFINED_FLAG_MASK;
    const validDelims =
      !tkStr.includes("|") &&
      !nnStr.includes("|") &&
      !p.includes("|") &&
      !w.includes("|") &&
      !attM.includes("|") &&
      !attU.includes("|");
    const validHexDigest = /^[0-9a-f]{64}$/i.test(d);
    const coherentFlagScore = validNums && s >= minScoreForFlags(f);
    const validNonce = !expChal || /^[A-Za-z0-9_-]{8,64}$/.test(nnStr);

    if (!validNums || !validDelims || !validHexDigest || !coherentFlagScore || !validNonce) {
      reasons.push("ATTEST_INVALID");
      score += 6;
    } else {
      if (expChal) {
        if (expDiff > 0 && !verifyPowSolution(tkStr, expChal, w, expDiff)) {
          reasons.push("POW_INVALID");
          score += 6;
        }
        if (expMethod && attM !== expMethod) {
          reasons.push("REQUEST_BINDING_MISMATCH");
          score += 6;
        }
        if (expPath && (!attU || normalizePathname(attU) !== expPath)) {
          if (!reasons.includes("REQUEST_BINDING_MISMATCH")) {
            reasons.push("REQUEST_BINDING_MISMATCH");
            score += 6;
          }
        }
        const expectedV2 = sha256Hex(
          `VB_ATTEST_V2|${tkStr}|${nnStr}|${s}|${f}|${p}|${expChal}|${w}|${attM}|${attU}`
        );
        if (!safeEqualHex(d.toLowerCase(), expectedV2)) {
          reasons.push("ATTEST_DIGEST_MISMATCH");
          score += 6;
        }
      } else {
        const expectedV2 = sha256Hex(`VB_ATTEST_V2|${tkStr}|${nnStr}|${s}|${f}|${p}`);
        if (!safeEqualHex(d.toLowerCase(), expectedV2)) {
          reasons.push("ATTEST_DIGEST_MISMATCH");
          score += 6;
        }
      }

      score += s;
      const decoded = decodeFlags(f);
      for (const r of decoded) {
        if (!reasons.includes(r)) reasons.push(r);
      }
      if (s >= threshold) {
        reasons.push("BROWSER_INVARIANTS_FAILED");
      }
      if (
        (uaLinux && (p.startsWith("Win") || p === "MacIntel")) ||
        (uaWin && (p.startsWith("Linux") || p === "MacIntel")) ||
        (uaMac && (p.startsWith("Win") || p.startsWith("Linux")))
      ) {
        reasons.push("OS_PLATFORM_CONTRADICTION");
        score += 4;
      }
    }
  }

  const hardFail =
    reasons.includes("ATTEST_REQUIRED") ||
    reasons.includes("ATTEST_INVALID") ||
    reasons.includes("ATTEST_DIGEST_MISMATCH") ||
    reasons.includes("AUTOMATION_UA_DENIED") ||
    reasons.includes("POW_INVALID") ||
    reasons.includes("REQUEST_BINDING_MISMATCH") ||
    reasons.includes("CROSS_SITE_REQUEST_DENIED") ||
    reasons.includes("CL_TE_SMUGGLING") ||
    reasons.includes("PROXY_HEADER_LEAK");
  const blocked = m !== "monitor" && (score >= threshold || hardFail);
  return {
    ok: !blocked,
    blocked,
    score,
    threshold,
    mode: m,
    reasons,
  };
}

module.exports = {
  FLAG,
  decodeFlags,
  normalizeMode,
  thresholdForMode,
  evaluateTelemetry,
  evaluateInteraction,
  buildAttestation,
  verifyAttestation,
  isAutomationOrCliUa,
  verifyPowSolution,
  solvePowChallenge,
  normalizePathname,
  stripSchemeAndAuthority,
  expandPathCandidates,
  isProtectedPath,
  sha256Hex,
};
