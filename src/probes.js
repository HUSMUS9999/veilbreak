"use strict";

const crypto = require("node:crypto");

const VALID_MODES = new Set(["off", "monitor", "balanced", "strict"]);

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
    throw new Error(`Invalid VeilBreak mode '${mode}': expected 'off', 'monitor', 'balanced', or 'strict'`);
  }
  return m;
}

function thresholdForMode(mode) {
  const m = normalizeMode(mode);
  if (m === "strict") return 2;
  if (m === "balanced") return 4;
  return Number.POSITIVE_INFINITY;
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s || ""), "utf8").digest("hex");
}

function safeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length || a.length === 0) {
    return false;
  }
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
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
 * Catches synthetic JS clicks (`isTrusted === false`) and programmatic CDP/Juggler
 * teleport clicks (`<= 3` pointermoves, sub-12ms pointerdown->click dwell, exact center hit)
 * while exempting trusted keyboard activation (`isTrusted && detail === 0`) and
 * touch/pen pointer types (`pointerType === "touch" | "pen"`).
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

    // Exempt keyboard activation (Enter/Space on focused control -> isTrusted=true, detail=0)
    if (detail >= 1) {
      if (moves <= 3 && dwellMs >= 0 && dwellMs < 12 && hitCenter) {
        score += 4;
        reasons.push("TELEPORT_CLICK_PHYSICS");
      } else if (moves === 0 && dwellMs > 0 && dwellMs < 8) {
        // Require dwellMs > 0 so coarsened 100ms privacy timers (dwellMs === 0) don't false-positive
        score += 4;
        reasons.push("ZERO_TRAJECTORY_INSTANT_CLICK");
      }
    }
  }

  const blocked = m !== "monitor" && score >= threshold;
  return { ok: !blocked, blocked, score, threshold, mode: m, reasons };
}

function buildAttestation({ mode = "strict", ticket = "", nonce = "", telemetry = {}, antiCdp = true } = {}) {
  const m = normalizeMode(mode);
  if (m === "off") return null;
  const ev = evaluateTelemetry(telemetry, { mode: m, antiCdp });
  const safeTicket = String(ticket || "").replace(/\|/g, "");
  const safeNonce = String(nonce || "").replace(/\|/g, "");
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

  // 1. Headless / automation User-Agent or Sec-CH-UA check (enforced in BOTH strict & balanced!)
  if (
    (m === "strict" || m === "balanced") &&
    (/HeadlessChrome|Playwright|Puppeteer|PhantomJS|SlimerJS/i.test(ua) || /HeadlessChrome/i.test(secChUa))
  ) {
    reasons.push("AUTOMATION_UA_DENIED");
    score += 6;
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
  const chromeVerMatch = ua.match(/Chrome\/(\d+)/);
  if (chromeVerMatch && Number(chromeVerMatch[1]) >= 115 && secChUa.includes('" Not A;Brand";v="99"')) {
    reasons.push("SEC_CH_UA_GREASE_LIE");
    score += 2;
  }

  // 4. Parse & strictly validate VB_ATTEST_V2 telemetry envelope (matches Python verifier parity)
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

    const validNums =
      (v === undefined || v === 2) &&
      typeof s === "number" &&
      Number.isInteger(s) &&
      s >= 0 &&
      s <= 10_000 &&
      typeof f === "number" &&
      Number.isInteger(f) &&
      f >= 0 &&
      f <= 0xfffff;
    const validDelims = !tkStr.includes("|") && !nnStr.includes("|") && !p.includes("|");
    const validHexDigest = /^[0-9a-f]{64}$/i.test(d);
    const coherentFlagScore = !(f > 0 && s === 0);

    if (!validNums || !validDelims || !validHexDigest || !coherentFlagScore) {
      reasons.push("ATTEST_INVALID");
      score += 6;
    } else {
      const expectedV2 = sha256Hex(`VB_ATTEST_V2|${tkStr}|${nnStr}|${s}|${f}|${p}`);
      if (!safeEqualHex(d.toLowerCase(), expectedV2)) {
        reasons.push("ATTEST_DIGEST_MISMATCH");
        score += 6;
      }
      score += s;
      const decoded = decodeFlags(f);
      if (decoded.length > 0) {
        for (const r of decoded) {
          if (!reasons.includes(r)) reasons.push(r);
        }
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
    reasons.includes("AUTOMATION_UA_DENIED");
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
  sha256Hex,
};
