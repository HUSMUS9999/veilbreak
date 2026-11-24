"use strict";

const crypto = require("node:crypto");

const VALID_MODES = new Set(["off", "monitor", "balanced", "strict"]);

function normalizeMode(mode = "strict") {
  const m = String(mode || "strict").trim().toLowerCase();
  if (!VALID_MODES.has(m)) {
    throw new Error(`Invalid CloakGate mode '${mode}': expected 'off', 'monitor', 'balanced', or 'strict'`);
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
 * Evaluates the 6 empirically verified hardware/physics invariants against CloakBrowser
 * and fingerprint-noise Chromium forks.
 */
function evaluateTelemetry(telemetry = {}, { mode = "strict", antiCdp = true } = {}) {
  const m = normalizeMode(mode);
  const threshold = thresholdForMode(m);
  if (m === "off") {
    return { ok: true, blocked: false, score: 0, flags: 0, threshold, mode: m, reasons: [] };
  }

  let score = 0;
  let flags = 0;
  const reasons = [];

  if (antiCdp && telemetry.webdriver) {
    score += 4;
    flags |= 64;
    reasons.push("WEBDRIVER_FLAG");
  }
  if (antiCdp && telemetry.cdpRuntimeEnable) {
    score += 4;
    flags |= 128;
    reasons.push("CDP_RUNTIME_ENABLE");
  }
  if ((telemetry.canvas2dUniqueColors ?? 1) > 1) {
    score += 2;
    flags |= 1;
    reasons.push("CANVAS2D_SYNTHETIC_NOISE");
  }
  if ((telemetry.webglClearUniqueColors ?? 1) > 1) {
    score += 2;
    flags |= 2;
    reasons.push("WEBGL_CLEAR_SYNTHETIC_NOISE");
  }
  if ((telemetry.silentAudioNonZeroSamples ?? 0) > 0) {
    score += 2;
    flags |= 4;
    reasons.push("SILENT_AUDIO_SYNTHETIC_NOISE");
  }
  if (telemetry.domRectSubpixelDrift) {
    score += 2;
    flags |= 8;
    reasons.push("DOMRECT_SUBPIXEL_POISONING");
  }
  if (telemetry.osFontLie) {
    score += 2;
    flags |= 16;
    reasons.push("OS_CORE_FONT_LIE");
  }
  if (telemetry.d3d11ExtMismatch) {
    score += 1;
    flags |= 32;
    reasons.push("D3D11_EXTENSION_PARITY_LIE");
  }

  const blocked = m !== "monitor" && score >= threshold;
  return {
    ok: !blocked,
    blocked,
    score,
    flags,
    threshold,
    mode: m,
    platform: String(telemetry.platform || "").slice(0, 48),
    reasons,
  };
}

function buildAttestation({ mode = "strict", ticket = "", nonce = "", telemetry = {}, antiCdp = true } = {}) {
  const m = normalizeMode(mode);
  if (m === "off") return null;
  const ev = evaluateTelemetry(telemetry, { mode: m, antiCdp });
  const digest = sha256Hex(`CG_ATTEST_V1|${ticket}|${nonce}|${ev.score}|${ev.flags}|${ev.platform}`);
  return {
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
  const secChPlat = getHeader(headers, "sec-ch-ua-platform").replace(/"/g, "").toLowerCase();

  // 1. Headless / automation User-Agent check (strict)
  if (m === "strict" && /HeadlessChrome|Playwright|Puppeteer|PhantomJS|SlimerJS/i.test(ua)) {
    reasons.push("AUTOMATION_UA_DENIED");
    score += 6;
  }

  // 2. OS header contradiction check (Linux UA + Windows Client Hint, etc.)
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

  // 3. Cryptographic hardware attestation check
  if (!attest || typeof attest !== "object") {
    if (m === "strict") {
      reasons.push("CLOAK_ATTEST_REQUIRED");
      score += 6;
    }
  } else {
    const s = Number(attest.s);
    const f = Number(attest.f);
    const p = String(attest.p || "").slice(0, 48);
    const d = String(attest.d || "");

    if (!Number.isInteger(s) || s < 0 || !Number.isInteger(f) || f < 0 || d.length !== 64) {
      reasons.push("CLOAK_ATTEST_INVALID");
      score += 6;
    } else {
      const expected = sha256Hex(`CG_ATTEST_V1|${ticket}|${nonce}|${s}|${f}|${p}`);
      if (!safeEqualHex(d, expected)) {
        reasons.push("CLOAK_ATTEST_DIGEST_MISMATCH");
        score += 6;
      }
      score += s;
      if (s >= threshold) {
        reasons.push("CLOAK_HARDWARE_INVARIANTS_FAILED");
      }
      // Cross-check reported navigator.platform vs HTTP UA
      if ((uaLinux && (p.startsWith("Win") || p === "MacIntel")) || (uaWin && p.startsWith("Linux"))) {
        reasons.push("OS_PLATFORM_CONTRADICTION");
        score += 4;
      }
    }
  }

  const blocked = m !== "monitor" && (score >= threshold || reasons.includes("CLOAK_ATTEST_REQUIRED") || reasons.includes("CLOAK_ATTEST_INVALID") || reasons.includes("CLOAK_ATTEST_DIGEST_MISMATCH") || reasons.includes("AUTOMATION_UA_DENIED"));
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
  normalizeMode,
  thresholdForMode,
  evaluateTelemetry,
  buildAttestation,
  verifyAttestation,
  sha256Hex,
};
