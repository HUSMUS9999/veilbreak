"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const { normalizeMode, resolvePreset } = require("./presets.js");

const AUTOMATION_OR_CLI_UA_RE =
  /HeadlessChrome|Playwright|Puppeteer|PhantomJS|SlimerJS|curl\/|wget\/|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|httpie|libwww-perl|java\/|okhttp|axios\/|node-fetch|undici|burp|caido|mitmproxy|insomnia|postman|sqlmap|ffuf|nuclei/i;

const AI_CRAWLER_UA_RE =
  /firecrawl|mendable|apify|crawlee|browserless|scrapingbee|zenrows|brightdata|oxylabs|stagehand|browser-?use|steel-?browser|gptbot|oai-searchbot|chatgpt-user|claudebot|claude-web|anthropic-ai|perplexitybot|ccbot|bytespider|diffbot|scrapy|colly|zyte|phantombuster|hyperbrowser|browserbase/i;

const CRAWLER_HEADER_PREFIXES = ["x-firecrawl-", "x-apify-", "x-browserless-", "x-scrapingbee-"];

const PROXY_LEAK_HEADERS = [
  "proxy-connection",
  "x-burp-header",
  "x-burp-collaborator",
  "x-caido-id",
  "x-caido-replay",
  "x-mitmproxy",
];

// Bitmask flags for compact wire telemetry envelope (VB_ATTEST_V2 / VB_HS_V3)
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
  CDP_SOFT_RENDERER: 1 << 15,        // 32768
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
  [FLAG.CDP_SOFT_RENDERER, "HEADLESS_SOFTWARE_WEBGL"],
]);

const DEFINED_FLAG_MASK = 0xffff;
const FLAG_MIN_WEIGHTS = Object.freeze([2, 2, 2, 2, 2, 2, 4, 1, 4, 4, 4, 4, 2, 2, 4, 3]);

function minScoreForFlags(bits, cdpWeight = null) {
  let minScore = 0;
  for (let i = 0; i < FLAG_MIN_WEIGHTS.length; i++) {
    if ((bits & (1 << i)) !== 0) {
      if (i === 7 && Number.isInteger(cdpWeight) && cdpWeight >= 0) {
        minScore += cdpWeight;
      } else {
        minScore += FLAG_MIN_WEIGHTS[i];
      }
    }
  }
  return minScore;
}

function decodeFlags(flags) {
  const out = [];
  for (const [bit, name] of FLAG_REASON_MAP) {
    if ((flags & bit) !== 0) out.push(name);
  }
  return out;
}

function thresholdForMode(mode) {
  const m = normalizeMode(mode);
  if (m === "strict" || m === "paranoid") return 2;
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

const PROXY_LEAK_SET = new Set(PROXY_LEAK_HEADERS);

function isCrawlerHeaderName(kl) {
  if (!kl.startsWith("x-")) return false;
  for (let i = 0; i < CRAWLER_HEADER_PREFIXES.length; i++) {
    if (kl.startsWith(CRAWLER_HEADER_PREFIXES[i])) return true;
  }
  return false;
}

const VB_INSPECTED_HEADERS = new Set([
  "user-agent",
  "sec-ch-ua",
  "sec-ch-ua-platform",
  "sec-fetch-site",
  "sec-fetch-mode",
  "content-length",
  "transfer-encoding",
  "x-http-method-override",
  "x-method-override",
  "x-http-method",
]);

function normalizeHeaderInfo(headers) {
  const map = Object.create(null);
  let hasProxyLeak = false;
  let hasCrawlerPrefix = false;
  if (!headers || typeof headers !== "object") {
    return { map, hasProxyLeak, hasCrawlerPrefix };
  }
  for (const k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    const kl = k.toLowerCase();
    if (!hasProxyLeak && PROXY_LEAK_SET.has(kl)) hasProxyLeak = true;
    if (!hasCrawlerPrefix && isCrawlerHeaderName(kl)) hasCrawlerPrefix = true;
    if (!VB_INSPECTED_HEADERS.has(kl)) continue;
    const raw = headers[k];
    const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
    if (map[kl] === undefined) map[kl] = val;
    else if (val) map[kl] = map[kl] ? `${map[kl]}, ${val}` : val;
  }
  return { map, hasProxyLeak, hasCrawlerPrefix };
}

function getHeader(headers, name) {
  if (!headers || typeof headers !== "object") return "";
  const target = name.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(headers, target)) {
    const v = headers[target];
    return Array.isArray(v) ? v.join(", ") : String(v ?? "");
  }
  for (const k in headers) {
    if (Object.prototype.hasOwnProperty.call(headers, k) && k.toLowerCase() === target) {
      const v = headers[k];
      return Array.isArray(v) ? v.join(", ") : String(v ?? "");
    }
  }
  return "";
}

function isAiCrawlerRequest(headers) {
  if (!headers || typeof headers !== "object") return false;
  let ua = "";
  let secChUa = "";
  for (const k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    const kl = k.toLowerCase();
    if (kl === "user-agent") {
      const v = headers[k];
      const s = Array.isArray(v) ? v.join(", ") : String(v ?? "");
      ua = ua ? (s ? `${ua}, ${s}` : ua) : s;
    } else if (kl === "sec-ch-ua") {
      const v = headers[k];
      const s = Array.isArray(v) ? v.join(", ") : String(v ?? "");
      secChUa = secChUa ? (s ? `${secChUa}, ${s}` : secChUa) : s;
    } else if (isCrawlerHeaderName(kl)) {
      return true;
    }
  }
  return AI_CRAWLER_UA_RE.test(ua.trim()) || AI_CRAWLER_UA_RE.test(secChUa);
}

function isAutomationOrCliUa(headers) {
  if (!headers || typeof headers !== "object") return true;
  const ua = getHeader(headers, "user-agent").trim();
  const ch = getHeader(headers, "sec-ch-ua");
  if (!ua) return true;
  return AUTOMATION_OR_CLI_UA_RE.test(ua) || /HeadlessChrome/i.test(ch);
}

/**
 * Zero-allocation single-pass header check for unprotected routes: checks AI crawler
 * header prefixes/UAs and CLI/automation UAs in a single scan without allocating a map.
 */
function checkUnprotectedCrawlerOrCli(headers, blockAiCrawlers = true) {
  if (!headers || typeof headers !== "object") {
    return { crawlerHit: false, cliHit: true };
  }
  let ua = "";
  let secChUa = "";
  let hasCrawlerPrefix = false;
  for (const k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    const kl = k.toLowerCase();
    if (kl === "user-agent") {
      const v = headers[k];
      const s = Array.isArray(v) ? v.join(", ") : String(v ?? "");
      ua = ua ? (s ? `${ua}, ${s}` : ua) : s;
    } else if (kl === "sec-ch-ua") {
      const v = headers[k];
      const s = Array.isArray(v) ? v.join(", ") : String(v ?? "");
      secChUa = secChUa ? (s ? `${secChUa}, ${s}` : secChUa) : s;
    } else if (blockAiCrawlers && !hasCrawlerPrefix && isCrawlerHeaderName(kl)) {
      hasCrawlerPrefix = true;
    }
  }
  const uaTrim = ua.trim();
  const crawlerHit =
    Boolean(blockAiCrawlers) &&
    (hasCrawlerPrefix || AI_CRAWLER_UA_RE.test(uaTrim) || AI_CRAWLER_UA_RE.test(secChUa));
  if (crawlerHit) return { crawlerHit: true, cliHit: false };
  const cliHit = !uaTrim || AUTOMATION_OR_CLI_UA_RE.test(uaTrim) || /HeadlessChrome/i.test(secChUa);
  return { crawlerHit: false, cliHit };
}

function hexNibble(code) {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x37;
  if (code >= 0x61 && code <= 0x66) return code - 0x57;
  return -1;
}

function hexByteAt(s, idx) {
  return (hexNibble(s.charCodeAt(idx + 1)) << 4) | hexNibble(s.charCodeAt(idx + 2));
}

function decodePercentLenient(s) {
  if (s.indexOf("%") < 0) return s;
  return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
    let out = "";
    let i = 0;
    const len = run.length;
    while (i < len) {
      const b = hexByteAt(run, i);
      if (b === 0x00) {
        out += "\0";
        i += 3;
        continue;
      }
      if (b <= 0x7f) {
        out += String.fromCharCode(b);
        i += 3;
        continue;
      }
      // Zero-exception RFC 3629 UTF-8 leading-byte decoder (exact parity with strict UTF-8 / decodeURIComponent)
      if (b >= 0xc2 && b <= 0xdf && i + 6 <= len) {
        const b2 = hexByteAt(run, i + 3);
        if ((b2 & 0xc0) === 0x80) {
          out += String.fromCharCode(((b & 0x1f) << 6) | (b2 & 0x3f));
          i += 6;
          continue;
        }
      } else if (b >= 0xe0 && b <= 0xef && i + 9 <= len) {
        const b2 = hexByteAt(run, i + 3);
        const b3 = hexByteAt(run, i + 6);
        const validB2 = b === 0xe0 ? (b2 >= 0xa0 && b2 <= 0xbf) : b === 0xed ? (b2 >= 0x80 && b2 <= 0x9f) : ((b2 & 0xc0) === 0x80);
        if (validB2 && (b3 & 0xc0) === 0x80) {
          out += String.fromCharCode(((b & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f));
          i += 9;
          continue;
        }
      } else if (b >= 0xf0 && b <= 0xf4 && i + 12 <= len) {
        const b2 = hexByteAt(run, i + 3);
        const b3 = hexByteAt(run, i + 6);
        const b4 = hexByteAt(run, i + 9);
        const validB2 = b === 0xf0 ? (b2 >= 0x90 && b2 <= 0xbf) : b === 0xf4 ? (b2 >= 0x80 && b2 <= 0x8f) : ((b2 & 0xc0) === 0x80);
        if (validB2 && (b3 & 0xc0) === 0x80 && (b4 & 0xc0) === 0x80) {
          const cp = ((b & 0x07) << 18) | ((b2 & 0x3f) << 12) | ((b3 & 0x3f) << 6) | (b4 & 0x3f);
          out += String.fromCodePoint(cp);
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

function stripSchemeAndAuthority(rawUrl) {
  let s = String(rawUrl || "/").trimStart();
  if (!s) return "/";
  if (s.charCodeAt(0) === 47) return s;
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
  let s = String(rawPath || "/").replace(/\\/g, "/");
  const nul = s.indexOf("\0");
  if (nul >= 0) s = s.slice(0, nul);
  if (!s.startsWith("/")) s = "/" + s;
  s = s
    .split("/")
    .map((seg) => seg.split(";")[0])
    .join("/")
    .replace(/\/+/g, "/");
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s || "/";
}

function stripTrailingSpacesAndDots(seg) {
  let end = seg.length;
  while (end > 0) {
    const code = seg.charCodeAt(end - 1);
    if (code === 0x2e || code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d || code === 0x0b || code === 0x0c) {
      end--;
    } else {
      break;
    }
  }
  return end === seg.length ? seg : seg.slice(0, end);
}

function trimSegmentNoise(normPath) {
  let s = String(normPath || "/")
    .split("/")
    .map(stripTrailingSpacesAndDots)
    .join("/")
    .replace(/\/+/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s || "/";
}

const CLEAN_ASCII_PATH_RE =
  /^\/(?:[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*(?:\/[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*)*)?\/?$/;

function decodePercent2(s) {
  let out = s;
  for (let pass = 0; pass < 2; pass++) {
    const next = decodePercentLenient(out);
    if (next === out) break;
    out = next;
  }
  return out;
}

function normalizeDecodedPathname(decodedNoQuery) {
  let s = String(decodedNoQuery || "/").replace(/\0/g, "").replace(/\\/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  s = s
    .split("/")
    .map((seg) => seg.split(";")[0])
    .join("/");
  s = path.posix.normalize(s);
  if (!s.startsWith("/")) s = "/" + s;
  if (s.length > 1) s = s.replace(/\/+$/, "");
  s = s.replace(/\?/g, "%3F").replace(/\|/g, "%7C");
  return s;
}

function normalizePathname(rawUrl) {
  let s = stripSchemeAndAuthority(rawUrl);
  const qIdx = s.indexOf("?");
  if (qIdx >= 0) s = s.slice(0, qIdx);
  if (!s) return "/";
  if (CLEAN_ASCII_PATH_RE.test(s)) {
    return s.length > 1 && s.endsWith("/") ? s.slice(0, -1) : s;
  }
  return normalizeDecodedPathname(decodePercent2(s));
}

function expandPathCandidates(rawUrl) {
  const raw = stripSchemeAndAuthority(rawUrl);
  const qIdx = raw.indexOf("?");
  const rawPath = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
  if (CLEAN_ASCII_PATH_RE.test(rawPath)) {
    const clean = rawPath.length > 1 && rawPath.endsWith("/") ? rawPath.slice(0, -1) : rawPath || "/";
    return [clean];
  }
  const set = new Set();

  const addRawOnly = (val) => {
    const n2 = cleanPathNoCollapse(val);
    set.add(n2);
    set.add(trimSegmentNoise(n2));
  };

  const addDecoded = (decVal) => {
    const n1 = normalizeDecodedPathname(decVal);
    const n2 = cleanPathNoCollapse(decVal);
    set.add(n1);
    set.add(n2);
    set.add(trimSegmentNoise(n1));
    set.add(trimSegmentNoise(n2));
  };

  addRawOnly(rawPath);

  // Decode rawPath in at most 2 passes total (splitting on literal '#' decodes disjoint halves with zero overlap!)
  const rawHash = rawPath.indexOf("#");
  let dec;
  if (rawHash >= 0) {
    const rawBefore = rawPath.slice(0, rawHash);
    addRawOnly(rawBefore);
    const decBefore = decodePercent2(rawBefore);
    addDecoded(decBefore);
    const decAfter = decodePercent2(rawPath.slice(rawHash + 1));
    dec = `${decBefore}#${decAfter}`;
  } else {
    dec = decodePercent2(rawPath);
  }
  addDecoded(dec);

  const nullIdx = dec.indexOf("\0");
  if (nullIdx >= 0) addDecoded(dec.slice(0, nullIdx));

  const decQ = dec.indexOf("?");
  if (decQ >= 0) addDecoded(dec.slice(0, decQ));
  const decH = dec.indexOf("#");
  if (decH >= 0) addDecoded(dec.slice(0, decH));

  return Array.from(set);
}

function normalizeProtectedPaths(protectedPaths) {
  const normalized = (Array.isArray(protectedPaths) && protectedPaths.length > 0 ? protectedPaths : ["/api"]).map((rule) => {
    if (rule instanceof RegExp) return rule;
    const raw = String(rule).trim();
    if (raw === "*") return "*";
    return normalizePathname(raw).toLowerCase();
  });
  normalized.matchAll = normalized.some((r) => r === "*" || r === "/");
  return normalized;
}

function compileProtectedPathRules(protectedPaths) {
  const compiled = normalizeProtectedPaths(protectedPaths).map((rule) => {
    if (rule instanceof RegExp) return { kind: "regex", regex: rule };
    if (rule === "*" || rule === "/") return { kind: "wild" };
    return { kind: "prefix", lower: rule, prefix: rule.endsWith("/") ? rule : `${rule}/` };
  });
  compiled.matchAll = compiled.some((r) => r.kind === "wild");
  return compiled;
}

function isProtectedPath(rawUrl, protectedPaths, preNormalized = false, preCleanPath = null) {
  const rules = preNormalized ? protectedPaths : normalizeProtectedPaths(protectedPaths);
  if (rules && rules.matchAll) return true;
  if (!rules || rules.length === 0) return false;
  if (preNormalized && rules.matchAll === undefined) {
    for (let i = 0; i < rules.length; i++) {
      const r = rules[i];
      if (r === "*" || r === "/" || (r && typeof r === "object" && !(r instanceof RegExp) && r.kind === "wild")) {
        return true;
      }
    }
  }
  const candidates = preCleanPath !== null ? [preCleanPath] : expandPathCandidates(rawUrl);
  for (const norm of candidates) {
    const normLower = norm.toLowerCase();
    for (const rule of rules) {
      if (rule && typeof rule === "object" && !(rule instanceof RegExp)) {
        if (rule.kind === "wild") return true;
        if (rule.kind === "regex") {
          rule.regex.lastIndex = 0;
          if (rule.regex.test(norm)) return true;
        } else if (normLower === rule.lower || normLower.startsWith(rule.prefix)) {
          return true;
        }
      } else if (rule instanceof RegExp) {
        rule.lastIndex = 0;
        if (rule.test(norm)) return true;
      } else if (
        rule === "*" ||
        rule === "/" ||
        normLower === rule ||
        normLower.startsWith(rule.endsWith("/") ? rule : `${rule}/`)
      ) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Stage 1: Evaluates all 15 physics, graphics, audio, cross-realm, prototype,
 * geometry, active CDP, and engine-coherence invariants.
 */
function evaluateTelemetry(telemetry = {}, { mode = "strict", antiCdp = true, allowDevTools } = {}) {
  const preset = resolvePreset(mode, { antiCdp, allowDevTools });
  const m = preset.mode;
  const threshold = preset.threshold;
  if (m === "off") {
    return { ok: true, blocked: false, score: 0, flags: 0, threshold, mode: m, platform: "", cdpActive: false, reasons: [] };
  }

  let score = 0;
  let flags = 0;
  const reasons = [];

  if (preset.antiCdp && (telemetry.webdriver || telemetry.freshIframeWebdriver)) {
    score += 4;
    flags |= FLAG.WEBDRIVER_FLAG;
    reasons.push("WEBDRIVER_FLAG");
  }
  if (preset.antiCdp && telemetry.automationGlobalArtifact) {
    score += 4;
    flags |= FLAG.AUTOMATION_GLOBAL;
    reasons.push("AUTOMATION_GLOBAL_ARTIFACT");
  }
  if (preset.antiCdp && telemetry.cdpRuntimeEnable && preset.cdpRuntimeWeight > 0) {
    score += preset.cdpRuntimeWeight;
    flags |= FLAG.CDP_RUNTIME_ENABLE;
    reasons.push("CDP_RUNTIME_ENABLE");
  }
  if (preset.antiCdp && telemetry.softwareWebglHeadless) {
    score += 3;
    flags |= FLAG.CDP_SOFT_RENDERER;
    reasons.push("HEADLESS_SOFTWARE_WEBGL");
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

  const cdpActive = Boolean(
    telemetry.cdpRuntimeEnable ||
      telemetry.automationGlobalArtifact ||
      telemetry.webdriver ||
      telemetry.freshIframeWebdriver
  );
  const blocked = m !== "monitor" && score >= threshold;
  return {
    ok: !blocked,
    blocked,
    score,
    flags,
    threshold,
    mode: m,
    platform: String(telemetry.platform || "").replace(/\|/g, "").slice(0, 48),
    cdpActive,
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
      if (moves <= 3 && dwellMs > 0 && dwellMs < 12 && hitCenter) {
        score += 4;
        reasons.push("TELEPORT_CLICK_PHYSICS");
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
  allowDevTools,
  challenge = "",
  difficulty = 0,
  powNonce = null,
  method = "",
  path: reqPath = "",
} = {}) {
  const m = normalizeMode(mode);
  if (m === "off") return null;
  const ev = evaluateTelemetry(telemetry, { mode: m, antiCdp, allowDevTools });
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

const METHOD_OVERRIDE_HEADER_NAMES = ["x-http-method-override", "x-method-override", "x-http-method"];

function hasMethodOverrideConflict(lookup, expectedMethod) {
  const expM = String(expectedMethod || "").trim().toUpperCase();
  let count = 0;
  for (let i = 0; i < METHOD_OVERRIDE_HEADER_NAMES.length; i++) {
    const val = String(lookup(METHOD_OVERRIDE_HEADER_NAMES[i]) || "").trim().toUpperCase();
    if (!val) continue;
    count++;
    // Flag immediately if ANY override header mismatches expectedMethod OR if multiple override headers are sent (shadowing bypass!)
    if (count > 1 || !expM || val !== expM) return true;
  }
  return false;
}

function evaluateRequestHeaders(
  headers,
  { enforcing, requireFetchMetadata, blockAiCrawlers, expectedMethod = "", skipHeaderChecks = false, headersPrevalidated = false }
) {
  const reasons = [];
  let score = 0;

  if (headersPrevalidated) {
    // O(1) zero-loop fast path when unified ProxySnare's validateHandshakeClientHeaders already verified
    // CL+TE, method overrides, proxy leaks, AI crawlers, CLI UAs, OS contradiction, and Fetch Metadata:
    // only check SEC_CH_UA_GREASE_LIE and extract UA OS flags via direct lowercase lookup!
    const rawUa = headers && typeof headers === "object" ? headers["user-agent"] : "";
    const rawSecCh = headers && typeof headers === "object" ? headers["sec-ch-ua"] : "";
    const ua = Array.isArray(rawUa) ? rawUa.join(", ") : String(rawUa ?? "");
    const secChUa = Array.isArray(rawSecCh) ? rawSecCh.join(", ") : String(rawSecCh ?? "");
    const uaLinux = ua.includes("Linux") && !ua.includes("Android");
    const uaWin = ua.includes("Windows NT");
    const uaMac = ua.includes("Macintosh");
    const chromeMatch = /Chrome\/(\d+)/i.exec(ua);
    if (chromeMatch && Number(chromeMatch[1]) >= 115 && secChUa.includes('" Not A;Brand";v="99"')) {
      reasons.push("SEC_CH_UA_GREASE_LIE");
      score += 2;
    }
    return { reasons, score, uaLinux, uaWin, uaMac };
  }

  if (skipHeaderChecks) {
    // True single-pass O(H) zero-map fast path for unified ProxySnare handshakes:
    // skip checks already enforced by ProxySnare (UA/crawler/proxy-leak/Fetch-Metadata)
    // while still enforcing CL_TE_SMUGGLING, METHOD_OVERRIDE_DENIED, OS_HEADER_CONTRADICTION, and SEC_CH_UA_GREASE_LIE!
    let ua = "";
    let secChUa = "";
    let secChPlatRaw = "";
    let cl = "";
    let te = "";
    let ov1 = "";
    let ov2 = "";
    let ov3 = "";
    if (headers && typeof headers === "object") {
      for (const k in headers) {
        if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
        const kl = k.toLowerCase();
        const raw = headers[k];
        if (kl === "user-agent") {
          const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
          ua = ua && val ? `${ua}, ${val}` : (ua || val);
        } else if (kl === "sec-ch-ua") {
          const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
          secChUa = secChUa && val ? `${secChUa}, ${val}` : (secChUa || val);
        } else if (kl === "sec-ch-ua-platform") {
          const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
          secChPlatRaw = secChPlatRaw && val ? `${secChPlatRaw}, ${val}` : (secChPlatRaw || val);
        } else if (kl === "content-length") {
          const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
          cl = cl && val ? `${cl}, ${val}` : (cl || val);
        } else if (kl === "transfer-encoding") {
          const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
          te = te && val ? `${te}, ${val}` : (te || val);
        } else if (kl === "x-http-method-override") {
          const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
          ov1 = ov1 && val ? `${ov1}, ${val}` : (ov1 || val);
        } else if (kl === "x-method-override") {
          const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
          ov2 = ov2 && val ? `${ov2}, ${val}` : (ov2 || val);
        } else if (kl === "x-http-method") {
          const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
          ov3 = ov3 && val ? `${ov3}, ${val}` : (ov3 || val);
        }
      }
    }
    const secChPlat = secChPlatRaw.replace(/"/g, "").toLowerCase();
    const uaLinux = ua.includes("Linux") && !ua.includes("Android");
    const uaWin = ua.includes("Windows NT");
    const uaMac = ua.includes("Macintosh");
    if (cl && te) {
      reasons.push("CL_TE_SMUGGLING");
      score += 10;
    }
    if (ov1 || ov2 || ov3) {
      const expM = String(expectedMethod || "").trim().toUpperCase();
      let ovCount = 0;
      let ovConflict = false;
      for (const rawOv of [ov1, ov2, ov3]) {
        const v = rawOv.trim().toUpperCase();
        if (!v) continue;
        ovCount++;
        if (ovCount > 1 || !expM || v !== expM) { ovConflict = true; break; }
      }
      if (ovConflict) {
        reasons.push("METHOD_OVERRIDE_DENIED");
        score += 6;
      }
    }
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
    const chromeMatch = /Chrome\/(\d+)/i.exec(ua);
    if (chromeMatch && Number(chromeMatch[1]) >= 115 && secChUa.includes('" Not A;Brand";v="99"')) {
      reasons.push("SEC_CH_UA_GREASE_LIE");
      score += 2;
    }
    return { reasons, score, uaLinux, uaWin, uaMac };
  }

  const info = normalizeHeaderInfo(headers);
  const h = info.map;
  const ua = h["user-agent"] || "";
  const uaLinux = ua.includes("Linux") && !ua.includes("Android");
  const uaWin = ua.includes("Windows NT");
  const uaMac = ua.includes("Macintosh");
  const uaTrim = ua.trim();
  const secChUa = h["sec-ch-ua"] || "";
  const secChPlat = (h["sec-ch-ua-platform"] || "").replace(/"/g, "").toLowerCase();
  const sfs = (h["sec-fetch-site"] || "").trim().toLowerCase();
  const sfm = (h["sec-fetch-mode"] || "").trim().toLowerCase();
  const cl = h["content-length"] || "";
  const te = h["transfer-encoding"] || "";

  if (cl && te) {
    reasons.push("CL_TE_SMUGGLING");
    score += 10;
  }
  if (hasMethodOverrideConflict((k) => h[k], expectedMethod)) {
    reasons.push("METHOD_OVERRIDE_DENIED");
    score += 6;
  }
  if (info.hasProxyLeak) {
    reasons.push("PROXY_HEADER_LEAK");
    score += 6;
  }
  if (blockAiCrawlers && (info.hasCrawlerPrefix || AI_CRAWLER_UA_RE.test(uaTrim) || AI_CRAWLER_UA_RE.test(secChUa))) {
    reasons.push("AI_CRAWLER_OR_SCRAPER_DENIED");
    score += 6;
  }
  const isCli = !uaTrim || AUTOMATION_OR_CLI_UA_RE.test(uaTrim) || /HeadlessChrome/i.test(secChUa);
  if (enforcing && isCli) {
    reasons.push("AUTOMATION_UA_DENIED");
    score += 6;
  }
  if (sfs.includes("cross-site")) {
    reasons.push("CROSS_SITE_REQUEST_DENIED");
    score += 6;
  }
  const chromeMatch = /Chrome\/(\d+)/i.exec(ua);
  const claimsModern =
    !isCli &&
    ((chromeMatch && Number(chromeMatch[1]) >= 80) ||
      (() => { const ffMatch = /Firefox\/(\d+)/i.exec(ua); return Boolean(ffMatch && Number(ffMatch[1]) >= 90); })());
  if (requireFetchMetadata && claimsModern) {
    if (!sfs || (sfs !== "same-origin" && sfs !== "same-site") || !sfm) {
      reasons.push("FETCH_METADATA_MISSING");
      score += 4;
    }
  }
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
  if (chromeMatch && Number(chromeMatch[1]) >= 115 && secChUa.includes('" Not A;Brand";v="99"')) {
    reasons.push("SEC_CH_UA_GREASE_LIE");
    score += 2;
  }
  return { reasons, score, uaLinux, uaWin, uaMac };
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
  blockAiCrawlers,
  antiCdp,
  allowDevTools,
  _preset = null,
  _expectedPathNormalized = false,
  _precomputedHdrEval = null,
} = {}) {
  const preset = _preset || resolvePreset(mode, { blockAiCrawlers, antiCdp, allowDevTools });
  const m = preset.mode;
  const threshold = preset.threshold;
  if (m === "off") {
    return { ok: true, blocked: false, score: 0, threshold, mode: m, reasons: [] };
  }

  const enforcing = m === "strict" || m === "balanced" || m === "paranoid";
  const hdrEval =
    _precomputedHdrEval ||
    evaluateRequestHeaders(headers, {
      enforcing,
      requireFetchMetadata,
      blockAiCrawlers: preset.blockAiCrawlers,
      expectedMethod,
    });
  const reasons = _precomputedHdrEval ? hdrEval.reasons.slice() : hdrEval.reasons;
  let score = hdrEval.score;
  const { uaLinux, uaWin, uaMac } = hdrEval;

  // Parse & strictly validate VB_ATTEST_V2 telemetry envelope
  let attObj = attest;
  if (typeof attObj === "string") {
    if (attObj.length > 8192) {
      attObj = { invalid: true };
    } else {
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
  }

  const tkStr = String(ticket ?? "");
  const nnStr = String(nonce ?? "");
  const expChal = String(expectedChallenge ?? "");
  const expDiff = Number.isInteger(expectedDifficulty) && expectedDifficulty > 0 ? expectedDifficulty : 0;
  const expMethod = String(expectedMethod || "").trim().toUpperCase();
  const expPath = expectedPath ? (_expectedPathNormalized ? String(expectedPath) : normalizePathname(String(expectedPath))) : "";

  if (attObj === null || attObj === undefined) {
    if (enforcing) {
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
    const isOptStr = (x) => x === null || x === undefined || typeof x === "string";
    const validStrTypes = isOptStr(attObj.p) && isOptStr(attObj.w) && isOptStr(attObj.m) && isOptStr(attObj.u);
    const pRaw = typeof attObj.p === "string" ? attObj.p : "";
    const p = pRaw.slice(0, 48);
    const d = typeof attObj.d === "string" ? attObj.d : "";
    const w = typeof attObj.w === "string" ? attObj.w : "";
    const attM = typeof attObj.m === "string" ? attObj.m.trim().toUpperCase() : "";
    const attU = typeof attObj.u === "string" ? attObj.u : "";

    const validNums =
      validStrTypes &&
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
    const coherentFlagScore = validNums && s >= minScoreForFlags(f, preset.cdpRuntimeWeight);
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
    reasons.includes("AI_CRAWLER_OR_SCRAPER_DENIED") ||
    reasons.includes("POW_INVALID") ||
    reasons.includes("REQUEST_BINDING_MISMATCH") ||
    reasons.includes("CROSS_SITE_REQUEST_DENIED") ||
    reasons.includes("CL_TE_SMUGGLING") ||
    reasons.includes("METHOD_OVERRIDE_DENIED") ||
    reasons.includes("PROXY_HEADER_LEAK") ||
    (m === "paranoid" && preset.antiCdp && !preset.allowDevTools && reasons.includes("CDP_RUNTIME_ENABLE"));
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

/**
 * Builds a challenge-bound VB_HS_V3 browser integrity proof for unified ProxySnare handshakes.
 */
function buildHandshakeProof({
  mode = "strict",
  challenge = "",
  telemetry = {},
  antiCdp = true,
  allowDevTools,
  workerOk = true,
  probeMs = 12,
} = {}) {
  const m = normalizeMode(mode);
  if (m === "off") return null;
  const ev = evaluateTelemetry(telemetry, { mode: m, antiCdp, allowDevTools });
  const ch = String(challenge || "").replace(/\|/g, "").slice(0, 64);
  const wr = String(telemetry.webglRenderer || "").replace(/\|/g, "").slice(0, 64);
  const cdp = ev.cdpActive ? 1 : 0;
  const wk = workerOk ? 1 : 0;
  const ms = Number.isFinite(probeMs) ? Math.max(0, Math.min(60_000, Math.round(probeMs))) : 0;
  const d = sha256Hex(`VB_HS_V3|${ch}|${ev.score}|${ev.flags}|${ev.platform}|${cdp}|${wr}|${wk}|${ms}`);
  return {
    v: 3,
    ch,
    s: ev.score,
    f: ev.flags,
    p: ev.platform,
    cdp,
    wr,
    wk,
    ms,
    d,
  };
}

/**
 * Verifies a challenge-bound VB_HS_V3 proof submitted inside a ProxySnare `/handshake`
 * (zero extra HTTP round trips per API call, while binding real browser probes into ECDH session minting).
 */
function verifyHandshakeProof({
  mode = "strict",
  headers = {},
  proof = null,
  expectedChallenge = "",
  requireFetchMetadata,
  blockAiCrawlers,
  antiCdp,
  allowDevTools,
  skipHeaderChecks = false,
  _preset = null,
  _headersPrevalidated = false,
} = {}) {
  const preset = _preset || resolvePreset(mode, { requireFetchMetadata, blockAiCrawlers, antiCdp, allowDevTools });
  const m = preset.mode;
  const threshold = preset.threshold;
  if (m === "off") {
    return { ok: true, blocked: false, score: 0, threshold, mode: m, cdpActive: false, reasons: [] };
  }

  const enforcing = m === "strict" || m === "balanced" || m === "paranoid";
  const hdrEval = evaluateRequestHeaders(headers, {
    enforcing,
    requireFetchMetadata: preset.requireFetchMetadata,
    blockAiCrawlers: preset.blockAiCrawlers,
    skipHeaderChecks: Boolean(skipHeaderChecks),
    headersPrevalidated: Boolean(_headersPrevalidated),
  });
  const reasons = hdrEval.reasons;
  let score = hdrEval.score;
  const { uaLinux, uaWin, uaMac } = hdrEval;

  let cdpActive = false;
  const expChal = String(expectedChallenge || "");
  if (proof === null || proof === undefined) {
    if (enforcing) {
      reasons.push("BROWSER_PROOF_REQUIRED");
      score += 6;
    }
  } else if (typeof proof !== "object" || Array.isArray(proof)) {
    reasons.push("BROWSER_PROOF_INVALID");
    score += 6;
  } else {
    const { v, ch, s, f, p: pRaw, cdp, wr: wrRaw, wk, ms, d } = proof;
    const isOptStr = (x) => x === null || x === undefined || typeof x === "string";
    const chStr = typeof ch === "string" ? ch : "";
    const p = typeof pRaw === "string" ? pRaw.slice(0, 48) : "";
    const wr = typeof wrRaw === "string" ? wrRaw.slice(0, 64) : "";
    const dStr = typeof d === "string" ? d : "";
    const validTypes =
      isOptStr(pRaw) &&
      isOptStr(wrRaw) &&
      isOptStr(ch) &&
      v === 3 &&
      typeof s === "number" && Number.isInteger(s) && s >= 0 && s <= 10_000 &&
      typeof f === "number" && Number.isInteger(f) && f >= 0 && f <= DEFINED_FLAG_MASK &&
      (cdp === 0 || cdp === 1) &&
      (wk === 0 || wk === 1) &&
      typeof ms === "number" && Number.isInteger(ms) && ms >= 0 && ms <= 60_000 &&
      /^[0-9a-f]{64}$/i.test(dStr) &&
      !chStr.includes("|") && !p.includes("|") && !wr.includes("|");
    const coherent = validTypes && s >= minScoreForFlags(f, preset.cdpRuntimeWeight);

    if (!coherent) {
      reasons.push("BROWSER_PROOF_INVALID");
      score += 6;
    } else if (!expChal ? enforcing && !chStr : !safeEqualHex(chStr, expChal)) {
      reasons.push("BROWSER_PROOF_CHALLENGE_MISMATCH");
      score += 6;
    } else {
      const expectedDigest = sha256Hex(`VB_HS_V3|${chStr}|${s}|${f}|${p}|${cdp}|${wr}|${wk}|${ms}`);
      if (!safeEqualHex(dStr.toLowerCase(), expectedDigest)) {
        reasons.push("BROWSER_PROOF_DIGEST_MISMATCH");
        score += 6;
      }
      const autoCdpFlags = (f & (FLAG.WEBDRIVER_FLAG | FLAG.AUTOMATION_GLOBAL)) !== 0;
      const runtimeCdpFlag = (f & FLAG.CDP_RUNTIME_ENABLE) !== 0;
      cdpActive = cdp === 1 || autoCdpFlags || runtimeCdpFlag;
      score += s;
      // Prevent cdp:1 with omitted CDP flag from slipping past strict/paranoid when antiCdp is active
      if (cdp === 1 && !autoCdpFlags && !runtimeCdpFlag && preset.antiCdp && preset.cdpRuntimeWeight > 0) {
        score += preset.cdpRuntimeWeight;
        reasons.push("CDP_RUNTIME_ENABLE");
      }
      for (const r of decodeFlags(f)) {
        if (!reasons.includes(r)) reasons.push(r);
      }
      if (s >= threshold) reasons.push("BROWSER_INVARIANTS_FAILED");
      if (
        (uaLinux && (p.startsWith("Win") || p === "MacIntel")) ||
        (uaWin && (p.startsWith("Linux") || p === "MacIntel")) ||
        (uaMac && (p.startsWith("Win") || p.startsWith("Linux")))
      ) {
        reasons.push("OS_PLATFORM_CONTRADICTION");
        score += 4;
      }
      if ((uaLinux || uaWin || uaMac) && !p && (m === "strict" || m === "paranoid")) {
        reasons.push("OS_PLATFORM_CONTRADICTION");
        score += 4;
      }
      // Server-side GPU / OS coherence check on reported WebGL renderer
      if (wr) {
        const gpuOsLie =
          (uaWin && /Intel Iris OpenGL Engine|Apple GPU|Apple M\d/i.test(wr)) ||
          ((uaLinux || uaMac) && /Direct3D11|D3D11|Direct3D9/i.test(wr));
        if (gpuOsLie) {
          reasons.push("WEBGL_HARDWARE_COHERENCE_LIE");
          score += 4;
        }
      }
      if (m === "paranoid" && preset.antiCdp && (autoCdpFlags || (!preset.allowDevTools && cdpActive))) {
        if (!reasons.includes("CDP_ACTIVE_DENIED")) reasons.push("CDP_ACTIVE_DENIED");
        score += 6;
      }
    }
  }

  const hardFail =
    reasons.includes("BROWSER_PROOF_REQUIRED") ||
    reasons.includes("BROWSER_PROOF_INVALID") ||
    reasons.includes("BROWSER_PROOF_CHALLENGE_MISMATCH") ||
    reasons.includes("BROWSER_PROOF_DIGEST_MISMATCH") ||
    reasons.includes("AUTOMATION_UA_DENIED") ||
    reasons.includes("AI_CRAWLER_OR_SCRAPER_DENIED") ||
    reasons.includes("CROSS_SITE_REQUEST_DENIED") ||
    reasons.includes("CL_TE_SMUGGLING") ||
    reasons.includes("METHOD_OVERRIDE_DENIED") ||
    reasons.includes("PROXY_HEADER_LEAK") ||
    reasons.includes("CDP_ACTIVE_DENIED");
  const blocked = m !== "monitor" && (score >= threshold || hardFail);
  return {
    ok: !blocked,
    blocked,
    score,
    threshold,
    mode: m,
    cdpActive,
    reasons,
  };
}

module.exports = {
  PROXY_LEAK_HEADERS,
  FLAG,
  decodeFlags,
  normalizeMode,
  resolvePreset,
  thresholdForMode,
  evaluateTelemetry,
  evaluateInteraction,
  buildAttestation,
  verifyAttestation,
  buildHandshakeProof,
  verifyHandshakeProof,
  isAutomationOrCliUa,
  isAiCrawlerRequest,
  checkUnprotectedCrawlerOrCli,
  evaluateRequestHeaders,
  verifyPowSolution,
  solvePowChallenge,
  normalizePathname,
  CLEAN_ASCII_PATH_RE,
  normalizeProtectedPaths,
  compileProtectedPathRules,
  stripSchemeAndAuthority,
  expandPathCandidates,
  isProtectedPath,
  sha256Hex,
};
