"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");
const zlib = require("node:zlib");
const { normalizeMode, verifyAttestation } = require("./probes.js");
const { buildBrowserGateScript, buildPlaygroundHtml } = require("./browser-sdk.js");

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "trailers",
  "transfer-encoding",
  "upgrade",
]);

const PROTECTED_FROM_CONN_STRIP = new Set([
  "host",
  "authorization",
  "cookie",
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
  "cf-connecting-ip",
  "true-client-ip",
]);

function stripHopByHop(headers, { isRequest = false } = {}) {
  const out = {};
  const connTokens = new Set();
  const connVal = headers?.connection;
  if (!isRequest && typeof connVal === "string") {
    for (const tok of connVal.split(",")) {
      const t = tok.trim().toLowerCase();
      if (t && !PROTECTED_FROM_CONN_STRIP.has(t) && !t.startsWith("x-auth-") && !t.startsWith("cf-")) {
        connTokens.add(t);
      }
    }
  }
  for (const [k, v] of Object.entries(headers || {})) {
    const kl = k.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(kl) || connTokens.has(kl)) continue;
    out[k] = v;
  }
  return out;
}

function escapeHtmlAttr(s) {
  return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function decodePercentLenient(s) {
  // Decode valid ASCII/UTF-8 percent escapes without letting invalid %ff poison adjacent runs (CRIT-2)
  return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
    let out = "";
    let i = 0;
    while (i < run.length) {
      const b = parseInt(run.slice(i + 1, i + 3), 16);
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
  let s = String(rawUrl || "/").trim();
  if (/^https?:\/\//i.test(s)) {
    const afterScheme = s.indexOf("://") + 3;
    const slashIdx = s.indexOf("/", afterScheme);
    const qIdx = s.indexOf("?", afterScheme);
    const hIdx = s.indexOf("#", afterScheme);
    const cuts = [slashIdx, qIdx, hIdx].filter((i) => i >= 0);
    if (cuts.length === 0) return "/";
    const first = Math.min(...cuts);
    s = s[first] === "/" ? s.slice(first) : "/" + s.slice(first);
  }
  return s;
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
  s = s.replace(/\\/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  s = s
    .split("/")
    .map((seg) => seg.split(";")[0])
    .join("/");
  s = path.posix.normalize(s);
  if (!s.startsWith("/")) s = "/" + s;
  return s;
}

function expandPathCandidates(rawUrl) {
  const raw = stripSchemeAndAuthority(rawUrl);
  const qIdx = raw.indexOf("?");
  const rawPath = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
  const set = new Set();
  set.add(normalizePathname(rawPath));

  const rawHash = rawPath.indexOf("#");
  if (rawHash >= 0) {
    set.add(normalizePathname(rawPath.slice(0, rawHash)));
  }

  let dec = rawPath;
  for (let pass = 0; pass < 2; pass++) {
    const next = decodePercentLenient(dec);
    if (next === dec) break;
    dec = next;
  }
  const decQ = dec.indexOf("?");
  if (decQ >= 0) set.add(normalizePathname(dec.slice(0, decQ)));
  const decH = dec.indexOf("#");
  if (decH >= 0) set.add(normalizePathname(dec.slice(0, decH)));

  return Array.from(set);
}

function sendJson(res, status, obj) {
  if (res.headersSent || res.writableEnded) return;
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
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

function serializeRulesForClient(protectedPaths) {
  return protectedPaths.map((p) => {
    if (p instanceof RegExp) return { regex: p.source, flags: p.flags.replace(/[gy]/g, "") };
    const raw = String(p).trim();
    return raw === "*" ? "*" : normalizePathname(raw);
  });
}

function isAutomationUa(headers) {
  const ua = String(headers?.["user-agent"] || "");
  const ch = String(headers?.["sec-ch-ua"] || "");
  return /HeadlessChrome|Playwright|Puppeteer|PhantomJS|SlimerJS/i.test(ua) || /HeadlessChrome/i.test(ch);
}

function normalizeIp(ip) {
  const s = String(ip || "").trim().toLowerCase().replace(/^::ffff:/, "");
  return s === "::1" ? "127.0.0.1" : s;
}

function parseIpv4Int(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

function parseIpv6BigInt(ip) {
  let s = String(ip || "").trim().toLowerCase();
  if (!s.includes(":")) return null;
  const lastColon = s.lastIndexOf(":");
  if (lastColon >= 0 && s.slice(lastColon + 1).includes(".")) {
    const v4 = parseIpv4Int(s.slice(lastColon + 1));
    if (v4 === null) return null;
    const hi = ((v4 >>> 16) & 0xffff).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - (left.length + right.length);
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 0) return null;
  const groups = [...left, ...Array(Math.max(0, missing)).fill("0"), ...right];
  if (groups.length !== 8) return null;
  let acc = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    acc = (acc << 16n) | BigInt(parseInt(g, 16));
  }
  return acc;
}

function compileTrustedProxies(spec) {
  const rawList = Array.isArray(spec)
    ? spec
    : typeof spec === "string"
      ? spec.split(",")
      : [];
  const exact = new Set();
  const cidrsV4 = [];
  const cidrsV6 = [];
  for (const item of rawList) {
    const entry = String(item || "").trim().toLowerCase();
    if (!entry) continue;
    const slash = entry.indexOf("/");
    if (slash > 0) {
      const baseRaw = entry.slice(0, slash);
      const bitsStr = entry.slice(slash + 1);
      if (!/^\d{1,3}$/.test(bitsStr)) continue;
      const bits = Number(bitsStr);
      const baseV6 = parseIpv6BigInt(baseRaw);
      if (baseV6 !== null && bits >= 0 && bits <= 128) {
        const mask = bits === 0 ? 0n : (((1n << BigInt(bits)) - 1n) << BigInt(128 - bits));
        cidrsV6.push({ net: baseV6 & mask, mask });
        continue;
      }
      const baseInt = parseIpv4Int(baseRaw);
      if (baseInt !== null && bits >= 0 && bits <= 32) {
        const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
        cidrsV4.push({ net: (baseInt & mask) >>> 0, mask });
        continue;
      }
      continue;
    }
    const rawV6 = parseIpv6BigInt(entry);
    if (rawV6 !== null) exact.add(`v6:${rawV6.toString(16)}`);
    exact.add(normalizeIp(entry));
  }
  return {
    size: exact.size + cidrsV4.length + cidrsV6.length,
    has(ip) {
      const raw = String(ip || "").trim().toLowerCase();
      const norm = normalizeIp(raw);
      if (exact.has(norm)) return true;
      const rawV6 = parseIpv6BigInt(raw);
      if (rawV6 !== null) {
        if (exact.has(`v6:${rawV6.toString(16)}`)) return true;
        for (const c of cidrsV6) {
          if ((rawV6 & c.mask) === c.net) return true;
        }
      }
      const v4 = parseIpv4Int(norm);
      if (v4 !== null) {
        for (const c of cidrsV4) {
          if (((v4 & c.mask) >>> 0) === c.net) return true;
        }
        if (cidrsV6.length > 0) {
          const mappedV6 = (0xffffn << 32n) | BigInt(v4);
          for (const c of cidrsV6) {
            if ((mappedV6 & c.mask) === c.net) return true;
          }
        }
      }
      return false;
    },
  };
}

function resolveClientIp(req, trustedProxies) {
  const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
  // Pass RAW IP (preserving ::1 / ::ffff:...) to trustedProxies.has() before normalizing return value (Loop 4 MED-9)
  if (remoteRaw && trustedProxies.size > 0 && trustedProxies.has(remoteRaw)) {
    const xff = String(req?.headers?.["x-forwarded-for"] || "");
    if (xff) {
      const rawParts = xff.split(",").map((s) => s.trim()).filter(Boolean);
      for (let i = rawParts.length - 1; i >= 0; i--) {
        if (!trustedProxies.has(rawParts[i])) {
          return normalizeIp(rawParts[i]);
        }
      }
      if (rawParts.length > 0) return normalizeIp(rawParts[0]);
    }
  }
  return normalizeIp(remoteRaw) || "unknown";
}

function createVeilBreakMiddleware(options = {}) {
  const mode = normalizeMode(options.mode ?? "strict");
  const basePath = String(options.basePath || "/__veilbreak").replace(/\/+$/, "") || "/__veilbreak";
  const protectedPaths = Array.isArray(options.protectedPaths) && options.protectedPaths.length > 0
    ? options.protectedPaths
    : ["/api"];
  const ticketTtlMs = Number.isFinite(options.ticketTtlMs) && options.ticketTtlMs > 0 ? options.ticketTtlMs : 60_000;
  const maxTickets = Number.isFinite(options.maxTickets) && options.maxTickets >= 100 ? options.maxTickets : 30_000;
  const maxTicketsPerMinPerIp =
    Number.isFinite(options.maxTicketsPerMinPerIp) && options.maxTicketsPerMinPerIp > 0
      ? options.maxTicketsPerMinPerIp
      : 180;
  const autoBlockPage = options.autoBlockPage !== false;
  const enablePlayground = options.enablePlayground !== false;
  const exposeDebugHeaders = options.exposeDebugHeaders !== false;
  const trustedProxies = compileTrustedProxies(options.trustProxy);
  const onDetect = typeof options.onDetect === "function" ? options.onDetect : null;

  const tickets = new Map();
  const ticketRates = new Map();
  const gateJs = buildBrowserGateScript({
    basePath,
    defaultMode: mode,
    protectedRules: serializeRulesForClient(protectedPaths),
    autoBlockPage,
  });
  const playgroundHtml = buildPlaygroundHtml({ basePath, mode });

  function allowTicketMint(ip, now) {
    const key = ip || "unknown";
    // Bounded expired-first LRU cleanup — never call `.clear()` wiping active rate buckets (MED-08)
    if (ticketRates.size > 10_000) {
      for (const [k, arr] of ticketRates) {
        const fresh = arr.filter((t) => now - t < 60_000);
        if (fresh.length === 0) ticketRates.delete(k);
      }
      if (ticketRates.size > 10_000) {
        const drop = ticketRates.size - 8_500;
        let i = 0;
        for (const k of ticketRates.keys()) {
          ticketRates.delete(k);
          if (++i >= drop) break;
        }
      }
    }
    const arr = (ticketRates.get(key) || []).filter((t) => now - t < 60_000);
    // Refresh Map order (delete + set) for true LRU so actively rate-limited IPs are NEVER evicted first (MED-20)
    ticketRates.delete(key);
    if (arr.length >= maxTicketsPerMinPerIp) {
      ticketRates.set(key, arr);
      return false;
    }
    arr.push(now);
    ticketRates.set(key, arr);
    return true;
  }

  function mintTicket() {
    const now = Date.now();
    if (tickets.size >= maxTickets) {
      // Evict ONLY expired tickets; refuse minting at capacity rather than kicking live users (MED-08)
      for (const [k, exp] of tickets) {
        if (exp <= now) tickets.delete(k);
      }
      if (tickets.size >= maxTickets) {
        return null;
      }
    }
    const tk = crypto.randomBytes(16).toString("hex");
    tickets.set(tk, now + ticketTtlMs);
    return tk;
  }

  function consumeTicket(tk) {
    if (!tk) return false;
    const now = Date.now();
    const exp = tickets.get(tk);
    if (!exp) return false;
    tickets.delete(tk);
    return exp > now;
  }

  async function handleInner(req, res, next) {
    const urlStr = req.originalUrl || req.url || "/";
    const pathname = normalizePathname(urlStr);

    if (req.method === "GET" && pathname === `${basePath}/gate.js`) {
      res.writeHead(200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Length": Buffer.byteLength(gateJs),
      });
      res.end(gateJs);
      return true;
    }

    if (enablePlayground && req.method === "GET" && pathname === `${basePath}/playground`) {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Length": Buffer.byteLength(playgroundHtml),
      });
      res.end(playgroundHtml);
      return true;
    }

    if (req.method === "GET" && pathname === `${basePath}/health`) {
      sendJson(res, 200, { ok: true, mode });
      return true;
    }

    if ((req.method === "GET" || req.method === "POST") && pathname === `${basePath}/ticket`) {
      const sfs = String(req.headers["sec-fetch-site"] || "").toLowerCase();
      if (sfs.includes("cross-site")) {
        sendJson(res, 403, { ok: false, error: "CROSS_SITE_TICKET_DENIED" });
        return true;
      }
      if ((mode === "strict" || mode === "balanced") && isAutomationUa(req.headers)) {
        sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["AUTOMATION_UA_DENIED"] });
        return true;
      }
      const remoteIp = resolveClientIp(req, trustedProxies);
      if (!allowTicketMint(remoteIp, Date.now())) {
        sendJson(res, 429, { ok: false, error: "TICKET_RATE_LIMITED" });
        return true;
      }
      const tk = mintTicket();
      if (!tk) {
        sendJson(res, 503, { ok: false, error: "TICKET_CAPACITY_EXCEEDED" });
        return true;
      }
      sendJson(res, 200, { ok: true, ticket: tk, mode });
      return true;
    }

    if (mode === "off") {
      if (typeof next === "function") next();
      return false;
    }

    // Allow CORS preflight OPTIONS without attestation
    if (req.method === "OPTIONS" && req.headers["access-control-request-method"]) {
      if (typeof next === "function") next();
      return false;
    }

    // Pass RAW urlStr so pre-hash & decoded-%3F/%23 bypasses are caught (Loop 3 CRIT-3 & HIGH-7)
    if (!isProtectedPath(urlStr, protectedPaths)) {
      if ((mode === "strict" || mode === "balanced") && isAutomationUa(req.headers)) {
        const verdict = { ok: false, blocked: true, score: 6, threshold: mode === "strict" ? 2 : 4, mode, reasons: ["AUTOMATION_UA_DENIED"] };
        if (exposeDebugHeaders) {
          res.setHeader("X-VeilBreak-Score", "6");
          res.setHeader("X-VeilBreak-Mode", mode);
        }
        if (onDetect) {
          try { onDetect({ ...verdict, path: pathname, method: req.method }); } catch {}
        }
        sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["AUTOMATION_UA_DENIED"] });
        return true;
      }
      if (typeof next === "function") next();
      return false;
    }

    const ticket = String(req.headers["x-vb-ticket"] || "");
    const nonce = String(req.headers["x-vb-nonce"] || "");
    let attest = null;
    try {
      const rawAtt = req.headers["x-vb-attest"];
      if (typeof rawAtt === "string" && rawAtt.trim()) attest = JSON.parse(rawAtt);
    } catch {
      attest = { invalid: true };
    }

    const ticketValid = consumeTicket(ticket);
    const verdict = verifyAttestation({ mode, headers: req.headers, attest, ticket, nonce });
    if ((mode === "strict" || mode === "balanced") && !ticketValid) {
      verdict.blocked = true;
      verdict.ok = false;
      verdict.score += 6;
      verdict.reasons.push("TICKET_REPLAYED_OR_INVALID");
    }

    req.veilBreak = verdict;
    if (exposeDebugHeaders) {
      res.setHeader("X-VeilBreak-Score", String(verdict.score));
      res.setHeader("X-VeilBreak-Mode", verdict.mode);
    }

    if ((verdict.blocked || verdict.score > 0) && onDetect) {
      try { onDetect({ ...verdict, path: pathname, method: req.method }); } catch {}
    }

    if (verdict.blocked) {
      const body = exposeDebugHeaders
        ? {
            ok: false,
            error: "VEILBREAK_DENIED",
            score: verdict.score,
            threshold: verdict.threshold,
            reasons: verdict.reasons,
          }
        : { ok: false, error: "VEILBREAK_DENIED" };
      sendJson(res, 403, body);
      return true;
    }

    if (typeof next === "function") next();
    return false;
  }

  function handle(req, res, next) {
    return handleInner(req, res, next).catch((err) => {
      if (typeof next === "function") {
        next(err);
        return true;
      }
      sendJson(res, 500, { ok: false, error: "INTERNAL_ERROR" });
      return true;
    });
  }

  handle.mode = mode;
  return handle;
}

function decodeHtmlBody(rawBuf, contentEncoding, maxOutputLength = 5 * 1024 * 1024) {
  const enc = String(contentEncoding || "").trim().toLowerCase();
  if (!enc || enc === "identity") return rawBuf;
  const opts = { maxOutputLength };
  if (enc === "gzip") return zlib.gunzipSync(rawBuf, opts);
  if (enc === "deflate") return zlib.inflateSync(rawBuf, opts);
  if (enc === "br") return zlib.brotliDecompressSync(rawBuf, opts);
  return null;
}

function injectGateIntoHtml(html, basePath, mode, autoBlockPage) {
  const safeSrc = escapeHtmlAttr(`${basePath}/gate.js`);
  const blockAttr = autoBlockPage === false ? "false" : "true";
  const tag = `<script src="${safeSrc}" data-mode="${escapeHtmlAttr(mode)}" data-block-page="${blockAttr}"></script>`;
  if (new RegExp(`<script\\b[^>]*\\bsrc=["']${safeSrc.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']`, "i").test(html)) {
    return html;
  }
  if (/<head(?:\s[^>]*)?>/i.test(html)) {
    return html.replace(/<head(?:\s[^>]*)?>/i, (m) => `${m}${tag}`);
  }
  if (/<\/head>/i.test(html)) {
    return html.replace(/<\/head>/i, (m) => `${tag}${m}`);
  }
  if (/<body(?:\s[^>]*)?>/i.test(html)) {
    return html.replace(/<body(?:\s[^>]*)?>/i, (m) => `${m}${tag}`);
  }
  return `${tag}${html}`;
}

function encodeForwardPathname(normPath) {
  return normPath
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
}

function createVeilBreakServer(options = {}) {
  const targetUrl = new URL(options.target || "http://127.0.0.1:3000");
  if (targetUrl.protocol !== "http:" && targetUrl.protocol !== "https:") {
    throw new Error(`Unsupported target protocol '${targetUrl.protocol}': expected http: or https:`);
  }
  const basePath = String(options.basePath || "/__veilbreak").replace(/\/+$/, "") || "/__veilbreak";
  const mode = normalizeMode(options.mode ?? "strict");
  const injectGate = options.injectGate !== false;
  const maxHtmlBytes = Number.isFinite(options.maxHtmlBytes) && options.maxHtmlBytes > 0 ? options.maxHtmlBytes : 5 * 1024 * 1024;
  const upstreamTimeoutMs = Number.isFinite(options.upstreamTimeoutMs) && options.upstreamTimeoutMs > 0 ? options.upstreamTimeoutMs : 30_000;
  const middleware = createVeilBreakMiddleware({ ...options, basePath, mode });
  const clientMod = targetUrl.protocol === "https:" ? https : http;
  const baseTargetPath = targetUrl.pathname && targetUrl.pathname !== "/" ? targetUrl.pathname.replace(/\/+$/, "") : "";

  const server = http.createServer((req, res) => {
    Promise.resolve(middleware(req, res))
      .then((handled) => {
        if (handled) return;

        // Reuse exact stripSchemeAndAuthority so `http://host?x=/api/secret` NEVER desyncs (Loop 4 CRIT-2)
        // and encode only unescaped non-RFC3986 bytes in query so valid %20/%3A are NEVER double-encoded (Loop 4 HIGH-5)
        let rawFwd = stripSchemeAndAuthority(req.url || "/");
        let fwdSearch = "";
        const qIdx = rawFwd.indexOf("?");
        if (qIdx >= 0) {
          fwdSearch = rawFwd.slice(qIdx);
          rawFwd = rawFwd.slice(0, qIdx);
        }
        const safeSearch = fwdSearch
          ? fwdSearch.replace(/[^A-Za-z0-9\-._~!$&'()*+,;=:@/?%]|%(?![0-9a-fA-F]{2})/g, (ch) => encodeURIComponent(ch))
          : "";
        let fwdPath = `${encodeForwardPathname(normalizePathname(rawFwd))}${safeSearch}`;
        if (baseTargetPath) fwdPath = `${baseTargetPath}${fwdPath}`;

        const fwdHeaders = stripHopByHop(req.headers, { isRequest: true });
        fwdHeaders.host = targetUrl.host;
        const remoteIp = normalizeIp(req.socket?.remoteAddress || "");
        if (remoteIp) {
          fwdHeaders["x-forwarded-for"] = fwdHeaders["x-forwarded-for"]
            ? `${fwdHeaders["x-forwarded-for"]}, ${remoteIp}`
            : remoteIp;
        }
        const acceptHdr = String(req.headers["accept"] || "").toLowerCase();
        if (injectGate && acceptHdr.includes("text/html")) {
          fwdHeaders["accept-encoding"] = "identity";
        }

        const upstreamReq = clientMod.request(
          {
            protocol: targetUrl.protocol,
            hostname: targetUrl.hostname,
            port: targetUrl.port || (targetUrl.protocol === "https:" ? 443 : 80),
            method: req.method,
            path: fwdPath,
            headers: fwdHeaders,
            timeout: upstreamTimeoutMs,
          },
          (upRes) => {
            upRes.on("error", () => {
              if (!res.headersSent) sendJson(res, 502, { ok: false, error: "UPSTREAM_ERROR" });
              else res.destroy();
            });

            const statusCode = upRes.statusCode || 200;
            const ct = String(upRes.headers["content-type"] || "").toLowerCase();
            const outHeaders = stripHopByHop(upRes.headers);
            const canHaveBody = req.method !== "HEAD" && statusCode !== 204 && statusCode !== 304;

            if (injectGate && canHaveBody && ct.includes("text/html")) {
              const chunks = [];
              let totalBytes = 0;
              let overflowed = false;
              upRes.on("data", (c) => {
                if (overflowed) {
                  res.write(c);
                  return;
                }
                totalBytes += c.length;
                if (totalBytes > maxHtmlBytes) {
                  overflowed = true;
                  res.writeHead(statusCode, outHeaders);
                  for (const prev of chunks) res.write(prev);
                  chunks.length = 0;
                  res.write(c);
                  return;
                }
                chunks.push(c);
              });
              upRes.on("end", () => {
                if (overflowed) {
                  res.end();
                  return;
                }
                const rawBuf = Buffer.concat(chunks);
                const ce = outHeaders["content-encoding"];
                let decoded = rawBuf;
                if (ce) {
                  try {
                    const maybe = decodeHtmlBody(rawBuf, ce, maxHtmlBytes);
                    if (!maybe) {
                      res.writeHead(statusCode, outHeaders);
                      res.end(rawBuf);
                      return;
                    }
                    decoded = maybe;
                    delete outHeaders["content-encoding"];
                  } catch {
                    res.writeHead(statusCode, outHeaders);
                    res.end(rawBuf);
                    return;
                  }
                }
                const html = injectGateIntoHtml(decoded.toString("utf8"), basePath, mode, options.autoBlockPage);
                const buf = Buffer.from(html, "utf8");
                outHeaders["content-length"] = String(buf.length);
                delete outHeaders["etag"];
                res.writeHead(statusCode, outHeaders);
                res.end(buf);
              });
              return;
            }
            res.writeHead(statusCode, outHeaders);
            upRes.pipe(res);
          }
        );

        upstreamReq.on("timeout", () => upstreamReq.destroy(new Error("UPSTREAM_TIMEOUT")));
        upstreamReq.on("error", () => {
          if (!res.headersSent) sendJson(res, 502, { ok: false, error: "UPSTREAM_UNREACHABLE" });
          else res.destroy();
        });
        res.on("close", () => {
          if (!res.writableEnded) upstreamReq.destroy();
        });
        req.pipe(upstreamReq);
      })
      .catch(() => {
        if (!res.headersSent) sendJson(res, 500, { ok: false, error: "INTERNAL_ERROR" });
      });
  });

  return {
    server,
    mode,
    listen(port = 8080, host = "127.0.0.1") {
      return new Promise((resolve, reject) => {
        const onErr = (err) => reject(err);
        server.once("error", onErr);
        server.listen(port, host, () => {
          server.removeListener("error", onErr);
          resolve(`http://${host}:${server.address().port}`);
        });
      });
    },
    close() {
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

module.exports = { createVeilBreakMiddleware, createVeilBreakServer, normalizePathname };
