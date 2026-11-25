"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");
const zlib = require("node:zlib");
const {
  normalizeMode,
  verifyAttestation,
  isAutomationOrCliUa,
  normalizePathname,
  stripSchemeAndAuthority,
  isProtectedPath,
  sha256Hex,
} = require("./probes.js");
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

const PROXY_LEAK_HEADERS = [
  "proxy-connection",
  "x-burp-header",
  "x-burp-collaborator",
  "x-caido-id",
  "x-caido-replay",
  "x-mitmproxy",
];

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

function sendJson(res, status, obj, extraHeaders = {}) {
  if (res.headersSent || res.writableEnded) return;
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
    ...extraHeaders,
  });
  res.end(payload);
}

function serializeRulesForClient(protectedPaths) {
  return protectedPaths.map((p) => {
    if (p instanceof RegExp) return { regex: p.source, flags: p.flags.replace(/[gy]/g, "") };
    const raw = String(p).trim();
    return raw === "*" ? "*" : normalizePathname(raw);
  });
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

function positiveIntOption(val, fallback, name) {
  if (val === undefined || val === null) return fallback;
  if (!Number.isInteger(val) || val < 1) {
    throw new Error(`Invalid VeilBreak option '${name}': expected a positive integer`);
  }
  return val;
}

function nonNegativeIntOption(val, fallback, name, maxVal = 22) {
  if (val === undefined || val === null) return fallback;
  if (!Number.isInteger(val) || val < 0 || val > maxVal) {
    throw new Error(`Invalid VeilBreak option '${name}': expected an integer in 0..${maxVal}`);
  }
  return val;
}

function parseHttpOriginHost(originRaw) {
  const s = String(originRaw || "").trim();
  if (!s) return "";
  try {
    const u = new URL(s);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password) return "";
    const h = u.host.toLowerCase();
    if (u.protocol === "http:" && h.endsWith(":80")) return h.slice(0, -3);
    if (u.protocol === "https:" && h.endsWith(":443")) return h.slice(0, -4);
    return h;
  } catch {
    return "";
  }
}

function normalizeHostDefaultPort(hostRaw) {
  const h = String(hostRaw || "").trim().toLowerCase();
  if (h.endsWith(":80")) return h.slice(0, -3);
  if (h.endsWith(":443")) return h.slice(0, -4);
  return h;
}

function isHtmlBootstrapNavigation(req) {
  const headers = req.headers || {};
  if (req.method !== "GET") return false;
  const accept = String(headers["accept"] || "").toLowerCase();
  const sfm = String(headers["sec-fetch-mode"] || "").trim().toLowerCase();
  const sfd = String(headers["sec-fetch-dest"] || "").trim().toLowerCase();
  const ua = String(headers["user-agent"] || "");
  if (!accept.includes("text/html")) return false;
  if (isAutomationOrCliUa(headers)) return false;
  if (headers["content-length"] && headers["transfer-encoding"]) return false;
  if (PROXY_LEAK_HEADERS.some((h) => headers[h] !== undefined)) return false;
  if (headers["x-original-url"] || headers["x-rewrite-url"]) return false;
  const cm = /Chrome\/(\d+)/i.exec(ua);
  const fm = /Firefox\/(\d+)/i.exec(ua);
  const claimsModern = (cm && Number(cm[1]) >= 80) || (fm && Number(fm[1]) >= 90);
  if (claimsModern && (sfm !== "navigate" || sfd !== "document")) return false;
  return true;
}

function createVeilBreakMiddleware(options = {}) {
  const mode = normalizeMode(options.mode ?? "strict");
  const basePath = String(options.basePath || "/__veilbreak").replace(/\/+$/, "") || "/__veilbreak";
  const protectedPaths =
    Array.isArray(options.protectedPaths) && options.protectedPaths.length > 0
      ? options.protectedPaths
      : ["/api"];
  const ticketTtlMs = Number.isFinite(options.ticketTtlMs) && options.ticketTtlMs > 0 ? options.ticketTtlMs : 60_000;
  const maxTickets = positiveIntOption(options.maxTickets, 30_000, "maxTickets");
  const maxTicketsPerMinPerIp = positiveIntOption(options.maxTicketsPerMinPerIp, 180, "maxTicketsPerMinPerIp");
  const ticketPowBits = nonNegativeIntOption(
    options.ticketPowBits,
    mode === "strict" ? 12 : mode === "balanced" ? 10 : 0,
    "ticketPowBits",
    22
  );
  const bindIp = options.bindIp !== false;
  const requireFetchMetadata = options.requireFetchMetadata !== undefined ? Boolean(options.requireFetchMetadata) : mode === "strict";
  const antiCdp = options.antiCdp !== false;
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
    antiCdp,
  });
  const playgroundHtml = buildPlaygroundHtml({ basePath, mode, antiCdp });

  function allowTicketMint(ip, now) {
    const key = ip || "unknown";
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
    ticketRates.delete(key);
    if (arr.length >= maxTicketsPerMinPerIp) {
      ticketRates.set(key, arr);
      return false;
    }
    arr.push(now);
    ticketRates.set(key, arr);
    return true;
  }

  function mintTicket({ ip, userAgent }) {
    const now = Date.now();
    if (tickets.size >= maxTickets) {
      for (const [k, rec] of tickets) {
        if (rec.exp <= now) tickets.delete(k);
      }
      if (tickets.size >= maxTickets) {
        return null;
      }
    }
    const tk = crypto.randomBytes(16).toString("hex");
    const challenge = crypto.randomBytes(16).toString("hex");
    tickets.set(tk, {
      exp: now + ticketTtlMs,
      ip: normalizeIp(ip),
      uaHash: sha256Hex(userAgent || ""),
      challenge,
      difficulty: ticketPowBits,
    });
    return { ticket: tk, challenge, difficulty: ticketPowBits };
  }

  function consumeTicket(tk) {
    if (!tk) return null;
    const now = Date.now();
    const rec = tickets.get(tk);
    if (!rec) return null;
    tickets.delete(tk);
    if (rec.exp <= now) return null;
    return rec;
  }

  async function handleInner(req, res, next) {
    const urlStr = req.originalUrl || req.url || "/";
    const pathname = normalizePathname(urlStr);
    const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
    const fromTrustedProxy = Boolean(remoteRaw && trustedProxies.size > 0 && trustedProxies.has(remoteRaw));

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
      const headers = req.headers || {};
      const sfs = String(headers["sec-fetch-site"] || "").trim().toLowerCase();
      const sfm = String(headers["sec-fetch-mode"] || "").trim().toLowerCase();
      const origin = String(headers["origin"] || "").trim();
      const host = String(headers["host"] || "").trim().toLowerCase();

      if (sfs.includes("cross-site")) {
        sendJson(res, 403, { ok: false, error: "CROSS_SITE_TICKET_DENIED" });
        return true;
      }
      if (origin && host) {
        const oh = parseHttpOriginHost(origin);
        if (!oh || oh !== normalizeHostDefaultPort(host)) {
          sendJson(res, 403, { ok: false, error: "CROSS_ORIGIN_TICKET_DENIED" });
          return true;
        }
      }
      if (mode === "strict" || mode === "balanced") {
        for (const ph of PROXY_LEAK_HEADERS) {
          if (headers[ph] !== undefined) {
            sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["PROXY_HEADER_LEAK"] });
            return true;
          }
        }
        if (isAutomationOrCliUa(headers)) {
          sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["AUTOMATION_UA_DENIED"] });
          return true;
        }
        const ua = String(headers["user-agent"] || "");
        const acceptLang = String(headers["accept-language"] || "").trim();
        const conn = String(headers["connection"] || "").trim().toLowerCase();
        const cm = /Chrome\/(\d+)/i.exec(ua);
        const fm = /Firefox\/(\d+)/i.exec(ua);
        const claimsModern = (cm && Number(cm[1]) >= 80) || (fm && Number(fm[1]) >= 90);
        if (requireFetchMetadata && claimsModern) {
          if (!sfs || (sfs !== "same-origin" && sfs !== "same-site") || !sfm) {
            sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["FETCH_METADATA_MISSING"] });
            return true;
          }
          if (!acceptLang) {
            sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["ACCEPT_LANGUAGE_REQUIRED"] });
            return true;
          }
          if (!fromTrustedProxy && conn === "close") {
            sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["REPEATER_CONNECTION_CLOSE"] });
            return true;
          }
        }
      }

      const remoteIp = resolveClientIp(req, trustedProxies);
      if (!allowTicketMint(remoteIp, Date.now())) {
        sendJson(res, 429, { ok: false, error: "TICKET_RATE_LIMITED" });
        return true;
      }
      const minted = mintTicket({ ip: remoteIp, userAgent: headers["user-agent"] || "" });
      if (!minted) {
        sendJson(res, 503, { ok: false, error: "TICKET_CAPACITY_EXCEEDED" });
        return true;
      }
      sendJson(res, 200, { ok: true, ...minted, mode }, { Vary: "Origin, User-Agent" });
      return true;
    }

    if (mode === "off") {
      if (typeof next === "function") next();
      return false;
    }

    // Strict cross-origin CORS preflight OPTIONS exemption
    const preOriginHost = parseHttpOriginHost(req.headers?.["origin"]);
    const preHost = normalizeHostDefaultPort(req.headers?.["host"]);
    const preUa = String(req.headers?.["user-agent"] || "");
    const preCm = /Chrome\/(\d+)/i.exec(preUa);
    const preFm = /Firefox\/(\d+)/i.exec(preUa);
    const preModern = ((preCm && Number(preCm[1]) >= 80) || (preFm && Number(preFm[1]) >= 90)) && !isAutomationOrCliUa(req.headers);
    const hasPreProxyLeak = PROXY_LEAK_HEADERS.some((h) => req.headers?.[h] !== undefined);
    const isCorsPreflight =
      req.method === "OPTIONS" &&
      req.headers?.["access-control-request-method"] &&
      Boolean(preOriginHost) &&
      (!preHost || preOriginHost !== preHost) &&
      !isAutomationOrCliUa(req.headers) &&
      !hasPreProxyLeak &&
      !req.headers?.["x-original-url"] &&
      !req.headers?.["x-rewrite-url"] &&
      !req.headers?.["x-http-method"] &&
      (!preModern ||
        (String(req.headers?.["sec-fetch-mode"] || "").toLowerCase() === "cors" &&
          (fromTrustedProxy || String(req.headers?.["connection"] || "").toLowerCase() !== "close"))) &&
      !(req.headers?.["content-length"] && req.headers?.["transfer-encoding"]) &&
      !req.headers?.["x-http-method-override"] &&
      !req.headers?.["x-method-override"];
    if (isCorsPreflight) {
      if (typeof next === "function") next();
      return false;
    }

    const overrideUrls = [req.headers?.["x-original-url"], req.headers?.["x-rewrite-url"]]
      .flat()
      .filter((u) => typeof u === "string" && u.trim() !== "");
    const overrideTargetsProtected = overrideUrls.some((u) => isProtectedPath(u, protectedPaths));
    const protectedHit = isProtectedPath(urlStr, protectedPaths) || overrideTargetsProtected;

    if (!protectedHit) {
      if ((mode === "strict" || mode === "balanced") && isAutomationOrCliUa(req.headers)) {
        const verdict = {
          ok: false,
          blocked: true,
          score: 6,
          threshold: mode === "strict" ? 2 : 4,
          mode,
          reasons: ["AUTOMATION_UA_DENIED"],
        };
        if (exposeDebugHeaders) {
          res.setHeader("X-VeilBreak-Score", "6");
          res.setHeader("X-VeilBreak-Mode", mode);
        }
        if (onDetect) {
          try { onDetect({ ...verdict, path: pathname, method: req.method }); } catch {}
        }
        const body = exposeDebugHeaders
          ? { ok: false, error: "VEILBREAK_DENIED", score: 6, threshold: verdict.threshold, reasons: ["AUTOMATION_UA_DENIED"] }
          : { ok: false, error: "VEILBREAK_DENIED" };
        sendJson(res, 403, body);
        return true;
      }
      if (typeof next === "function") next();
      return false;
    }

    const remoteIp = resolveClientIp(req, trustedProxies);
    const ticket = String(req.headers["x-vb-ticket"] || "");
    const nonce = String(req.headers["x-vb-nonce"] || "");
    let attest = null;
    try {
      const rawAtt = req.headers["x-vb-attest"];
      if (typeof rawAtt === "string" && rawAtt.trim()) attest = JSON.parse(rawAtt);
    } catch {
      attest = { invalid: true };
    }

    const ticketRec = consumeTicket(ticket);
    const verdict = verifyAttestation({
      mode,
      headers: req.headers,
      attest,
      ticket,
      nonce,
      expectedChallenge: ticketRec ? ticketRec.challenge : "",
      expectedDifficulty: ticketRec ? ticketRec.difficulty : 0,
      expectedMethod: ticketRec ? req.method : "",
      expectedPath: ticketRec ? urlStr : "",
      requireFetchMetadata,
    });

    if (overrideTargetsProtected) {
      verdict.score += 6;
      verdict.reasons.push("PROXY_PATH_OVERRIDE_HEADER");
      if (mode !== "monitor") {
        verdict.blocked = true;
        verdict.ok = false;
      }
    }

    if (mode === "strict" || mode === "balanced") {
      if (!ticketRec) {
        verdict.blocked = true;
        verdict.ok = false;
        verdict.score += 6;
        verdict.reasons.push("TICKET_REPLAYED_OR_INVALID");
      } else {
        const uaHash = sha256Hex(req.headers["user-agent"] || "");
        if ((bindIp && ticketRec.ip !== remoteIp) || ticketRec.uaHash !== uaHash) {
          verdict.blocked = true;
          verdict.ok = false;
          verdict.score += 6;
          verdict.reasons.push("TICKET_BINDING_MISMATCH");
        }
      }
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

function injectGateIntoHtml(html, basePath, mode, autoBlockPage, antiCdp = true) {
  const safeSrc = escapeHtmlAttr(`${basePath}/gate.js`);
  const blockAttr = autoBlockPage === false ? "false" : "true";
  const cdpAttr = antiCdp === false ? ' data-anti-cdp="false"' : "";
  const tag = `<script src="${safeSrc}" data-mode="${escapeHtmlAttr(mode)}" data-block-page="${blockAttr}"${cdpAttr}></script>`;
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
    .map((seg) => encodeURIComponent(seg.replace(/%3F/gi, "?")))
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
  const antiCdp = options.antiCdp !== false;
  const maxHtmlBytes = Number.isFinite(options.maxHtmlBytes) && options.maxHtmlBytes > 0 ? options.maxHtmlBytes : 5 * 1024 * 1024;
  const upstreamTimeoutMs = Number.isFinite(options.upstreamTimeoutMs) && options.upstreamTimeoutMs > 0 ? options.upstreamTimeoutMs : 30_000;
  const middleware = createVeilBreakMiddleware({ ...options, basePath, mode, antiCdp });
  const clientMod = targetUrl.protocol === "https:" ? https : http;
  const baseTargetPath = targetUrl.pathname && targetUrl.pathname !== "/" ? targetUrl.pathname.replace(/\/+$/, "") : "";

  const effectivePaths =
    Array.isArray(options.protectedPaths) && options.protectedPaths.length > 0 ? options.protectedPaths : ["/api"];
  const exposeDebugHeaders = options.exposeDebugHeaders !== false;

  const server = http.createServer((req, res) => {
    const htmlBootstrapProbe =
      injectGate &&
      mode !== "off" &&
      mode !== "monitor" &&
      isProtectedPath("/", effectivePaths) &&
      !req.headers?.["x-vb-ticket"] &&
      !req.headers?.["x-vb-attest"] &&
      isHtmlBootstrapNavigation(req) &&
      !normalizePathname(req.url || "/").startsWith(`${basePath}/`);

    const middlewareStep = htmlBootstrapProbe ? Promise.resolve(false) : Promise.resolve(middleware(req, res));

    middlewareStep
      .then((handled) => {
        if (handled) return;

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
        const normFwd = normalizePathname(rawFwd);
        const trailingSlash = rawFwd.length > 1 && rawFwd.endsWith("/") && normFwd !== "/" ? "/" : "";
        let fwdPath = `${encodeForwardPathname(normFwd)}${trailingSlash}${safeSearch}`;
        if (baseTargetPath) fwdPath = `${baseTargetPath}${fwdPath}`;

        const fwdHeaders = stripHopByHop(req.headers, { isRequest: true });
        delete fwdHeaders["x-original-url"];
        delete fwdHeaders["x-rewrite-url"];
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
        if (htmlBootstrapProbe) {
          delete fwdHeaders["if-modified-since"];
          delete fwdHeaders["if-none-match"];
        }

        let responded = false;
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
              if (responded) return;
              responded = true;
              if (!res.headersSent) sendJson(res, 502, { ok: false, error: "UPSTREAM_ERROR" });
              else res.destroy();
            });

            const statusCode = upRes.statusCode || 200;
            const ct = String(upRes.headers["content-type"] || "").toLowerCase();

            // For wildcard HTML-bootstrap probes, ONLY allow genuine text/html responses (or header-only 3xx redirects without forwarding any non-HTML body!)
            if (htmlBootstrapProbe && !ct.includes("text/html")) {
              if (statusCode >= 301 && statusCode <= 308 && statusCode !== 304 && Boolean(upRes.headers["location"])) {
                responded = true;
                const redirHeaders = stripHopByHop(upRes.headers);
                delete redirHeaders["content-length"];
                delete redirHeaders["content-encoding"];
                delete redirHeaders["content-type"];
                redirHeaders["content-length"] = "0";
                res.writeHead(statusCode, redirHeaders);
                res.end();
                upRes.destroy();
                return;
              }
              responded = true;
              if (typeof options.onDetect === "function") {
                try {
                  options.onDetect({
                    ok: false,
                    blocked: true,
                    score: 6,
                    threshold: mode === "strict" ? 2 : 4,
                    mode,
                    reasons: ["ATTEST_REQUIRED"],
                    method: req.method,
                    path: normalizePathname(req.url || "/"),
                  });
                } catch {}
              }
              const errBody = exposeDebugHeaders
                ? { ok: false, error: "VEILBREAK_DENIED", reasons: ["ATTEST_REQUIRED"] }
                : { ok: false, error: "VEILBREAK_DENIED" };
              sendJson(res, 403, errBody);
              upRes.destroy();
              return;
            }

            // Never let an unattested CORS OPTIONS preflight leak body from a non-CORS upstream route!
            if (
              req.method === "OPTIONS" &&
              Boolean(req.headers["access-control-request-method"]) &&
              !req.veilBreak &&
              mode !== "off" &&
              mode !== "monitor" &&
              isProtectedPath(req.url || "/", effectivePaths) &&
              !upRes.headers["access-control-allow-origin"]
            ) {
              responded = true;
              if (typeof options.onDetect === "function") {
                try {
                  options.onDetect({
                    ok: false,
                    blocked: true,
                    score: 6,
                    threshold: mode === "strict" ? 2 : 4,
                    mode,
                    reasons: ["CORS_PREFLIGHT_NOT_ENABLED"],
                    method: req.method,
                    path: normalizePathname(req.url || "/"),
                  });
                } catch {}
              }
              sendJson(res, 403, { ok: false, error: "CORS_PREFLIGHT_NOT_ENABLED" });
              upRes.destroy();
              return;
            }
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
                const html = injectGateIntoHtml(decoded.toString("utf8"), basePath, mode, options.autoBlockPage, antiCdp);
                const buf = Buffer.from(html, "utf8");
                outHeaders["content-length"] = String(buf.length);
                delete outHeaders["etag"];
                delete outHeaders["last-modified"];
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
          if (responded) return;
          responded = true;
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
      return new Promise((resolve) => {
        if (typeof server.closeIdleConnections === "function") server.closeIdleConnections();
        server.close(() => resolve());
        if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      });
    },
  };
}

module.exports = { createVeilBreakMiddleware, createVeilBreakServer, normalizePathname };
