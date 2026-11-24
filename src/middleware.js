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

function stripHopByHop(headers) {
  const out = {};
  const connTokens = new Set();
  const connVal = headers?.connection;
  if (typeof connVal === "string") {
    for (const tok of connVal.split(",")) {
      const t = tok.trim().toLowerCase();
      if (t) connTokens.add(t);
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

function normalizePathname(rawUrl) {
  let s = String(rawUrl || "/").trim();
  if (/^https?:\/\//i.test(s)) {
    try {
      s = new URL(s).pathname || "/";
    } catch {
      const idx = s.indexOf("/", s.indexOf("://") + 3);
      s = idx >= 0 ? s.slice(idx) : "/";
    }
  }
  const qIdx = s.search(/[?#]/);
  if (qIdx >= 0) s = s.slice(0, qIdx);
  if (!s) return "/";
  for (let pass = 0; pass < 2; pass++) {
    try {
      const dec = decodeURIComponent(s);
      if (dec === s) break;
      s = dec;
    } catch {
      break;
    }
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

function isProtectedPath(rawPathname, protectedPaths) {
  const norm = normalizePathname(rawPathname);
  const normLower = norm.toLowerCase();
  for (const rule of protectedPaths) {
    if (rule instanceof RegExp) {
      rule.lastIndex = 0;
      if (rule.test(norm)) return true;
    } else {
      const rNorm = normalizePathname(String(rule)).toLowerCase();
      if (
        rNorm === "*" ||
        rNorm === "/" ||
        normLower === rNorm ||
        normLower.startsWith(rNorm.endsWith("/") ? rNorm : `${rNorm}/`)
      ) {
        return true;
      }
    }
  }
  return false;
}

function serializeRulesForClient(protectedPaths) {
  return protectedPaths.map((p) =>
    p instanceof RegExp ? { regex: p.source, flags: p.flags.replace(/[gy]/g, "") } : normalizePathname(String(p))
  );
}

function isAutomationUa(headers) {
  const ua = String(headers?.["user-agent"] || "");
  const ch = String(headers?.["sec-ch-ua"] || "");
  return /HeadlessChrome|Playwright|Puppeteer|PhantomJS|SlimerJS/i.test(ua) || /HeadlessChrome/i.test(ch);
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
    if (ticketRates.size > 10_000) ticketRates.clear();
    const arr = (ticketRates.get(key) || []).filter((t) => now - t < 60_000);
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
      // First evict ONLY expired tickets so active users aren't kicked out
      for (const [k, exp] of tickets) {
        if (exp <= now) tickets.delete(k);
      }
      if (tickets.size >= maxTickets) {
        const target = Math.floor(maxTickets * 0.85);
        for (const k of tickets.keys()) {
          tickets.delete(k);
          if (tickets.size <= target) break;
        }
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

    if (req.method === "GET" && pathname === `${basePath}/ticket`) {
      if ((mode === "strict" || mode === "balanced") && isAutomationUa(req.headers)) {
        sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["AUTOMATION_UA_DENIED"] });
        return true;
      }
      const remoteIp = String(req.socket?.remoteAddress || "").replace(/^::ffff:/, "");
      if (!allowTicketMint(remoteIp, Date.now())) {
        sendJson(res, 429, { ok: false, error: "TICKET_RATE_LIMITED" });
        return true;
      }
      sendJson(res, 200, { ok: true, ticket: mintTicket(), mode });
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

    if (!isProtectedPath(pathname, protectedPaths)) {
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

function decodeHtmlBody(rawBuf, contentEncoding) {
  const enc = String(contentEncoding || "").trim().toLowerCase();
  if (!enc || enc === "identity") return rawBuf;
  if (enc === "gzip") return zlib.gunzipSync(rawBuf);
  if (enc === "deflate") return zlib.inflateSync(rawBuf);
  if (enc === "br") return zlib.brotliDecompressSync(rawBuf);
  return null;
}

function injectGateIntoHtml(html, basePath, mode, autoBlockPage) {
  const safeSrc = escapeHtmlAttr(`${basePath}/gate.js`);
  const blockAttr = autoBlockPage === false ? "false" : "true";
  const tag = `<script src="${safeSrc}" data-mode="${escapeHtmlAttr(mode)}" data-block-page="${blockAttr}"></script>`;
  if (html.includes(`${basePath}/gate.js`)) return html;
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

        let fwdPath = req.url || "/";
        if (/^https?:\/\//i.test(fwdPath)) {
          try {
            const parsed = new URL(fwdPath);
            fwdPath = `${parsed.pathname}${parsed.search}`;
          } catch {
            fwdPath = "/";
          }
        }
        if (!fwdPath.startsWith("/")) fwdPath = "/" + fwdPath;
        if (baseTargetPath) fwdPath = `${baseTargetPath}${fwdPath}`;

        const fwdHeaders = stripHopByHop(req.headers);
        fwdHeaders.host = targetUrl.host;
        const remoteIp = String(req.socket?.remoteAddress || "").replace(/^::ffff:/, "");
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
                    const maybe = decodeHtmlBody(rawBuf, ce);
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
