"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");
const { normalizeMode, verifyAttestation } = require("./probes.js");
const { buildBrowserGateScript, buildPlaygroundHtml } = require("./browser-sdk.js");

function sendJson(res, status, obj) {
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function isProtectedPath(pathname, protectedPaths) {
  for (const rule of protectedPaths) {
    if (rule instanceof RegExp) {
      if (rule.test(pathname)) return true;
    } else if (rule === "*" || rule === "/" || pathname === rule || pathname.startsWith(rule.endsWith("/") ? rule : `${rule}/`)) {
      return true;
    }
  }
  return false;
}

function createVeilBreakMiddleware(options = {}) {
  const mode = normalizeMode(options.mode ?? "strict");
  const basePath = options.basePath || "/__veilbreak";
  const protectedPaths = Array.isArray(options.protectedPaths) && options.protectedPaths.length > 0
    ? options.protectedPaths
    : ["/api"];
  const ticketTtlMs = Number.isFinite(options.ticketTtlMs) ? options.ticketTtlMs : 60_000;
  const autoBlockPage = options.autoBlockPage !== false;
  const onDetect = typeof options.onDetect === "function" ? options.onDetect : null;

  const tickets = new Map();
  const gateJs = buildBrowserGateScript({
    basePath,
    defaultMode: mode,
    protectedPaths: protectedPaths.filter((p) => typeof p === "string"),
    autoBlockPage,
  });
  const playgroundHtml = buildPlaygroundHtml({ basePath, mode });

  function mintTicket() {
    const now = Date.now();
    if (tickets.size > 30_000) {
      for (const [k, exp] of tickets) {
        if (exp <= now || tickets.size > 25_000) tickets.delete(k);
        if (tickets.size <= 25_000) break;
      }
    }
    const tk = crypto.randomBytes(16).toString("hex");
    tickets.set(tk, now + ticketTtlMs);
    return tk;
  }

  function consumeTicket(tk) {
    const now = Date.now();
    const exp = tickets.get(tk);
    if (!exp || exp <= now) return false;
    tickets.delete(tk);
    return true;
  }

  async function handle(req, res, next) {
    const urlStr = req.url || "/";
    const pathname = urlStr.split("?")[0] || "/";

    if (req.method === "GET" && pathname === `${basePath}/gate.js`) {
      res.writeHead(200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Length": Buffer.byteLength(gateJs),
      });
      res.end(gateJs);
      return true;
    }

    if (req.method === "GET" && pathname === `${basePath}/playground`) {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Length": Buffer.byteLength(playgroundHtml),
      });
      res.end(playgroundHtml);
      return true;
    }

    if (req.method === "GET" && pathname === `${basePath}/ticket`) {
      sendJson(res, 200, { ok: true, ticket: mintTicket(), mode });
      return true;
    }

    if (req.method === "GET" && pathname === `${basePath}/health`) {
      sendJson(res, 200, { ok: true, mode, version: "2.0.0" });
      return true;
    }

    if (!isProtectedPath(pathname, protectedPaths)) {
      if (mode === "strict") {
        const ua = String(req.headers["user-agent"] || "");
        const ch = String(req.headers["sec-ch-ua"] || "");
        if (/HeadlessChrome|Playwright|Puppeteer|PhantomJS/i.test(ua) || /HeadlessChrome/i.test(ch)) {
          sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["AUTOMATION_UA_DENIED"] });
          return true;
        }
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

    const ticketValid = mode === "strict" ? consumeTicket(ticket) : (ticket ? consumeTicket(ticket) : true);
    const verdict = verifyAttestation({ mode, headers: req.headers, attest, ticket, nonce });
    if (mode === "strict" && !ticketValid) {
      verdict.blocked = true;
      verdict.ok = false;
      verdict.reasons.push("TICKET_REPLAYED_OR_INVALID");
    }

    req.veilBreak = verdict;
    res.setHeader("X-VeilBreak-Score", String(verdict.score));
    res.setHeader("X-VeilBreak-Mode", verdict.mode);

    if ((verdict.blocked || verdict.score > 0) && onDetect) {
      try { onDetect({ ...verdict, path: pathname, method: req.method }); } catch {}
    }

    if (verdict.blocked) {
      sendJson(res, 403, {
        ok: false,
        error: "VEILBREAK_DENIED",
        score: verdict.score,
        threshold: verdict.threshold,
        reasons: verdict.reasons,
      });
      return true;
    }

    if (typeof next === "function") next();
    return false;
  }

  handle.mode = mode;
  return handle;
}

function createVeilBreakServer(options = {}) {
  const targetUrl = new URL(options.target || "http://127.0.0.1:3000");
  const basePath = options.basePath || "/__veilbreak";
  const mode = normalizeMode(options.mode ?? "strict");
  const injectGate = options.injectGate !== false;
  const middleware = createVeilBreakMiddleware({ ...options, basePath, mode });
  const clientMod = targetUrl.protocol === "https:" ? https : http;

  const server = http.createServer(async (req, res) => {
    const handled = await middleware(req, res);
    if (handled) return;

    const fwdHeaders = { ...req.headers, host: targetUrl.host };
    if (injectGate) delete fwdHeaders["accept-encoding"];

    const upstreamReq = clientMod.request(
      {
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || (targetUrl.protocol === "https:" ? 443 : 80),
        method: req.method,
        path: req.url,
        headers: fwdHeaders,
      },
      (upRes) => {
        const ct = String(upRes.headers["content-type"] || "").toLowerCase();
        const outHeaders = { ...upRes.headers };
        if (injectGate && ct.includes("text/html")) {
          const chunks = [];
          upRes.on("data", (c) => chunks.push(c));
          upRes.on("end", () => {
            let html = Buffer.concat(chunks).toString("utf8");
            const blockAttr = options.autoBlockPage === false ? "false" : "true";
            const tag = `<script src="${basePath}/gate.js" data-mode="${mode}" data-block-page="${blockAttr}"></script>`;
            if (!html.includes(`${basePath}/gate.js`)) {
              html = html.includes("</head>")
                ? html.replace("</head>", `${tag}</head>`)
                : `${tag}${html}`;
            }
            const buf = Buffer.from(html, "utf8");
            outHeaders["content-length"] = String(buf.length);
            delete outHeaders["transfer-encoding"];
            res.writeHead(upRes.statusCode || 200, outHeaders);
            res.end(buf);
          });
          return;
        }
        res.writeHead(upRes.statusCode || 200, outHeaders);
        upRes.pipe(res);
      }
    );

    upstreamReq.on("error", (err) => {
      if (!res.headersSent) {
        sendJson(res, 502, { ok: false, error: "UPSTREAM_UNREACHABLE", detail: err.message });
      }
    });
    req.pipe(upstreamReq);
  });

  return {
    server,
    mode,
    listen(port = 8080, host = "127.0.0.1") {
      return new Promise((resolve) => {
        server.listen(port, host, () => resolve(`http://${host}:${server.address().port}`));
      });
    },
    close() {
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

module.exports = { createVeilBreakMiddleware, createVeilBreakServer };
