"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");
const zlib = require("node:zlib");
const {
  PROXY_LEAK_HEADERS,
  normalizeMode,
  resolvePreset,
  verifyAttestation,
  verifyHandshakeProof,
  isAutomationOrCliUa,
  isAiCrawlerRequest,
  checkUnprotectedCrawlerOrCli,
  evaluateRequestHeaders,
  normalizePathname,
  CLEAN_ASCII_PATH_RE,
  normalizeProtectedPaths,
  compileProtectedPathRules,
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

function stripHopByHop(headers, { isRequest = false } = {}) {
  const out = {};
  if (!headers || typeof headers !== "object") return out;
  let connTokens = null;
  const connVal = !isRequest ? headers.connection : undefined;
  if (typeof connVal === "string" && connVal) {
    for (const tok of connVal.split(",")) {
      const t = tok.trim().toLowerCase();
      if (t && !PROTECTED_FROM_CONN_STRIP.has(t) && !t.startsWith("x-auth-") && !t.startsWith("cf-")) {
        if (!connTokens) connTokens = new Set();
        connTokens.add(t);
      }
    }
  }
  for (const k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    const kl = k.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(kl) || (connTokens && connTokens.has(kl))) continue;
    out[k] = headers[k];
  }
  return out;
}

function escapeHtmlAttr(s) {
  return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function sendJson(res, status, obj, extraHeaders = {}, isHead = false, req = null) {
  if (res.headersSent || res.writableEnded) return;
  const closeUnread =
    status >= 400 &&
    req &&
    (req.httpVersionMajor === undefined || req.httpVersionMajor < 2) &&
    !req.complete &&
    !req.readableEnded &&
    hasRequestBodyHeader(req.headers);
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
    ...(closeUnread ? { Connection: "close" } : {}),
    ...extraHeaders,
  });
  if (isHead) res.end();
  else res.end(payload);
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
  let exactV6Count = 0;
  const V4_MAPPED_PREFIX = 0xffffn << 32n;
  const V4_MAPPED_MASK = ((1n << 96n) - 1n) << 32n;
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
    if (rawV6 !== null) {
      exact.add(`v6:${rawV6.toString(16)}`);
      exactV6Count++;
      if ((rawV6 & V4_MAPPED_MASK) === V4_MAPPED_PREFIX) {
        const v4 = Number(rawV6 & 0xffffffffn);
        exact.add(`${(v4 >>> 24) & 255}.${(v4 >>> 16) & 255}.${(v4 >>> 8) & 255}.${v4 & 255}`);
      }
    }
    exact.add(normalizeIp(entry));
  }
  const hasV6Rules = exactV6Count > 0 || cidrsV6.length > 0;
  const hasMappedV6Cidrs = cidrsV6.some((c) => (c.net & V4_MAPPED_MASK) === (V4_MAPPED_PREFIX & c.mask));
  return {
    size: exact.size + cidrsV4.length + cidrsV6.length,
    has(ip) {
      const raw = String(ip || "").trim().toLowerCase();
      const norm = normalizeIp(raw);
      if (exact.has(norm)) return true;
      // Fast IPv4 / ::ffff:-mapped IPv4 path: skip BigInt & IPv6 CIDR loops unless a configured IPv6 CIDR actually overlaps ::ffff:0:0/96!
      if (!norm.includes(":") && (raw === norm || raw.startsWith("::ffff:"))) {
        if (cidrsV4.length > 0 || hasMappedV6Cidrs) {
          const v4 = parseIpv4Int(norm);
          if (v4 !== null) {
            for (let i = 0; i < cidrsV4.length; i++) {
              const c = cidrsV4[i];
              if (((v4 & c.mask) >>> 0) === c.net) return true;
            }
            if (hasMappedV6Cidrs) {
              const mappedV6 = V4_MAPPED_PREFIX | BigInt(v4);
              for (let i = 0; i < cidrsV6.length; i++) {
                const c = cidrsV6[i];
                if ((mappedV6 & c.mask) === c.net) return true;
              }
            }
          }
        }
        return false;
      }
      if (hasV6Rules) {
        const rawV6 = parseIpv6BigInt(raw);
        if (rawV6 !== null) {
          if (exact.has(`v6:${rawV6.toString(16)}`)) return true;
          for (let i = 0; i < cidrsV6.length; i++) {
            const c = cidrsV6[i];
            if ((rawV6 & c.mask) === c.net) return true;
          }
        }
      }
      return false;
    },
  };
}

function resolveClientIp(req, trustedProxies, expressTrustsProxy = false, fromTrustedProxy = null) {
  const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
  const trustedByList =
    fromTrustedProxy !== null
      ? Boolean(fromTrustedProxy && trustedProxies.size > 0)
      : Boolean(remoteRaw && trustedProxies.size > 0 && trustedProxies.has(remoteRaw));
  if (remoteRaw && trustedByList) {
    const xff = String(req?.headers?.["x-forwarded-for"] || "");
    if (xff) {
      // Zero-array right-to-left scan of X-Forwarded-For (only inspects rightmost hops!)
      let end = xff.length;
      let firstNonEmpty = "";
      while (end > 0) {
        const comma = xff.lastIndexOf(",", end - 1);
        const hop = xff.slice(comma + 1, end).trim();
        if (hop) {
          firstNonEmpty = hop;
          if (!trustedProxies.has(hop)) return normalizeIp(hop);
        }
        if (comma < 0) break;
        end = comma;
      }
      if (firstNonEmpty) return normalizeIp(firstNonEmpty);
    }
  }
  if (expressTrustsProxy && trustedProxies.size === 0 && req?.ip) {
    return normalizeIp(req.ip);
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
  if (!s || s.includes("?") || s.includes("#") || s.includes("@") || !/^https?:\/\/[^/\\]/i.test(s)) return "";
  try {
    const u = new URL(s);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password) return "";
    if (u.pathname !== "/" || u.search || u.hash || s.endsWith("/")) return "";
    const h = u.host.toLowerCase();
    if (u.protocol === "http:" && h.endsWith(":80")) return h.slice(0, -3);
    if (u.protocol === "https:" && h.endsWith(":443")) return h.slice(0, -4);
    return h;
  } catch {
    return "";
  }
}

function isTrustworthyOriginRequest(req, fromTrustedProxy) {
  if (req?.socket?.encrypted) return true;
  if (fromTrustedProxy) {
    const xfp = String(req?.headers?.["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
    if (xfp === "https") return true;
  }
  const host = String(req?.headers?.["host"] || "").trim().toLowerCase();
  const hostOnly = host.startsWith("[") ? host.slice(0, host.indexOf("]") + 1) : host.split(":")[0];
  return (
    !hostOnly ||
    hostOnly === "localhost" ||
    hostOnly === "127.0.0.1" ||
    hostOnly === "[::1]" ||
    hostOnly.endsWith(".localhost")
  );
}

function normalizeHostDefaultPort(hostRaw) {
  let h = String(hostRaw || "").trim().toLowerCase();
  if (!h) return "";
  if (h.startsWith("[")) {
    try {
      h = new URL(`http://${h}`).host.toLowerCase();
    } catch {
      // keep raw bracketed host if unparseable
    }
  }
  if (h.endsWith(":80")) return h.slice(0, -3);
  if (h.endsWith(":443")) return h.slice(0, -4);
  return h;
}

function hasDuplicateHostOrCl(rawHeaders) {
  if (!Array.isArray(rawHeaders) || rawHeaders.length === 0) return false;
  let hosts = 0;
  let cls = 0;
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const k = String(rawHeaders[i] || "").toLowerCase();
    if (k === "host") {
      if (++hosts > 1) return true;
    } else if (k === "content-length") {
      if (++cls > 1) return true;
    }
  }
  return false;
}

function hasRequestBodyHeader(headers) {
  if (!headers) return false;
  if (headers["transfer-encoding"]) return true;
  const clRaw = headers["content-length"];
  const clTrim = Array.isArray(clRaw) ? clRaw.join(",").trim() : String(clRaw ?? "").trim();
  return clTrim !== "" && !/^0+$/.test(clTrim);
}

function isHtmlBootstrapNavigation(req, { blockAiCrawlers = true, fromTrustedProxy = false, requireFetchMeta = true, strictConnectionCheck = true } = {}) {
  const headers = req.headers || {};
  if (req.method !== "GET") return false;
  const accept = String(headers["accept"] || "").toLowerCase();
  const sfm = String(headers["sec-fetch-mode"] || "").trim().toLowerCase();
  const sfd = String(headers["sec-fetch-dest"] || "").trim().toLowerCase();
  const sfs = String(headers["sec-fetch-site"] || "").trim().toLowerCase();
  const ua = String(headers["user-agent"] || "");
  if (!accept.includes("text/html")) return false;
  if (hasRequestBodyHeader(headers)) return false;
  if (hasDuplicateHostOrCl(req.rawHeaders)) return false;
  if (isAutomationOrCliUa(headers)) return false;
  if (blockAiCrawlers && isAiCrawlerRequest(headers)) return false;
  if (PROXY_LEAK_HEADERS.some((h) => headers[h] !== undefined)) return false;
  if (headers["x-original-url"] || headers["x-rewrite-url"]) return false;
  const cm = /Chrome\/(\d+)/i.exec(ua);
  const claimsModern = (cm && Number(cm[1]) >= 80) || (() => { const fm = /Firefox\/(\d+)/i.exec(ua); return Boolean(fm && Number(fm[1]) >= 90); })();
  if (sfm || sfd || (claimsModern && requireFetchMeta)) {
    const validDest = sfd === "document" || (sfd === "iframe" && (sfs === "same-origin" || sfs === "same-site"));
    if (sfm !== "navigate" || !validDest) return false;
  }
  if (claimsModern && strictConnectionCheck && !fromTrustedProxy && String(headers["connection"] || "").trim().toLowerCase() === "close") return false;
  return true;
}

function createVeilBreakMiddleware(options = {}) {
  const preset = resolvePreset(options.mode ?? "strict", options);
  const mode = preset.mode;
  const enforcing = mode === "strict" || mode === "balanced" || mode === "paranoid";
  const basePath = String(options.basePath || "/__veilbreak").replace(/\/+$/, "") || "/__veilbreak";
  const protectedPaths =
    Array.isArray(options.protectedPaths) && options.protectedPaths.length > 0
      ? options.protectedPaths
      : ["/api"];
  const normalizedProtectedPaths = compileProtectedPathRules(protectedPaths);
  const ticketTtlMs = Number.isFinite(options.ticketTtlMs) && options.ticketTtlMs > 0 ? options.ticketTtlMs : 60_000;
  const maxTickets = positiveIntOption(options.maxTickets, 30_000, "maxTickets");
  const maxTicketsPerMinPerIp = positiveIntOption(options.maxTicketsPerMinPerIp, 180, "maxTicketsPerMinPerIp");
  const ticketPowBits = nonNegativeIntOption(
    options.ticketPowBits,
    preset.ticketPowBits,
    "ticketPowBits",
    22
  );
  const bindIp = preset.bindIp;
  const requireFetchMetadata = preset.requireFetchMetadata;
  const explicitRequireFetchMetadata = options.requireFetchMetadata === true;
  const blockAiCrawlers = preset.blockAiCrawlers;
  const antiCdp = preset.antiCdp;
  const allowDevTools = preset.allowDevTools;
  const autoBlockPage = preset.autoBlockPage;
  const sri = preset.sri;
  const unified = Boolean(options.unified);
  const enablePlayground = options.enablePlayground !== false;
  const exposeDebugHeaders = options.exposeDebugHeaders !== false;
  const trustedProxies = compileTrustedProxies(options.trustProxy);
  const onDetect = typeof options.onDetect === "function" ? options.onDetect : null;

  const tickets = new Map();
  const ticketRates = new Map();
  const extStore = options.store && typeof options.store.get === "function" && typeof options.store.set === "function" ? options.store : null;
  if (extStore && typeof extStore.take !== "function" && typeof extStore.delete !== "function" && typeof extStore.del !== "function") {
    throw new Error("VeilBreak options.store must implement 'take', 'delete', or 'del' to enforce single-use tickets");
  }
  const allowBlockPageOverridePath =
    typeof options._allowBlockPageOverridePath === "string"
      ? options._allowBlockPageOverridePath
      : (enablePlayground ? `${basePath}/playground` : "");
  let _gateAsset = null;
  const ensureGateAsset = () => {
    if (!_gateAsset) {
      const js = buildBrowserGateScript({
        basePath,
        defaultMode: mode,
        protectedRules: serializeRulesForClient(protectedPaths),
        autoBlockPage,
        antiCdp,
        allowDevTools,
        unified,
        includeTicketPow: options.includeTicketPow !== undefined ? Boolean(options.includeTicketPow) : !unified,
        sri,
        userGestureWindowMs: options.userGestureWindowMs,
        allowBlockPageOverridePath,
      });
      const buf = Buffer.from(js, "utf8");
      const sriVal = `sha384-${crypto.createHash("sha384").update(buf).digest("base64")}`;
      const ver = crypto.createHash("sha256").update(buf).digest("hex").slice(0, 12);
      const verQueryRe = new RegExp(`(?:^|&)v=${ver}(?:&|$)`);
      _gateAsset = { js, buf, sri: sriVal, version: ver, verQueryRe, br: null, gz: null };
    }
    return _gateAsset;
  };
  if (!options._lazyGateScript) ensureGateAsset();
  const pickGateJsEncoding = (req) => {
    const ga = ensureGateAsset();
    const ae = String(req?.headers?.["accept-encoding"] || "").toLowerCase();
    if (/\bbr\b(?!\s*;\s*q\s*=\s*0(?:\.0+)?(?![.\d]))/.test(ae)) {
      if (!ga.br) {
        ga.br = zlib.brotliCompressSync(ga.buf, {
          params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 },
        });
      }
      return { buf: ga.br, enc: "br", etag: `"${ga.version}-br"` };
    }
    if (/\bgzip\b(?!\s*;\s*q\s*=\s*0(?:\.0+)?(?![.\d]))/.test(ae)) {
      if (!ga.gz) ga.gz = zlib.gzipSync(ga.buf, { level: 6 });
      return { buf: ga.gz, enc: "gzip", etag: `"${ga.version}-gzip"` };
    }
    return { buf: ga.buf, enc: "", etag: `"${ga.version}"` };
  };
  const playgroundHtmlBuf = enablePlayground
    ? Buffer.from(buildPlaygroundHtml({ basePath, mode, antiCdp }), "utf8")
    : null;

  function allowTicketMint(ip, now) {
    const key = ip || "unknown";
    if (!ticketRates.has(key) && ticketRates.size >= 10_000) {
      for (const [k, arr] of ticketRates) {
        if (arr.length === 0 || now - arr[arr.length - 1] >= 60_000) ticketRates.delete(k);
        else break;
      }
      if (ticketRates.size >= 10_000) {
        const drop = ticketRates.size - 8_500;
        let i = 0;
        for (const k of ticketRates.keys()) {
          ticketRates.delete(k);
          if (++i >= drop) break;
        }
      }
    }
    let arr = ticketRates.get(key);
    let start = 0;
    if (!arr) {
      arr = [];
    } else {
      while (start < arr.length && now - arr[start] >= 60_000) start++;
      if (start > 0) arr = arr.slice(start);
    }
    // Check limit BEFORE deleting from Map so rejected requests preserve strict insertion-order monotonicity for O(1) head-pruning!
    if (arr.length >= maxTicketsPerMinPerIp) {
      if (start > 0) ticketRates.set(key, arr);
      return false;
    }
    ticketRates.delete(key);
    arr.push(now);
    ticketRates.set(key, arr);
    return true;
  }

  async function mintTicket({ ip, userAgent }) {
    const now = Date.now();
    const tk = crypto.randomBytes(16).toString("hex");
    const challenge = crypto.randomBytes(16).toString("hex");
    const uaStr = String(userAgent || "");
    const rec = {
      exp: now + ticketTtlMs,
      ip: normalizeIp(ip),
      ua: uaStr,
      uaHash: sha256Hex(uaStr),
      challenge,
      difficulty: ticketPowBits,
    };
    if (extStore) {
      await extStore.set(`vb:tk:${tk}`, rec, ticketTtlMs);
      return { ticket: tk, challenge, difficulty: ticketPowBits };
    }
    if (tickets.size >= maxTickets) {
      for (const [k, r] of tickets) {
        if (r.exp <= now) tickets.delete(k);
        else break;
      }
      if (tickets.size >= maxTickets) {
        return null;
      }
    }
    tickets.set(tk, rec);
    return { ticket: tk, challenge, difficulty: ticketPowBits };
  }

  const TICKET_HEX_RE = /^[a-f0-9]{32}$/;
  async function consumeTicket(tk) {
    if (typeof tk !== "string" || !TICKET_HEX_RE.test(tk)) return null;
    const now = Date.now();
    if (extStore) {
      const key = `vb:tk:${tk}`;
      const rec = typeof extStore.take === "function"
        ? await extStore.take(key)
        : await (async () => {
            const v = await extStore.get(key);
            if (v && typeof extStore.delete === "function") await extStore.delete(key);
            else if (v && typeof extStore.del === "function") await extStore.del(key);
            return v;
          })();
      if (!rec || rec.exp <= now) return null;
      return rec;
    }
    const rec = tickets.get(tk);
    if (!rec) return null;
    tickets.delete(tk);
    if (rec.exp <= now) return null;
    return rec;
  }

  const prePathCache = new WeakMap();
  const cleanRawPathCache = new WeakMap();

  async function handleInner(req, res, next) {
    const urlStr = req.originalUrl || req.url || "/";
    const cachedPath = prePathCache.get(req);
    const qIdxUrl = urlStr.indexOf("?");
    let isCleanAscii = false;
    let pathname;
    if (typeof cachedPath === "string") {
      pathname = cachedPath;
    } else {
      const rawPathOnly = qIdxUrl >= 0 ? urlStr.slice(0, qIdxUrl) : urlStr;
      if (CLEAN_ASCII_PATH_RE.test(rawPathOnly)) {
        isCleanAscii = true;
        cleanRawPathCache.set(req, rawPathOnly);
        pathname = rawPathOnly.length > 1 && rawPathOnly.endsWith("/") ? rawPathOnly.slice(0, -1) : rawPathOnly || "/";
      } else {
        pathname = normalizePathname(urlStr);
      }
    }

    if ((req.method === "GET" || req.method === "HEAD") && pathname === `${basePath}/gate.js`) {
      const ga = ensureGateAsset();
      const query = qIdxUrl >= 0 ? urlStr.slice(qIdxUrl + 1) : "";
      const hasMatchingVer = ga.verQueryRe.test(query);
      const ccVal = hasMatchingVer
        ? "public, max-age=31536000, immutable, no-transform"
        : "public, no-cache, no-transform";
      const asset = pickGateJsEncoding(req);
      const inm = String(req.headers["if-none-match"] || "").trim();
      const inmMatches =
        Boolean(inm) &&
        (inm === "*" ||
          inm === asset.etag ||
          inm === `W/${asset.etag}` ||
          (inm.includes(",") && inm.split(",").some((t) => { const s = t.trim(); return s === "*" || s === asset.etag || s === `W/${asset.etag}`; })));
      if (inmMatches) {
        res.writeHead(304, {
          ETag: asset.etag,
          "Cache-Control": ccVal,
          Vary: "Accept-Encoding",
        });
        res.end();
        return true;
      }
      res.writeHead(200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": ccVal,
        ETag: asset.etag,
        Vary: "Accept-Encoding",
        ...(asset.enc ? { "Content-Encoding": asset.enc } : {}),
        "X-Content-Type-Options": "nosniff",
        "Content-Length": asset.buf.length,
      });
      if (req.method === "HEAD") res.end();
      else res.end(asset.buf);
      return true;
    }

    if (enablePlayground && playgroundHtmlBuf && (req.method === "GET" || req.method === "HEAD") && pathname === `${basePath}/playground`) {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Length": playgroundHtmlBuf.length,
      });
      if (req.method === "HEAD") res.end();
      else res.end(playgroundHtmlBuf);
      return true;
    }

    if ((req.method === "GET" || req.method === "HEAD") && pathname === `${basePath}/health`) {
      sendJson(res, 200, { ok: true, mode }, {}, req.method === "HEAD");
      return true;
    }

    // Lazily evaluate trustedProxies CIDR / Express trust-proxy lookup only when actually needed
    // (zero CIDR/Express overhead on static gate.js, playground, health, mode:"off", and unprotected routes!)
    let _trustCache = null;
    const getTrustInfo = () => {
      if (!_trustCache) {
        const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
        const expressTrustsProxy = Boolean(req?.app && typeof req.app.get === "function" && req.app.get("trust proxy"));
        const remoteInTrustedProxies = Boolean(remoteRaw && trustedProxies.size > 0 && trustedProxies.has(remoteRaw));
        const fromTrustedProxy = trustedProxies.size > 0 ? remoteInTrustedProxies : expressTrustsProxy;
        _trustCache = { expressTrustsProxy, remoteInTrustedProxies, fromTrustedProxy };
      }
      return _trustCache;
    };

    if ((req.method === "GET" || req.method === "POST") && pathname === `${basePath}/ticket`) {
      const { expressTrustsProxy, remoteInTrustedProxies, fromTrustedProxy } = getTrustInfo();
      const headers = req.headers || {};
      const sfs = String(headers["sec-fetch-site"] || "").trim().toLowerCase();
      const sfm = String(headers["sec-fetch-mode"] || "").trim().toLowerCase();
      const origin = String(headers["origin"] || "").trim();
      const host = String(headers["host"] || "").trim().toLowerCase();

      if (hasDuplicateHostOrCl(req.rawHeaders)) {
        sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["DUPLICATE_HEADER_SMUGGLING"] }, {}, false, req);
        return true;
      }
      if (sfs.includes("cross-site")) {
        sendJson(res, 403, { ok: false, error: "CROSS_SITE_TICKET_DENIED" }, {}, false, req);
        return true;
      }
      if (origin) {
        const oh = parseHttpOriginHost(origin);
        const normHost = host ? normalizeHostDefaultPort(host) : "";
        const xfhFirst = fromTrustedProxy
          ? normalizeHostDefaultPort(String(headers["x-forwarded-host"] || "").split(",")[0] || "")
          : "";
        if (!oh || ((!normHost || oh !== normHost) && (!xfhFirst || oh !== xfhFirst))) {
          sendJson(res, 403, { ok: false, error: "CROSS_ORIGIN_TICKET_DENIED" }, {}, false, req);
          return true;
        }
      }
      if (enforcing) {
        for (const ph of PROXY_LEAK_HEADERS) {
          if (headers[ph] !== undefined) {
            sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["PROXY_HEADER_LEAK"] }, {}, false, req);
            return true;
          }
        }
        if (blockAiCrawlers && isAiCrawlerRequest(headers)) {
          sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["AI_CRAWLER_OR_SCRAPER_DENIED"] }, {}, false, req);
          return true;
        }
        if (isAutomationOrCliUa(headers)) {
          sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["AUTOMATION_UA_DENIED"] }, {}, false, req);
          return true;
        }
        const ua = String(headers["user-agent"] || "");
        const acceptLang = String(headers["accept-language"] || "").trim();
        const conn = String(headers["connection"] || "").trim().toLowerCase();
        const cm = /Chrome\/(\d+)/i.exec(ua);
        const claimsModern = (cm && Number(cm[1]) >= 80) || (() => { const fm = /Firefox\/(\d+)/i.exec(ua); return Boolean(fm && Number(fm[1]) >= 90); })();
        const effFetchMeta = requireFetchMetadata && (explicitRequireFetchMetadata || isTrustworthyOriginRequest(req, fromTrustedProxy));
        if (effFetchMeta && claimsModern) {
          if (!sfs || (sfs !== "same-origin" && sfs !== "same-site") || !sfm) {
            sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["FETCH_METADATA_MISSING"] }, {}, false, req);
            return true;
          }
          if (!acceptLang) {
            sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["ACCEPT_LANGUAGE_REQUIRED"] }, {}, false, req);
            return true;
          }
          if (mode !== "balanced" && !fromTrustedProxy && conn === "close") {
            sendJson(res, 403, { ok: false, error: "VEILBREAK_DENIED", reasons: ["REPEATER_CONNECTION_CLOSE"] }, {}, false, req);
            return true;
          }
        }
      }

      const remoteIp = resolveClientIp(req, trustedProxies, expressTrustsProxy, remoteInTrustedProxies);
      if (!allowTicketMint(remoteIp, Date.now())) {
        sendJson(res, 429, { ok: false, error: "TICKET_RATE_LIMITED" }, {}, false, req);
        return true;
      }
      const minted = await mintTicket({ ip: remoteIp, userAgent: headers["user-agent"] || "" });
      if (!minted) {
        sendJson(res, 503, { ok: false, error: "TICKET_CAPACITY_EXCEEDED" }, {}, false, req);
        return true;
      }
      sendJson(res, 200, { ok: true, ...minted, mode }, { Vary: "Origin, User-Agent" });
      return true;
    }

    if (mode === "off") {
      if (typeof next === "function") next();
      return false;
    }

    // Strict cross-origin CORS preflight OPTIONS exemption (only parsed when method === OPTIONS with non-empty ACRM)
    if (req.method === "OPTIONS" && Boolean(String(req.headers?.["access-control-request-method"] || "").trim())) {
      const { fromTrustedProxy } = getTrustInfo();
      const preOriginHost = parseHttpOriginHost(req.headers?.["origin"]);
      const preHost = normalizeHostDefaultPort(req.headers?.["host"]);
      const preXfhFirst = fromTrustedProxy
        ? normalizeHostDefaultPort(String(req.headers?.["x-forwarded-host"] || "").split(",")[0] || "")
        : "";
      const preUa = String(req.headers?.["user-agent"] || "");
      const cliPre = isAutomationOrCliUa(req.headers);
      const crawlerPre = blockAiCrawlers && isAiCrawlerRequest(req.headers);
      const preModern =
        !cliPre &&
        !crawlerPre &&
        ((() => { const preCm = /Chrome\/(\d+)/i.exec(preUa); return Boolean(preCm && Number(preCm[1]) >= 80); })() ||
          (() => { const preFm = /Firefox\/(\d+)/i.exec(preUa); return Boolean(preFm && Number(preFm[1]) >= 90); })());
      const hasPreProxyLeak = PROXY_LEAK_HEADERS.some((h) => req.headers?.[h] !== undefined);
      const sameOriginPre = Boolean(preOriginHost && ((preHost && preOriginHost === preHost) || (preXfhFirst && preOriginHost === preXfhFirst)));
      const isCorsPreflight =
        !hasDuplicateHostOrCl(req.rawHeaders) &&
        Boolean(preOriginHost) &&
        !sameOriginPre &&
        !cliPre &&
        !crawlerPre &&
        !hasPreProxyLeak &&
        !req.headers?.["x-original-url"] &&
        !req.headers?.["x-rewrite-url"] &&
        !req.headers?.["x-http-method"] &&
        (!preModern ||
          (String(req.headers?.["sec-fetch-mode"] || "").toLowerCase() === "cors" &&
            (fromTrustedProxy || String(req.headers?.["connection"] || "").toLowerCase() !== "close"))) &&
        !hasRequestBodyHeader(req.headers) &&
        !req.headers?.["x-http-method-override"] &&
        !req.headers?.["x-method-override"] &&
        !req.headers?.["x-vb-ticket"] &&
        !req.headers?.["x-vb-attest"];
      if (isCorsPreflight) {
        if (typeof next === "function") next();
        return false;
      }
    }

    const origHdr = req.headers?.["x-original-url"];
    const rewHdr = req.headers?.["x-rewrite-url"];
    let overrideTargetsProtected = false;
    if (origHdr !== undefined || rewHdr !== undefined) {
      const MAX_OV_PARTS = 16;
      let totalOv = 0;
      const checkOvStr = (s) => {
        if (typeof s !== "string") return false;
        const trimmed = s.trim();
        if (!trimmed) return false;
        if (++totalOv > MAX_OV_PARTS) return true;
        if (isProtectedPath(trimmed, normalizedProtectedPaths, true)) return true;
        let commasSeen = 0;
        let comma = trimmed.indexOf(",");
        if (comma >= 0) {
          let start = 0;
          while (start <= trimmed.length) {
            if (comma >= 0 && ++commasSeen > MAX_OV_PARTS) return true;
            const end = comma >= 0 ? comma : trimmed.length;
            const pt = trimmed.slice(start, end).trim();
            if (pt) {
              if (++totalOv > MAX_OV_PARTS) return true;
              if (isProtectedPath(pt, normalizedProtectedPaths, true)) return true;
            }
            if (comma < 0) break;
            start = comma + 1;
            comma = trimmed.indexOf(",", start);
          }
        }
        return false;
      };
      const checkOv = (v) => (Array.isArray(v) ? v.some(checkOvStr) : checkOvStr(v));
      overrideTargetsProtected = checkOv(origHdr) || checkOv(rewHdr);
    }
    const protectedHit =
      isProtectedPath(urlStr, normalizedProtectedPaths, true, isCleanAscii ? pathname : null) || overrideTargetsProtected;

    if (!protectedHit) {
      if (enforcing) {
        const { crawlerHit, cliHit } = checkUnprotectedCrawlerOrCli(req.headers, blockAiCrawlers);
        if (crawlerHit || cliHit) {
          const denyReason = crawlerHit ? "AI_CRAWLER_OR_SCRAPER_DENIED" : "AUTOMATION_UA_DENIED";
          const verdict = {
            ok: false,
            blocked: true,
            score: 6,
            threshold: preset.threshold,
            mode,
            reasons: [denyReason],
          };
          if (exposeDebugHeaders) {
            res.setHeader("X-VeilBreak-Score", "6");
            res.setHeader("X-VeilBreak-Mode", mode);
          }
          if (onDetect) {
            try { onDetect({ ...verdict, path: pathname, method: req.method }); } catch {}
          }
          const body = exposeDebugHeaders
            ? { ok: false, error: "VEILBREAK_DENIED", score: 6, threshold: verdict.threshold, reasons: [denyReason] }
            : { ok: false, error: "VEILBREAK_DENIED" };
          sendJson(res, 403, body, {}, req.method === "HEAD", req);
          return true;
        }
      }
      if (typeof next === "function") next();
      return false;
    }

    const ticket = String(req.headers["x-vb-ticket"] || "");
    const nonce = String(req.headers["x-vb-nonce"] || "");
    const rawAtt = req.headers["x-vb-attest"];
    const hasRawAtt = typeof rawAtt === "string" && rawAtt.trim().length > 0;
    const validTicketSyntax = TICKET_HEX_RE.test(ticket);
    const { expressTrustsProxy, remoteInTrustedProxies, fromTrustedProxy } = getTrustInfo();
    const effFetchMetaReq = requireFetchMetadata && (explicitRequireFetchMetadata || isTrustworthyOriginRequest(req, fromTrustedProxy));
    let attest = null;
    if (hasRawAtt) {
      if (rawAtt.length > 8192) {
        attest = { invalid: true };
      } else {
        try {
          attest = JSON.parse(rawAtt);
        } catch {
          attest = { invalid: true };
        }
      }
    }
    // Pre-gate extStore (Redis) lookups behind cheap structural + single evaluateRequestHeaders() checks (zero Redis hits on malformed/override/crawler floods!)
    let skipStoreLookup = !validTicketSyntax;
    let preHdrEval = null;
    if (!skipStoreLookup && enforcing && extStore) {
      const attShapeOk =
        Boolean(attest) &&
        typeof attest === "object" &&
        !Array.isArray(attest) &&
        typeof attest.d === "string" &&
        /^[0-9a-f]{64}$/i.test(attest.d) &&
        Number.isInteger(attest.s) &&
        attest.s >= 0 &&
        attest.s <= 10_000 &&
        Number.isInteger(attest.f) &&
        attest.f >= 0;
      const nonceShapeOk = /^[A-Za-z0-9_-]{8,64}$/.test(nonce);
      if (overrideTargetsProtected || !attShapeOk || !nonceShapeOk) {
        skipStoreLookup = true;
      } else {
        preHdrEval = evaluateRequestHeaders(req.headers, {
          enforcing,
          requireFetchMetadata: effFetchMetaReq,
          blockAiCrawlers,
          expectedMethod: req.method,
        });
        if (preHdrEval.score >= preset.threshold) {
          skipStoreLookup = true;
        }
      }
    }

    const ticketRec = skipStoreLookup ? null : await consumeTicket(ticket);
    const verdict = verifyAttestation({
      mode,
      headers: req.headers,
      attest,
      ticket,
      nonce,
      expectedChallenge: ticketRec ? ticketRec.challenge : "",
      expectedDifficulty: ticketRec ? ticketRec.difficulty : 0,
      expectedMethod: req.method,
      expectedPath: ticketRec ? pathname : "",
      _expectedPathNormalized: Boolean(ticketRec),
      requireFetchMetadata: effFetchMetaReq,
      blockAiCrawlers,
      antiCdp,
      allowDevTools,
      _preset: preset,
      _precomputedHdrEval: preHdrEval,
    });

    if (overrideTargetsProtected) {
      verdict.score += 6;
      verdict.reasons.push("PROXY_PATH_OVERRIDE_HEADER");
      if (mode !== "monitor") {
        verdict.blocked = true;
        verdict.ok = false;
      }
    }

    let retryTicketHint = false;
    if (enforcing) {
      if (!ticketRec) {
        verdict.blocked = true;
        verdict.ok = false;
        verdict.score += 6;
        verdict.reasons.push("TICKET_REPLAYED_OR_INVALID");
      } else {
        const curUa = String(req.headers["user-agent"] || "");
        const ipChanged = bindIp && ticketRec.ip !== resolveClientIp(req, trustedProxies, expressTrustsProxy, remoteInTrustedProxies);
        const uaChanged =
          ticketRec.ua !== undefined
            ? ticketRec.ua !== curUa
            : ticketRec.uaHash !== sha256Hex(curUa);
        if (ipChanged || uaChanged) {
          // If ONLY the IP changed (mobile Wi-Fi<->5G roam or dual-stack Happy Eyeballs) and attestation itself was clean, signal safe 1x retry
          if (ipChanged && !uaChanged && !verdict.blocked) {
            retryTicketHint = true;
          }
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
      const extraHdrs = {};
      if (retryTicketHint) extraHdrs["X-VB-Retry-Ticket"] = "1";
      // Hint Post-Redirect-Get recovery when a redirected GET re-sent a prior POST's consumed ticket
      if (
        (req.method === "GET" || req.method === "HEAD") &&
        ticket &&
        (verdict.reasons.includes("TICKET_REPLAYED_OR_INVALID") || verdict.reasons.includes("REQUEST_BINDING_MISMATCH"))
      ) {
        extraHdrs["X-VB-Redirect-Get"] = "1";
      }
      const body = exposeDebugHeaders
        ? {
            ok: false,
            error: "VEILBREAK_DENIED",
            score: verdict.score,
            threshold: verdict.threshold,
            reasons: verdict.reasons,
          }
        : { ok: false, error: "VEILBREAK_DENIED" };
      sendJson(res, 403, body, extraHdrs, req.method === "HEAD", req);
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
      sendJson(res, 500, { ok: false, error: "INTERNAL_ERROR" }, {}, false, req);
      return true;
    });
  }

  handle.mode = mode;
  handle.basePath = basePath;
  handle._trustedProxies = trustedProxies;
  handle._setPrePath = (req, p) => { prePathCache.set(req, p); };
  handle._getPrePath = (req) => prePathCache.get(req);
  handle._setCleanRawPath = (req, p) => { cleanRawPathCache.set(req, p); };
  handle._getCleanRawPath = (req) => cleanRawPathCache.get(req);
  Object.defineProperties(handle, {
    gateSri: { enumerable: true, get: () => ensureGateAsset().sri },
    gateVersion: { enumerable: true, get: () => ensureGateAsset().version },
    gateJs: { enumerable: true, get: () => ensureGateAsset().js },
  });
  handle.preset = preset;
  handle.verifyHandshakeProof = (opts) => {
    const hasPresetOverride =
      opts &&
      (opts.mode !== undefined ||
        opts.requireFetchMetadata !== undefined ||
        opts.blockAiCrawlers !== undefined ||
        opts.antiCdp !== undefined ||
        opts.allowDevTools !== undefined);
    const verdict = verifyHandshakeProof({
      mode,
      requireFetchMetadata,
      blockAiCrawlers,
      antiCdp,
      allowDevTools,
      ...opts,
      ...(hasPresetOverride ? {} : { _preset: preset }),
    });
    if ((verdict.blocked || verdict.score > 0) && onDetect) {
      try {
        onDetect({ ...verdict, path: `${basePath}/handshake`, method: "POST" });
      } catch {}
    }
    return verdict;
  };
  return handle;
}

function decodeHtmlBodyAsync(rawBuf, contentEncoding, maxOutputLength = 5 * 1024 * 1024) {
  const enc = String(contentEncoding || "").trim().toLowerCase();
  if (!enc || enc === "identity") return Promise.resolve(rawBuf);
  const opts = { maxOutputLength };
  const fn =
    enc === "gzip"
      ? zlib.gunzip
      : enc === "deflate"
        ? zlib.inflate
        : enc === "br"
          ? zlib.brotliDecompress
          : null;
  if (!fn) return Promise.resolve(null);
  return new Promise((resolve) => {
    fn(rawBuf, opts, (err, out) => resolve(err ? null : out));
  });
}

function asciiLower(s) {
  const str = String(s);
  if (str.indexOf("\u0130") < 0 && str.indexOf("\u212A") < 0) return str.toLowerCase();
  return str.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

function findTagInsertIndex(html, tagName, lowHtml) {
  const low = lowHtml || asciiLower(html);
  const needle = `<${tagName}`;
  let idx = 0;
  let nextCommentStart = low.indexOf("<!--", 0);
  while (idx < low.length) {
    const pos = low.indexOf(needle, idx);
    if (pos < 0) return -1;
    while (nextCommentStart >= 0 && nextCommentStart < pos) {
      const cEnd = low.indexOf("-->", nextCommentStart + 4);
      if (cEnd < 0) return -1;
      if (cEnd > pos) {
        idx = cEnd + 3;
        nextCommentStart = low.indexOf("<!--", idx);
        break;
      }
      nextCommentStart = low.indexOf("<!--", cEnd + 3);
    }
    if (idx > pos) continue;
    const nextCh = low[pos + needle.length];
    if (nextCh === ">" || nextCh === " " || nextCh === "\t" || nextCh === "\r" || nextCh === "\n" || nextCh === "/") {
      const gt = low.indexOf(">", pos + needle.length);
      if (gt >= 0) return gt + 1;
      return -1;
    }
    idx = pos + needle.length;
  }
  return -1;
}

const GATE_SRC_RE_CACHE = new Map();
function hasGateScriptTag(html, low, baseSrc) {
  if (low && !low.includes(asciiLower(baseSrc))) return false;
  let entry = GATE_SRC_RE_CACHE.get(baseSrc);
  if (!entry) {
    if (GATE_SRC_RE_CACHE.size > 64) GATE_SRC_RE_CACHE.clear();
    const esc = escapeHtmlAttr(baseSrc).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    entry = {
      fastRe: new RegExp(esc, "i"),
      tagRe: new RegExp(`<script\\b[^<>]*\\bsrc=["']${esc}(?:\\?[^"']*)?["']`, "i"),
    };
    GATE_SRC_RE_CACHE.set(baseSrc, entry);
  }
  if (!low && !entry.fastRe.test(html)) return false;
  return entry.tagRe.test(html);
}

function injectGateIntoHtml(
  html,
  basePath,
  mode,
  autoBlockPage,
  antiCdp = true,
  { sri = "", version = "", unified = false, allowDevTools, bridgeToken = "" } = {}
) {
  const baseSrc = `${basePath}/gate.js`;
  const srcWithVer = version ? `${baseSrc}?v=${encodeURIComponent(version)}` : baseSrc;
  const safeSrc = escapeHtmlAttr(srcWithVer);
  const blockAttr = autoBlockPage === false ? "false" : "true";
  const cdpAttr = antiCdp === false ? ' data-anti-cdp="false"' : "";
  const devAttr = allowDevTools === true ? ' data-allow-devtools="true"' : "";
  const sriAttr = sri ? ` integrity="${escapeHtmlAttr(sri)}"` : "";
  const uniAttr = unified ? ' data-unified="true"' : "";
  const brAttr = bridgeToken ? ` data-vb-bridge="${escapeHtmlAttr(bridgeToken)}"` : "";
  const tag = `<script src="${safeSrc}"${sriAttr} data-mode="${escapeHtmlAttr(mode)}" data-block-page="${blockAttr}"${cdpAttr}${devAttr}${uniAttr}${brAttr}></script>`;
  if (hasGateScriptTag(html, null, baseSrc)) {
    return html;
  }
  // Fast-path 4KB -> 64KB -> full document using length-preserving asciiLower() (avoids 5MB stalls & U+0130 index shifts!)
  const tryInsertWithLower = (lowStr) => {
    const headAfter = findTagInsertIndex(html, "head", lowStr);
    if (headAfter >= 0) {
      // Keep <meta charset> at the top of <head> for HTML5 1024-byte charset prescan
      const metaMatch = /^(\s*<meta\b[^<>]*\bcharset\b[^<>]*>)/i.exec(html.slice(headAfter, headAfter + 256));
      const insertAt = metaMatch ? headAfter + metaMatch[0].length : headAfter;
      return `${html.slice(0, insertAt)}${tag}${html.slice(insertAt)}`;
    }
    const closeHead = lowStr.indexOf("</head>");
    if (closeHead >= 0) {
      return `${html.slice(0, closeHead)}${tag}${html.slice(closeHead)}`;
    }
    const bodyAfter = findTagInsertIndex(html, "body", lowStr);
    if (bodyAfter >= 0) {
      return `${html.slice(0, bodyAfter)}${tag}${html.slice(bodyAfter)}`;
    }
    return null;
  };
  const res4k = tryInsertWithLower(asciiLower(html.length > 4096 ? html.slice(0, 4096) : html));
  if (res4k !== null) return res4k;
  if (html.length > 4096) {
    const res64k = tryInsertWithLower(asciiLower(html.length > 65536 ? html.slice(0, 65536) : html));
    if (res64k !== null) return res64k;
  }
  if (html.length > 65536) {
    const resAll = tryInsertWithLower(asciiLower(html));
    if (resAll !== null) return resAll;
  }
  return `${tag}${html}`;
}

const STATIC_SUBRESOURCE_DESTS = new Set([
  "style", "image", "font", "script", "manifest", "audio", "video", "track", "worker", "serviceworker", "sharedworker",
]);
const EXTENSIONLESS_MEDIA_DESTS = new Set(["image", "font", "style", "audio", "video"]);
const STATIC_ASSET_EXT_RE = /\.(?:css|m?js|cjs|tsx?|jsx|vue|svelte|astro|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|webmanifest|wasm|mp4|webm|mp3|ogg|wav|vtt)$/i;
const VITE_DEV_PREFIX_RE = /(?:^|\/)@(?:vite|id|fs|react-refresh)(?:\/|$)/;
function inferStaticDest(headers, sfd, claimsModern) {
  if (sfd) return sfd;
  if (claimsModern) return "";
  const accept = String(headers?.accept || "").toLowerCase();
  if (!accept || accept.includes("text/html")) return "";
  if (accept.includes("image/")) return "image";
  if (accept.includes("text/css")) return "style";
  if (accept.includes("font/")) return "font";
  if (accept.includes("audio/")) return "audio";
  if (accept.includes("video/")) return "video";
  return "";
}

function isStaticSubresourceProbe(req, { blockAiCrawlers = true, fromTrustedProxy = false, pathname = "", requireFetchMeta = true, strictConnectionCheck = true } = {}) {
  if (req.method !== "GET" && req.method !== "HEAD") return false;
  const headers = req.headers || {};
  const ua = String(headers["user-agent"] || "");
  const cm = /Chrome\/(\d+)/i.exec(ua);
  const claimsModern = (cm && Number(cm[1]) >= 80) || (() => { const fm = /Firefox\/(\d+)/i.exec(ua); return Boolean(fm && Number(fm[1]) >= 90); })();
  const sfd = String(headers["sec-fetch-dest"] || "").trim().toLowerCase();
  const sfs = String(headers["sec-fetch-site"] || "").trim().toLowerCase();
  if (sfd || (claimsModern && requireFetchMeta)) {
    if (!STATIC_SUBRESOURCE_DESTS.has(sfd)) return false;
  }
  if (sfs && sfs !== "same-origin" && sfs !== "same-site" && sfs !== "none") return false;
  const p = pathname || normalizePathname(req.url || "/");
  // Allow extensionless same-origin/same-site media/font/style routes (e.g., Next.js /_next/image) including Safari < 16.4 via Accept inference,
  // because isAllowedStaticMime strictly binds upstream MIME to the exact dest!
  const effDest = inferStaticDest(headers, sfd, claimsModern);
  const allowExtensionlessMedia =
    EXTENSIONLESS_MEDIA_DESTS.has(effDest) && (!sfs || sfs === "same-origin" || sfs === "same-site");
  if (!STATIC_ASSET_EXT_RE.test(p) && !p.endsWith("/manifest.json") && !VITE_DEV_PREFIX_RE.test(p) && !allowExtensionlessMedia) {
    return false;
  }
  if (hasRequestBodyHeader(headers)) return false;
  if (hasDuplicateHostOrCl(req.rawHeaders)) return false;
  if (isAutomationOrCliUa(headers)) return false;
  if (blockAiCrawlers && isAiCrawlerRequest(headers)) return false;
  if (PROXY_LEAK_HEADERS.some((h) => headers[h] !== undefined)) return false;
  if (headers["x-original-url"] || headers["x-rewrite-url"]) return false;
  if (strictConnectionCheck && claimsModern && !fromTrustedProxy && String(headers["connection"] || "").trim().toLowerCase() === "close") return false;
  return true;
}

function isAllowedStaticMime(ct, pathname = "", sfd = "") {
  // On extensionless media/style/font routes (e.g. Next.js /_next/image), strictly bind upstream MIME to Sec-Fetch-Dest so JS/JSONP cannot leak under Sec-Fetch-Dest: image!
  const isExtMediaOnly =
    EXTENSIONLESS_MEDIA_DESTS.has(sfd) &&
    !STATIC_ASSET_EXT_RE.test(pathname) &&
    !pathname.endsWith("/manifest.json") &&
    !VITE_DEV_PREFIX_RE.test(pathname);
  if (isExtMediaOnly) {
    if (sfd === "image") return ct.startsWith("image/");
    if (sfd === "style") return ct.startsWith("text/css");
    if (sfd === "font") {
      return (
        ct.startsWith("font/") ||
        ct.startsWith("application/font") ||
        ct.startsWith("application/x-font-") ||
        ct.startsWith("application/vnd.ms-fontobject")
      );
    }
    if (sfd === "audio") return ct.startsWith("audio/");
    if (sfd === "video") return ct.startsWith("video/");
    return false;
  }
  return (
    ct.startsWith("text/css") ||
    ct.startsWith("image/") ||
    ct.startsWith("font/") ||
    ct.startsWith("audio/") ||
    ct.startsWith("video/") ||
    ct.startsWith("text/vtt") ||
    ct.startsWith("application/font") ||
    ct.startsWith("application/x-font-") ||
    ct.startsWith("application/vnd.ms-fontobject") ||
    ct.startsWith("application/wasm") ||
    ct.startsWith("application/javascript") ||
    ct.startsWith("application/x-javascript") ||
    ct.startsWith("text/javascript") ||
    ct.startsWith("application/manifest+json") ||
    ((!sfd || sfd === "manifest") && (pathname.endsWith("/manifest.json") || pathname.endsWith(".webmanifest")) && ct.startsWith("application/json"))
  );
}

function sanitizeForwardPathname(rawPath) {
  if (typeof rawPath === "string" && rawPath.length > 0 && rawPath !== "//" && CLEAN_ASCII_PATH_RE.test(rawPath)) {
    return rawPath;
  }
  let s = String(rawPath || "/").replace(/\\/g, "/");
  const nul = s.indexOf("\0");
  if (nul >= 0) s = s.slice(0, nul);
  const hash = s.indexOf("#");
  if (hash >= 0) s = s.slice(0, hash);
  if (!s.startsWith("/")) s = "/" + s;
  const hadTrailingSlash = s.length > 1 && s.endsWith("/");
  const out = [];
  for (const seg of s.split("/")) {
    if (!seg || seg === ".") continue;
    if (seg === "..") {
      if (out.length > 0) out.pop();
      continue;
    }
    // Preserve valid RFC 3986 pchar characters and existing %XX triplets (including %2F, %3F, %20) without double-encoding!
    const safeSeg = seg.replace(/[^A-Za-z0-9\-._~!$&'()*+,;=:@%]|%(?![0-9a-fA-F]{2})/g, (ch) => encodeURIComponent(ch));
    out.push(safeSeg);
  }
  const joined = "/" + out.join("/");
  return hadTrailingSlash && joined !== "/" ? `${joined}/` : joined;
}

function isSharedCacheDirective(headerVal) {
  const cc = String(headerVal || "").toLowerCase();
  if (!cc) return false;
  // RFC 9111 §5.2.2.4/§5.2.2.7: field-qualified private="..." / no-cache="..." still allow shared caching of the HTML body!
  if (/\b(?:no-store|(?:no-cache|private)(?!\s*=))\b/.test(cc)) return false;
  return /\b(?:public|s-maxage\s*=\s*[1-9]\d*|max-age\s*=\s*[1-9]\d*|stale-while-revalidate\s*=\s*[1-9]\d*|stale-if-error\s*=\s*[1-9]\d*)\b/.test(cc);
}

function classifyHtmlCaching(headersOrCc) {
  if (typeof headersOrCc === "string") {
    const isPublicCacheable = isSharedCacheDirective(headersOrCc);
    const cc = headersOrCc.toLowerCase();
    const isBrowserCached =
      !/\b(?:no-store|no-cache(?!\s*=))\b/.test(cc) &&
      /\b(?:max-age|s-maxage|stale-while-revalidate|stale-if-error)\s*=\s*[1-9]\d*\b/.test(cc);
    return { isPublicCacheable, isBrowserCached };
  }
  if (!headersOrCc || typeof headersOrCc !== "object") {
    return { isPublicCacheable: false, isBrowserCached: false };
  }
  let ccRaw = "";
  let expiresRaw = "";
  let isPublicCacheable = false;
  for (const k in headersOrCc) {
    if (!Object.prototype.hasOwnProperty.call(headersOrCc, k)) continue;
    const kl = k.toLowerCase();
    if (kl === "cache-control") ccRaw = String(headersOrCc[k] || "").toLowerCase();
    else if (kl === "expires") expiresRaw = String(headersOrCc[k] || "").trim();
    if (
      !isPublicCacheable &&
      (kl === "cache-control" ||
        kl === "surrogate-control" ||
        kl === "cdn-cache-control" ||
        kl.endsWith("-cdn-cache-control"))
    ) {
      if (isSharedCacheDirective(headersOrCc[k])) isPublicCacheable = true;
    }
  }
  const hasFutureExpires = Boolean(expiresRaw) && (() => {
    const expMs = Date.parse(expiresRaw);
    return Number.isFinite(expMs) && expMs > Date.now();
  })();
  if (!isPublicCacheable && hasFutureExpires && !/\b(?:no-store|(?:no-cache|private)(?!\s*=)|(?:s-maxage|max-age)\s*=\s*0)\b/.test(ccRaw)) {
    isPublicCacheable = true;
  }
  const isBrowserCached =
    !/\b(?:no-store|no-cache(?!\s*=))\b/.test(ccRaw) &&
    (/\b(?:max-age|s-maxage|stale-while-revalidate|stale-if-error)\s*=\s*[1-9]\d*\b/.test(ccRaw) ||
      (hasFutureExpires && !/\bmax-age\s*=\s*0\b/.test(ccRaw)));
  return { isPublicCacheable, isBrowserCached };
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
  const trustedProxies = middleware._trustedProxies || compileTrustedProxies(options.trustProxy);
  const clientMod = targetUrl.protocol === "https:" ? https : http;
  const baseTargetPath = targetUrl.pathname && targetUrl.pathname !== "/" ? targetUrl.pathname.replace(/\/+$/, "") : "";

  const sriOnPublicCache = Boolean(options.sriOnPublicCache);
  const effectivePaths = normalizeProtectedPaths(options.protectedPaths);
  const rootProtected = isProtectedPath("/", effectivePaths, true);
  const exposeDebugHeaders = options.exposeDebugHeaders !== false;

  const server = http.createServer((req, res) => {
    let htmlBootstrapProbe = false;
    let staticAssetProbe = false;
    let cachedReqNormPath = "";
    if (
      rootProtected &&
      mode !== "off" &&
      mode !== "monitor" &&
      (req.method === "GET" || req.method === "HEAD") &&
      !req.headers?.["x-vb-ticket"] &&
      !req.headers?.["x-vb-attest"]
    ) {
      const rawUrl = req.url || "/";
      const qIdx = rawUrl.indexOf("?");
      const rawPathOnly = qIdx >= 0 ? rawUrl.slice(0, qIdx) : rawUrl;
      let reqNormPath;
      if (CLEAN_ASCII_PATH_RE.test(rawPathOnly)) {
        middleware._setCleanRawPath(req, rawPathOnly);
        reqNormPath = rawPathOnly.length > 1 && rawPathOnly.endsWith("/") ? rawPathOnly.slice(0, -1) : rawPathOnly || "/";
      } else {
        reqNormPath = normalizePathname(rawUrl);
      }
      cachedReqNormPath = reqNormPath;
      middleware._setPrePath(req, reqNormPath);
      if (!reqNormPath.startsWith(`${basePath}/`)) {
        const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
        const fromTp = Boolean(remoteRaw && trustedProxies.size > 0 && trustedProxies.has(remoteRaw));
        const reqFetchMeta =
          middleware.preset.requireFetchMetadata &&
          (options.requireFetchMetadata === true || isTrustworthyOriginRequest(req, fromTp));
        htmlBootstrapProbe = isHtmlBootstrapNavigation(req, {
          blockAiCrawlers: middleware.preset.blockAiCrawlers,
          fromTrustedProxy: fromTp,
          requireFetchMeta: reqFetchMeta,
          strictConnectionCheck: mode !== "balanced",
        });
        if (!htmlBootstrapProbe) {
          staticAssetProbe = isStaticSubresourceProbe(req, {
            blockAiCrawlers: middleware.preset.blockAiCrawlers,
            fromTrustedProxy: fromTp,
            pathname: reqNormPath,
            requireFetchMeta: reqFetchMeta,
            strictConnectionCheck: mode !== "balanced",
          });
        }
      }
    }

    const middlewareStep = (htmlBootstrapProbe || staticAssetProbe) ? Promise.resolve(false) : Promise.resolve(middleware(req, res));

    middlewareStep
      .then((handled) => {
        if (handled) return;
        if (res.destroyed || res.closed || res.writableEnded || req.aborted || (req.destroyed && !req.complete)) return;

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
        const preCleanRaw = middleware._getCleanRawPath(req);
        const safeFwdPath = preCleanRaw && rawFwd === preCleanRaw && rawFwd !== "//" ? rawFwd : sanitizeForwardPathname(rawFwd);
        let fwdPath = `${safeFwdPath}${safeSearch}`;
        if (baseTargetPath) fwdPath = `${baseTargetPath}${fwdPath}`;

        const fwdHeaders = stripHopByHop(req.headers, { isRequest: true });
        delete fwdHeaders["x-original-url"];
        delete fwdHeaders["x-rewrite-url"];
        delete fwdHeaders["x-http-method-override"];
        delete fwdHeaders["x-method-override"];
        delete fwdHeaders["x-http-method"];
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
        if (htmlBootstrapProbe || staticAssetProbe) {
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
            const mimeEssence = ct.split(";", 1)[0].trim();
            const isHtmlMime = mimeEssence === "text/html";
            const reqSfdRaw = String(req.headers["sec-fetch-dest"] || "").trim().toLowerCase();
            const reqUaStatic = staticAssetProbe && !reqSfdRaw ? String(req.headers["user-agent"] || "") : "";
            const reqSfd = staticAssetProbe
              ? (() => {
                  if (reqSfdRaw) return reqSfdRaw;
                  const cmS = /Chrome\/(\d+)/i.exec(reqUaStatic);
                  const fmS = !cmS ? /Firefox\/(\d+)/i.exec(reqUaStatic) : null;
                  const modernS = Boolean((cmS && Number(cmS[1]) >= 80) || (fmS && Number(fmS[1]) >= 90));
                  return inferStaticDest(req.headers, reqSfdRaw, modernS);
                })()
              : reqSfdRaw;
            const reqPathForMime = staticAssetProbe ? (cachedReqNormPath || normalizePathname(req.url || "/")) : "";

            // For wildcard HTML-bootstrap & static-subresource probes, strictly verify upstream MIME essence before leaking any body bytes!
            if ((htmlBootstrapProbe && !isHtmlMime) || (staticAssetProbe && !isAllowedStaticMime(ct, reqPathForMime, reqSfd))) {
              if ((htmlBootstrapProbe || staticAssetProbe) && statusCode >= 301 && statusCode <= 308 && statusCode !== 304 && Boolean(upRes.headers["location"])) {
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
                    threshold: middleware.preset.threshold,
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
              Boolean(String(req.headers["access-control-request-method"] || "").trim()) &&
              !req.veilBreak &&
              mode !== "off" &&
              mode !== "monitor" &&
              isProtectedPath(req.url || "/", effectivePaths, true) &&
              !upRes.headers["access-control-allow-origin"]
            ) {
              responded = true;
              if (typeof options.onDetect === "function") {
                try {
                  options.onDetect({
                    ok: false,
                    blocked: true,
                    score: 6,
                    threshold: middleware.preset.threshold,
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

            if (injectGate && canHaveBody && isHtmlMime) {
              const chunks = [];
              let totalBytes = 0;
              let overflowed = false;
              const onData = (c) => {
                totalBytes += c.length;
                if (totalBytes > maxHtmlBytes) {
                  overflowed = true;
                  upRes.removeListener("data", onData);
                  upRes.removeListener("end", onEnd);
                  if (responded || res.headersSent || res.writableEnded) {
                    chunks.length = 0;
                    return;
                  }
                  responded = true;
                  res.writeHead(statusCode, outHeaders);
                  for (const prev of chunks) res.write(prev);
                  chunks.length = 0;
                  res.write(c);
                  upRes.pipe(res);
                  return;
                }
                chunks.push(c);
              };
              const onEnd = async () => {
                try {
                  if (overflowed || responded || res.headersSent || res.writableEnded) return;
                  const rawBuf = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, totalBytes);
                  chunks.length = 0;
                  const ce = outHeaders["content-encoding"];
                  let decoded = rawBuf;
                  if (ce) {
                    const maybe = await decodeHtmlBodyAsync(rawBuf, ce, maxHtmlBytes);
                    if (overflowed || responded || res.headersSent || res.writableEnded) return;
                    if (!maybe) {
                      responded = true;
                      res.writeHead(statusCode, outHeaders);
                      res.end(rawBuf);
                      return;
                    }
                    decoded = maybe;
                    delete outHeaders["content-encoding"];
                  }
                  if (overflowed || responded || res.headersSent || res.writableEnded) return;
                  const htmlStr = decoded.toString("utf8");
                  const isFullHtmlDoc = /<(?:!doctype\s+html|html|head|body)\b/i.test(htmlStr.slice(0, 4096));
                  if (!isFullHtmlDoc) {
                    responded = true;
                    outHeaders["content-length"] = String(decoded.length);
                    res.writeHead(statusCode, outHeaders);
                    res.end(decoded);
                    return;
                  }
                  const { isPublicCacheable, isBrowserCached } = classifyHtmlCaching(outHeaders);
                  // Avoid pinning SRI into public CDN-cacheable HTML (which would break across upgrades/config changes) unless opted in!
                  const useSri = middleware.preset.sri && (!isPublicCacheable || sriOnPublicCache);
                  const html = injectGateIntoHtml(
                    htmlStr,
                    basePath,
                    mode,
                    middleware.preset.autoBlockPage,
                    middleware.preset.antiCdp,
                    {
                      sri: useSri ? middleware.gateSri : "",
                      version: useSri ? middleware.gateVersion : "",
                      allowDevTools: middleware.preset.allowDevTools,
                    }
                  );
                  const htmlModified = html !== htmlStr;
                  const buf = htmlModified ? Buffer.from(html, "utf8") : decoded;
                  outHeaders["content-length"] = String(buf.length);
                  if (htmlModified) {
                    if (useSri && isBrowserCached && !isPublicCacheable) {
                      outHeaders["cache-control"] = "private, no-cache";
                      delete outHeaders["expires"];
                    }
                    delete outHeaders["etag"];
                    delete outHeaders["last-modified"];
                  }
                  responded = true;
                  res.writeHead(statusCode, outHeaders);
                  res.end(buf);
                } catch (_) {
                  if (!responded && !res.headersSent && !res.writableEnded) {
                    responded = true;
                    sendJson(res, 502, { ok: false, error: "UPSTREAM_DECODE_ERROR" });
                  }
                }
              };
              upRes.on("data", onData);
              upRes.on("end", onEnd);
              return;
            }
            responded = true;
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

module.exports = { createVeilBreakMiddleware, createVeilBreakServer, injectGateIntoHtml, normalizePathname };
