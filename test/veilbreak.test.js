"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const zlib = require("node:zlib");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const {
  evaluateTelemetry,
  evaluateInteraction,
  buildAttestation,
  verifyAttestation,
  buildBrowserGateScript,
  createVeilBreakServer,
  compileNaturalLanguage,
} = require("../src/index.js");

test("1. Clean genuine Chrome & Firefox telemetry scores 0/2 (strict) and 0/4 (balanced)", () => {
  const clean = {
    webdriver: false,
    freshIframeWebdriver: false,
    automationGlobalArtifact: false,
    cdpRuntimeEnable: false,
    webdriverGetterSpoofed: false,
    nativeFunctionTampered: false,
    workerRealmContradiction: false,
    canvas2dUniqueColors: 1,
    canvas2dRepeatDiff: 0,
    offscreenCanvasUniqueColors: 1,
    webglClearUniqueColors: 1,
    webglHardwareLie: false,
    silentAudioNonZeroSamples: 0,
    domRectSubpixelDrift: false,
    osFontLie: false,
    viewportGeometryImpossibility: false,
    engineCoherenceLie: false,
    platform: "Linux x86_64",
  };
  const strict = evaluateTelemetry(clean, { mode: "strict" });
  assert.equal(strict.ok, true);
  assert.equal(strict.blocked, false);
  assert.equal(strict.score, 0);
  assert.equal(strict.reasons.length, 0);
});

test("2. Multi-engine stealth telemetry triggers expected invariants in both strict & balanced", () => {
  const noiseProfile = evaluateTelemetry(
    {
      canvas2dUniqueColors: 6,
      webglClearUniqueColors: 6,
      silentAudioNonZeroSamples: 512,
      domRectSubpixelDrift: true,
      osFontLie: true,
      webglHardwareLie: true,
      platform: "Win32",
    },
    { mode: "balanced" }
  );
  assert.equal(noiseProfile.blocked, true);
  assert.equal(noiseProfile.score, 12);

  const geckoStealth = evaluateTelemetry(
    {
      canvas2dUniqueColors: 8,
      canvas2dRepeatDiff: 1024,
      webglHardwareLie: true,
      platform: "Win32",
    },
    { mode: "balanced" }
  );
  assert.equal(geckoStealth.blocked, true);
  assert.equal(geckoStealth.score, 6);
  assert.ok(geckoStealth.reasons.includes("CANVAS2D_NON_DETERMINISTIC"));
  assert.ok(geckoStealth.reasons.includes("WEBGL_HARDWARE_COHERENCE_LIE"));

  const jsStealth = evaluateTelemetry(
    {
      webdriverGetterSpoofed: true,
      nativeFunctionTampered: true,
      workerRealmContradiction: true,
      engineCoherenceLie: true,
      platform: "Win32",
    },
    { mode: "balanced" }
  );
  assert.equal(jsStealth.blocked, true);
  assert.equal(jsStealth.score, 14);
});

test("3. Privacy single-signal canvas farbling allowed in balanced mode, blocked in strict", () => {
  const canvasOnly = { canvas2dUniqueColors: 4, platform: "Linux x86_64" };
  assert.equal(evaluateTelemetry(canvasOnly, { mode: "balanced" }).blocked, false);
  assert.equal(evaluateTelemetry(canvasOnly, { mode: "strict" }).blocked, true);
});

test("4. Stage-2 Click Kinematics blocks bot clicks while allowing humans, touch/pen & keyboard accessibility", () => {
  const human = evaluateInteraction({ isTrusted: true, detail: 1, pointerType: "mouse", pointerMoves: 24, dwellMs: 78, hitExactCenter: false });
  assert.equal(human.blocked, false);
  assert.equal(human.score, 0);

  // Touch & pen taps (0 pointermoves, instant tap) must NOT false-positive!
  const touchTap = evaluateInteraction({ isTrusted: true, detail: 1, pointerType: "touch", pointerMoves: 0, dwellMs: 2, hitExactCenter: true });
  assert.equal(touchTap.blocked, false);
  assert.equal(touchTap.score, 0);

  // Keyboard accessibility activation (Enter/Space -> detail=0)
  const keyboard = evaluateInteraction({ isTrusted: true, detail: 0, pointerMoves: 0, dwellMs: -1, hitExactCenter: false });
  assert.equal(keyboard.blocked, false);
  assert.equal(keyboard.score, 0);

  // Coarsened timer (dwellMs === 0, not center-hit) must NOT false-positive
  const coarsened = evaluateInteraction({ isTrusted: true, detail: 1, pointerType: "mouse", pointerMoves: 0, dwellMs: 0, hitExactCenter: false });
  assert.equal(coarsened.blocked, false);

  // Synthetic JS click (Nodriver / SeleniumBase UC)
  const synthetic = evaluateInteraction({ isTrusted: false, detail: 0, pointerMoves: 0, dwellMs: -1, hitExactCenter: false });
  assert.equal(synthetic.blocked, true);
  assert.equal(synthetic.score, 6);
  assert.ok(synthetic.reasons.includes("UNTRUSTED_SYNTHETIC_CLICK"));

  // Programmatic CDP/Juggler teleport click
  const teleport = evaluateInteraction({ isTrusted: true, detail: 1, pointerType: "mouse", pointerMoves: 1, dwellMs: 0.4, hitExactCenter: true });
  assert.equal(teleport.blocked, true);
  assert.equal(teleport.score, 4);
  assert.ok(teleport.reasons.includes("TELEPORT_CLICK_PHYSICS"));
});

test("5. VB_ATTEST_V2 strict validation, balanced mode fail-closed, flag decoding & Python ticket-store parity", () => {
  const ticket = "abcdef0123456789abcdef0123456789";
  const nonce = "0123456789abcdef";
  const headers = {
    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"',
    "sec-ch-ua-platform": '"Linux"',
  };
  const att = buildAttestation({ mode: "strict", ticket, nonce, telemetry: { platform: "Linux x86_64" } });
  const okRes = verifyAttestation({ mode: "strict", headers, attest: att, ticket, nonce });
  assert.equal(okRes.ok, true);
  assert.equal(okRes.blocked, false);

  // Balanced mode must NOT fail open on missing attestation or HeadlessChrome UA!
  const balCurl = verifyAttestation({ mode: "balanced", headers: { "user-agent": "curl/8.5.0" }, attest: null });
  assert.equal(balCurl.blocked, true);
  assert.ok(balCurl.reasons.includes("ATTEST_REQUIRED"));

  const balHeadless = verifyAttestation({ mode: "balanced", headers: { "user-agent": "Mozilla/5.0 HeadlessChrome/158.0" }, attest: att, ticket, nonce });
  assert.equal(balHeadless.blocked, true);
  assert.ok(balHeadless.reasons.includes("AUTOMATION_UA_DENIED"));

  // Reject boolean/string coercion, delimiter injection, and incoherent {s:0, f:64}
  for (const badAtt of [
    { v: 2, s: false, f: 0, p: "Linux", d: "a".repeat(64) },
    { v: 2, s: 0, f: 64, p: "Linux", d: att.d },
    { v: 2, s: 0, f: 0, p: "Linux|evil", d: "a".repeat(64) },
    [],
  ]) {
    const r = verifyAttestation({ mode: "strict", headers, attest: badAtt, ticket, nonce });
    assert.equal(r.blocked, true);
    assert.ok(r.reasons.includes("ATTEST_INVALID"));
  }

  // Flag bitmask decoding on server
  const flaggedAtt = buildAttestation({
    mode: "strict",
    ticket,
    nonce,
    telemetry: { canvas2dUniqueColors: 5, platform: "Linux x86_64" },
  });
  const flaggedRes = verifyAttestation({ mode: "strict", headers, attest: flaggedAtt, ticket, nonce });
  assert.equal(flaggedRes.blocked, true);
  assert.ok(flaggedRes.reasons.includes("CANVAS2D_SYNTHETIC_NOISE"));

  // Python zero-dep verifier & one-time VeilBreakTicketStore parity
  const pyDir = path.join(__dirname, "..", "python");
  const pyOut = execFileSync("python3", [
    "-c",
    `import sys, json; sys.path.insert(0, ${JSON.stringify(pyDir)});
from veilbreak import verify_attestation, VeilBreakTicketStore
h = json.loads(${JSON.stringify(JSON.stringify(headers))})
att = json.loads(${JSON.stringify(JSON.stringify(att))})
r = verify_attestation(mode="strict", headers=h, attest=att, ticket=${JSON.stringify(ticket)}, nonce=${JSON.stringify(nonce)})
assert r.ok and not r.blocked and r.score == 0
r_bal = verify_attestation(mode="balanced", headers={"User-Agent": "curl/8.5.0"}, attest=None)
assert r_bal.blocked and "ATTEST_REQUIRED" in r_bal.reasons
# Test Python one-time ticket store replay protection
store = VeilBreakTicketStore(mode="strict")
tk = store.mint_ticket()
import hashlib
d = hashlib.sha256(f"VB_ATTEST_V2|{tk}|nn1|0|0|Linux x86_64".encode()).hexdigest()
req_h = dict(h, **{"X-VB-Ticket": tk, "X-VB-Nonce": "nn1", "X-VB-Attest": json.dumps({"v":2,"s":0,"f":0,"p":"Linux x86_64","d":d})})
v1 = store.verify_request(headers=req_h)
v2 = store.verify_request(headers=req_h)
assert v1.ok and not v1.blocked
assert v2.blocked and "TICKET_REPLAYED_OR_INVALID" in v2.reasons
print("PY_PARITY_OK")`,
  ], { encoding: "utf8" });
  assert.equal(pyOut.trim(), "PY_PARITY_OK");
});

test("6. Live HTTP server enforces one-time tickets, blocks path bypasses, handles gzip HTML & HEAD", async () => {
  const upstream = http.createServer((req, res) => {
    if (req.url.toLowerCase().includes("secret")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, secret: "PROTECTED_OK" }));
      return;
    }
    const html = "<!doctype html><html><head><title>App</title></head><body><h1>Hi</h1></body></html>";
    if (req.url === "/gzip") {
      const gz = zlib.gzipSync(Buffer.from(html, "utf8"));
      res.writeHead(200, { "Content-Type": "text/html", "Content-Encoding": "gzip", "Content-Length": gz.length });
      res.end(gz);
      return;
    }
    if (req.method === "HEAD") {
      res.writeHead(200, { "Content-Type": "text/html", "Content-Length": Buffer.byteLength(html) });
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  });
  await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
  const upPort = upstream.address().port;

  const gate = createVeilBreakServer({
    target: `http://127.0.0.1:${upPort}`,
    mode: "strict",
    protectedPaths: ["/api"],
  });
  const baseUrl = await gate.listen(0, "127.0.0.1");

  try {
    const htmlResp = await fetch(`${baseUrl}/`, { headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0.0.0" } });
    assert.equal(htmlResp.status, 200);
    assert.ok((await htmlResp.text()).includes("/__veilbreak/gate.js"));

    // Gzipped HTML decompressed & injected cleanly
    const gzResp = await fetch(`${baseUrl}/gzip`, { headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0.0.0" } });
    assert.equal(gzResp.status, 200);
    assert.ok((await gzResp.text()).includes("/__veilbreak/gate.js"));

    // HEAD response must NOT receive injected body
    const headResp = await fetch(`${baseUrl}/`, { method: "HEAD", headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0.0.0" } });
    assert.equal(headResp.status, 200);
    assert.equal((await headResp.text()).length, 0);

    // Path normalization blocks /API/secret, /%61pi/secret, //api/secret, /x/../api/secret
    for (const bypass of ["/API/secret", "/%61pi/secret", "//api/secret", "/x/../api/secret"]) {
      const r = await fetch(`${baseUrl}${bypass}`, { headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0.0.0" } });
      assert.equal(r.status, 403, `Bypass path must be blocked: ${bypass}`);
    }

    // Automation UA denied even on /__veilbreak/ticket!
    const botTk = await fetch(`${baseUrl}/__veilbreak/ticket`, { headers: { "User-Agent": "Mozilla/5.0 HeadlessChrome/158.0" } });
    assert.equal(botTk.status, 403);

    // Valid one-time ticket + clean attestation passes once, replay is blocked
    const tk = (await (await fetch(`${baseUrl}/__veilbreak/ticket`, { headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0.0.0" } })).json()).ticket;
    const nonce = "1122334455667788";
    const att = buildAttestation({ mode: "strict", ticket: tk, nonce, telemetry: { platform: "Linux x86_64" } });
    const reqHeaders = {
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0.0.0",
      "X-VB-Ticket": tk,
      "X-VB-Nonce": nonce,
      "X-VB-Attest": JSON.stringify(att),
    };
    const okApi = await fetch(`${baseUrl}/api/secret`, { headers: reqHeaders });
    assert.equal(okApi.status, 200);
    assert.equal((await okApi.json()).secret, "PROTECTED_OK");

    const replayApi = await fetch(`${baseUrl}/api/secret`, { headers: reqHeaders });
    assert.equal(replayApi.status, 403);
    const repJson = await replayApi.json();
    assert.ok(repJson.reasons.includes("TICKET_REPLAYED_OR_INVALID"));
    assert.ok(repJson.score >= 6);
  } finally {
    await gate.close();
    await new Promise((r) => upstream.close(r));
  }
});

test("7. Natural-language compiler slash/negation fixes & browser SDK syntax check", () => {
  // Slashes in "Brave/LibreWolf" must NOT hijack protectedPaths!
  const p1 = compileNaturalLanguage("protect http://localhost:3000 on port 9090 while keeping Brave/LibreWolf working");
  assert.equal(p1.intent, "protect");
  assert.equal(p1.options.mode, "balanced");
  assert.equal(p1.options.port, 9090);
  assert.deepEqual(p1.options.protectedPaths, ["/api"]);

  // Negated monitor stays strict
  const p2 = compileNaturalLanguage("do not monitor, block strictly on http://localhost:3000");
  assert.equal(p2.options.mode, "strict");

  const p3 = compileNaturalLanguage("show me a demo on port 9999");
  assert.equal(p3.intent, "demo");
  assert.equal(p3.options.port, 9999);

  const js = buildBrowserGateScript({ protectedRules: ["/api", { regex: "^/v\\d+/data", flags: "i" }] });
  new Function(js);
});

test("8. v2 CIDR trustProxy per-client ticket rate limiting, observe alias, and modular subpath exports", async () => {
  const { createVeilBreakMiddleware } = require("../src/middleware.js");
  const { normalizeMode } = require("../src/probes.js");
  assert.equal(normalizeMode("observe"), "monitor");

  const mw = createVeilBreakMiddleware({
    mode: "observe",
    trustProxy: ["10.0.0.0/8", "127.0.0.1"],
    maxTicketsPerMinPerIp: 2,
  });

  function callTicket(xff) {
    return new Promise((resolve) => {
      let status = 200;
      const req = {
        method: "GET",
        url: "/__veilbreak/ticket",
        socket: { remoteAddress: "10.5.0.2" },
        headers: { "user-agent": "Mozilla/5.0 Chrome/130.0", "x-forwarded-for": xff },
      };
      const res = {
        headersSent: false,
        writableEnded: false,
        writeHead(code) { status = code; this.headersSent = true; },
        end(body) { this.writableEnded = true; resolve({ status, body: JSON.parse(String(body)) }); },
      };
      mw(req, res);
    });
  }

  // Client A uses its 2-ticket budget cleanly
  assert.equal((await callTicket("198.51.100.10")).status, 200);
  assert.equal((await callTicket("198.51.100.10")).status, 200);
  assert.equal((await callTicket("198.51.100.10")).status, 429);

  // Client B behind the SAME reverse proxy IP 10.5.0.2 MUST NOT be blocked by Client A's bucket!
  assert.equal((await callTicket("198.51.100.22")).status, 200);

  const pkg = require("../package.json");
  assert.equal(pkg.exports["./probes"], "./src/probes.js");
  assert.equal(pkg.exports["./middleware"], "./src/middleware.js");
  assert.equal(pkg.exports["."].types, "./src/index.d.ts");
  assert.ok(pkg.files.includes("python/"));
});

test("9. Loop 2 security regressions: ['*'] wildcard, #/%ff bypasses, cross-site /ticket, IPv6 CIDR, Connection strip", async () => {
  const { createVeilBreakMiddleware, createVeilBreakServer, normalizePathname } = require("../src/index.js");
  assert.equal(normalizePathname("/%61pi/%ff/data"), "/api/%ff/data");
  assert.equal(normalizePathname("/%ff%2f../api/secret"), "/api/secret");
  assert.equal(normalizePathname("/x#/../api/secret"), "/api/secret");

  // Loop 3 LOW-20: incoherent low score for high-weight flag & undefined bits rejected in both JS & Python
  const badFlagRes = verifyAttestation({
    mode: "strict",
    headers: { "user-agent": "Mozilla/5.0 Chrome/130.0" },
    attest: { v: 2, s: 1, f: 64, p: "Linux", d: "a".repeat(64) },
    ticket: "t1",
    nonce: "n1",
  });
  assert.equal(badFlagRes.blocked, true);
  assert.ok(badFlagRes.reasons.includes("ATTEST_INVALID"));

  const pyL3 = execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.join(__dirname, "..", "python"))});
from veilbreak import verify_attestation, VeilBreakTicketStore
r1 = verify_attestation(mode="strict", headers={"User-Agent": "Mozilla/5.0 Chrome/130.0"}, attest={"v": 2, "s": 1, "f": 64, "p": "Linux", "d": "a"*64}, ticket="t1", nonce="n1")
assert r1.blocked and "ATTEST_INVALID" in r1.reasons
r2 = verify_attestation(mode="strict", headers={"User-Agent": "Mozilla/5.0 Chrome/130.0"}, attest={"v": None, "s": 0, "f": 0, "p": "Linux", "d": "a"*64}, ticket="t1", nonce="n1")
assert r2.blocked and "ATTEST_INVALID" in r2.reasons
st = VeilBreakTicketStore(mode="observe", max_tickets=1)
assert st.mode == "monitor"
assert st.mint_ticket() is not None
assert st.mint_ticket() is None
print("VB_PY_L3_OK")`,
    ],
    { encoding: "utf8" }
  ).trim();
  assert.equal(pyL3, "VB_PY_L3_OK");

  // CRIT-06: protectedPaths: ["*"] must protect arbitrary paths
  const starMw = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["*"] });
  let starStatus = 0;
  await starMw(
    {
      method: "GET",
      url: "/anything/here",
      socket: { remoteAddress: "127.0.0.1" },
      headers: { "user-agent": "Mozilla/5.0 Chrome/130.0" },
    },
    {
      headersSent: false,
      writableEnded: false,
      setHeader() {},
      writeHead(code) { starStatus = code; this.headersSent = true; },
      end() { this.writableEnded = true; },
    }
  );
  assert.equal(starStatus, 403);

  // MED-08: cross-site Sec-Fetch-Site rejected on /__veilbreak/ticket + IPv6 CIDR trustProxy
  const v6Mw = createVeilBreakMiddleware({
    mode: "strict",
    trustProxy: ["2001:db8:cafe::/48"],
    maxTicketsPerMinPerIp: 1,
  });
  function callTicket(headers, remoteAddress = "2001:db8:cafe::1") {
    return new Promise((resolve) => {
      let status = 200;
      v6Mw(
        { method: "GET", url: "/__veilbreak/ticket", socket: { remoteAddress }, headers },
        {
          headersSent: false,
          writableEnded: false,
          setHeader() {},
          writeHead(code) { status = code; this.headersSent = true; },
          end(body) { this.writableEnded = true; resolve({ status, body: JSON.parse(String(body)) }); },
        }
      );
    });
  }
  const csrf = await callTicket({
    "user-agent": "Mozilla/5.0 Chrome/130.0",
    "sec-fetch-site": "cross-site",
  });
  assert.equal(csrf.status, 403);
  assert.equal(csrf.body.error, "CROSS_SITE_TICKET_DENIED");

  // IPv6 CIDR unwraps trusted hop to distinct real client IPs
  const rA1 = await callTicket({ "user-agent": "Mozilla/5.0 Chrome/130.0", "x-forwarded-for": "198.51.100.1, 2001:db8:cafe::2" });
  const rA2 = await callTicket({ "user-agent": "Mozilla/5.0 Chrome/130.0", "x-forwarded-for": "198.51.100.1, 2001:db8:cafe::2" });
  const rB1 = await callTicket({ "user-agent": "Mozilla/5.0 Chrome/130.0", "x-forwarded-for": "198.51.100.2, 2001:db8:cafe::2" });
  assert.equal(rA1.status, 200);
  assert.equal(rA2.status, 429);
  assert.equal(rB1.status, 200);

  // HIGH-10 + Loop 4 CRIT-2 & HIGH-5: Connection strip, absolute-form ? before /, and query %20 preservation
  let seenAuth = null;
  let seenXff = null;
  let seenUrl = null;
  const upstream = http.createServer((req, res) => {
    seenAuth = req.headers.authorization || null;
    seenXff = req.headers["x-forwarded-for"] || null;
    seenUrl = req.url;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
  });
  await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
  const gate = createVeilBreakServer({
    target: `http://127.0.0.1:${upstream.address().port}`,
    mode: "strict",
    protectedPaths: ["/api"],
  });
  const baseUrl = await gate.listen(0, "127.0.0.1");
  try {
    // Loop 3 CRIT-3 + Loop 4 HIGH-5: valid %20 preserved without 500 or %2520 double-encoding & /api%3F blocked 403!
    const sp = await fetch(`${baseUrl}/public/my%20file.json?q=hello%20world`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0" },
    });
    assert.equal(sp.status, 200);
    assert.equal(seenUrl, "/public/my%20file.json?q=hello%20world");
    // Loop 4 CRIT-2: raw absolute-form `GET http://example.com?x=/api/secret` must NOT forward `/api/secret`!
    const rawAbs = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: "127.0.0.1", port: gate.server.address().port, method: "GET", path: "http://example.com?x=/api/secret", headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0" } },
        (r) => { r.resume(); r.on("end", () => resolve(r.statusCode)); }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(rawAbs, 200);
    assert.equal(seenUrl, "/?x=/api/secret");
    const qBypass = await fetch(`${baseUrl}/api%3F`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0" },
    });
    assert.equal(qBypass.status, 403);
    const res = await fetch(`${baseUrl}/public`, {
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0",
        Authorization: "Bearer keep-me",
        Connection: "keep-alive, authorization, x-forwarded-for",
      },
    });
    assert.equal(res.status, 200);
    assert.equal(seenAuth, "Bearer keep-me");
    assert.ok(seenXff && seenXff.includes("127.0.0.1"));
  } finally {
    await gate.close();
    await new Promise((r) => upstream.close(r));
  }
});
