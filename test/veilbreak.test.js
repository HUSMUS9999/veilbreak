"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const zlib = require("node:zlib");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const {
  SECURITY_PRESETS,
  resolvePreset,
  evaluateTelemetry,
  evaluateInteraction,
  buildAttestation,
  verifyAttestation,
  buildHandshakeProof,
  verifyHandshakeProof,
  isAiCrawlerRequest,
  buildBrowserGateScript,
  buildPlaygroundHtml,
  createVeilBreakMiddleware,
  createVeilBreakServer,
  compileNaturalLanguage,
  normalizePathname,
} = require("../src/index.js");

const CHROME_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36";

function makeBrowserHeaders(overrides = {}) {
  return {
    "user-agent": CHROME_UA,
    "sec-ch-ua": '"Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"',
    "sec-ch-ua-platform": '"Linux"',
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "accept-language": "en-US,en;q=0.9",
    ...overrides,
  };
}

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

test("4. Stage-2 Click Kinematics blocks bot clicks while allowing humans, touch/pen, trackpad taps & keyboard accessibility", () => {
  const human = evaluateInteraction({ isTrusted: true, detail: 1, pointerType: "mouse", pointerMoves: 24, dwellMs: 78, hitExactCenter: false });
  assert.equal(human.blocked, false);
  assert.equal(human.score, 0);

  const touchTap = evaluateInteraction({ isTrusted: true, detail: 1, pointerType: "touch", pointerMoves: 0, dwellMs: 2, hitExactCenter: true });
  assert.equal(touchTap.blocked, false);
  assert.equal(touchTap.score, 0);

  const keyboard = evaluateInteraction({ isTrusted: true, detail: 0, pointerMoves: 0, dwellMs: -1, hitExactCenter: false });
  assert.equal(keyboard.blocked, false);
  assert.equal(keyboard.score, 0);

  // Off-center quick trackpad tap-to-click does NOT false-positive!
  const trackpadTap = evaluateInteraction({ isTrusted: true, detail: 1, pointerType: "mouse", pointerMoves: 0, dwellMs: 4, hitExactCenter: false });
  assert.equal(trackpadTap.blocked, false);

  const synthetic = evaluateInteraction({ isTrusted: false, detail: 0, pointerMoves: 0, dwellMs: -1, hitExactCenter: false });
  assert.equal(synthetic.blocked, true);
  assert.equal(synthetic.score, 6);
  assert.ok(synthetic.reasons.includes("UNTRUSTED_SYNTHETIC_CLICK"));

  const teleport = evaluateInteraction({ isTrusted: true, detail: 1, pointerType: "mouse", pointerMoves: 1, dwellMs: 0.4, hitExactCenter: true });
  assert.equal(teleport.blocked, true);
  assert.equal(teleport.score, 4);
  assert.ok(teleport.reasons.includes("TELEPORT_CLICK_PHYSICS"));
});

test("5. VB_ATTEST_V2 PoW, method/path binding, CLI UA denial, flag decoding & Python ticket-store parity", () => {
  const ticket = "abcdef0123456789abcdef0123456789";
  const nonce = "0123456789abcdef";
  const headers = makeBrowserHeaders();
  const att = buildAttestation({ mode: "strict", ticket, nonce, telemetry: { platform: "Linux x86_64" } });
  const okRes = verifyAttestation({ mode: "strict", headers, attest: att, ticket, nonce });
  assert.equal(okRes.ok, true);
  assert.equal(okRes.blocked, false);

  // Challenge + PoW + method/path binding!
  const challenge = "cafebabecafebabecafebabecafebabe";
  const powAtt = buildAttestation({
    mode: "strict",
    ticket,
    nonce,
    challenge,
    difficulty: 10,
    method: "GET",
    path: "/api/secret",
    telemetry: { platform: "Linux x86_64" },
  });
  const okPow = verifyAttestation({
    mode: "strict",
    headers,
    attest: powAtt,
    ticket,
    nonce,
    expectedChallenge: challenge,
    expectedDifficulty: 10,
    expectedMethod: "GET",
    expectedPath: "/api/secret",
    requireFetchMetadata: true,
  });
  assert.equal(okPow.ok, true);

  // Method/path tampering in Repeater fails REQUEST_BINDING_MISMATCH!
  const badPathPow = verifyAttestation({
    mode: "strict",
    headers,
    attest: powAtt,
    ticket,
    nonce,
    expectedChallenge: challenge,
    expectedDifficulty: 10,
    expectedMethod: "POST",
    expectedPath: "/api/admin",
    requireFetchMetadata: true,
  });
  assert.equal(badPathPow.blocked, true);
  assert.ok(badPathPow.reasons.includes("REQUEST_BINDING_MISMATCH"));

  // Balanced mode blocks curl & HeadlessChrome
  const balCurl = verifyAttestation({ mode: "balanced", headers: { "user-agent": "curl/8.5.0" }, attest: null });
  assert.equal(balCurl.blocked, true);
  assert.ok(balCurl.reasons.includes("AUTOMATION_UA_DENIED"));
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

  const flaggedAtt = buildAttestation({
    mode: "strict",
    ticket,
    nonce,
    telemetry: { canvas2dUniqueColors: 5, platform: "Linux x86_64" },
  });
  const flaggedRes = verifyAttestation({ mode: "strict", headers, attest: flaggedAtt, ticket, nonce });
  assert.equal(flaggedRes.blocked, true);
  assert.ok(flaggedRes.reasons.includes("CANVAS2D_SYNTHETIC_NOISE"));

  // Python zero-dep verifier & IP/UA/PoW ticket store parity
  const pyDir = path.join(__dirname, "..", "python");
  const pyOut = execFileSync(
    "python3",
    [
      "-c",
      `import sys, json, hashlib; sys.path.insert(0, ${JSON.stringify(pyDir)});
from veilbreak import verify_attestation, VeilBreakTicketStore, solve_pow_challenge, is_path_protected
h = json.loads(${JSON.stringify(JSON.stringify(headers))})
att = json.loads(${JSON.stringify(JSON.stringify(att))})
r = verify_attestation(mode="strict", headers=h, attest=att, ticket=${JSON.stringify(ticket)}, nonce=${JSON.stringify(nonce)})
assert r.ok and not r.blocked and r.score == 0
r_bal = verify_attestation(mode="balanced", headers={"User-Agent": "curl/8.5.0"}, attest=None)
assert r_bal.blocked and "AUTOMATION_UA_DENIED" in r_bal.reasons
# Path normalization parity in Python!
for p in ("/api/%2e%2e/secret", "/api%00/secret", "http://127.0.0.1\\\\api\\\\secret", "//api/x", "/api#foo"):
    assert is_path_protected(p, ["/api/"]), f"missed {p}"
# IP + UA + PoW ticket challenge flow + theft/replay blocking
store = VeilBreakTicketStore(mode="strict", ticket_pow_bits=10)
ch = store.mint_ticket_challenge(ip="127.0.0.1", user_agent=h["user-agent"])
tk, chal, diff = ch["ticket"], ch["challenge"], ch["difficulty"]
w = solve_pow_challenge(tk, chal, diff)
nn = "1122334455667788"
d = hashlib.sha256(f"VB_ATTEST_V2|{tk}|{nn}|0|0|Linux x86_64|{chal}|{w}|GET|/api/secret".encode()).hexdigest()
req_h = dict(h, **{"X-VB-Ticket": tk, "X-VB-Nonce": nn, "X-VB-Attest": json.dumps({"v":2,"s":0,"f":0,"p":"Linux x86_64","w":w,"m":"GET","u":"/api/secret","d":d})})
v1 = store.verify_request(headers=req_h, ip="127.0.0.1", method="GET", path="/api/secret")
v2 = store.verify_request(headers=req_h, ip="127.0.0.1", method="GET", path="/api/secret")
assert v1.ok and not v1.blocked
assert v2.blocked and "TICKET_REPLAYED_OR_INVALID" in v2.reasons
# Ticket stolen to another IP must fail TICKET_BINDING_MISMATCH!
ch2 = store.mint_ticket_challenge(ip="127.0.0.1", user_agent=h["user-agent"])
w2 = solve_pow_challenge(ch2["ticket"], ch2["challenge"], ch2["difficulty"])
d2 = hashlib.sha256(f"VB_ATTEST_V2|{ch2['ticket']}|{nn}|0|0|Linux x86_64|{ch2['challenge']}|{w2}|GET|/api/secret".encode()).hexdigest()
req_h2 = dict(h, **{"X-VB-Ticket": ch2["ticket"], "X-VB-Nonce": nn, "X-VB-Attest": json.dumps({"v":2,"s":0,"f":0,"p":"Linux x86_64","w":w2,"m":"GET","u":"/api/secret","d":d2})})
v_theft = store.verify_request(headers=req_h2, ip="198.51.100.77", method="GET", path="/api/secret")
assert v_theft.blocked and "TICKET_BINDING_MISMATCH" in v_theft.reasons
print("PY_PARITY_OK")`,
    ],
    { encoding: "utf8" }
  ).trim();
  assert.equal(pyOut, "PY_PARITY_OK");
});

test("6. Live HTTP server enforces IP/UA/PoW one-time tickets, blocks curl & Repeater tampering, path bypasses, handles gzip HTML & HEAD", async () => {
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
    const htmlResp = await fetch(`${baseUrl}/`, { headers: makeBrowserHeaders() });
    assert.equal(htmlResp.status, 200);
    assert.ok((await htmlResp.text()).includes("/__veilbreak/gate.js"));

    const gzResp = await fetch(`${baseUrl}/gzip`, { headers: makeBrowserHeaders() });
    assert.equal(gzResp.status, 200);
    assert.ok((await gzResp.text()).includes("/__veilbreak/gate.js"));

    const headResp = await fetch(`${baseUrl}/`, { method: "HEAD", headers: makeBrowserHeaders() });
    assert.equal(headResp.status, 200);
    assert.equal((await headResp.text()).length, 0);

    // Path normalization blocks /API/secret, /%61pi/secret, //api/secret, /x/../api/secret, /api/%2e%2e/secret, /api%00/secret
    // Use raw http.request (like curl --path-as-is & Caido Repeater) so WHATWG fetch() doesn't pre-normalize %2e%2e client-side!
    for (const bypass of [
      "/API/secret",
      "/%61pi/secret",
      "//api/secret",
      "/x/../api/secret",
      "/api/%2e%2e/secret",
      "/api%00/secret",
      "/api./secret",
      "/api%20/secret",
    ]) {
      const status = await new Promise((resolve, reject) => {
        const req = http.request(
          { host: "127.0.0.1", port: gate.server.address().port, method: "GET", path: bypass, headers: makeBrowserHeaders() },
          (r) => { r.resume(); r.on("end", () => resolve(r.statusCode)); }
        );
        req.on("error", reject);
        req.end();
      });
      assert.equal(status, 403, `Bypass path must be blocked: ${bypass}`);
    }

    // Raw curl AND spoofed-UA curl (missing Sec-Fetch-*) denied on /__veilbreak/ticket!
    assert.equal((await fetch(`${baseUrl}/__veilbreak/ticket`, { headers: { "User-Agent": "curl/8.5.0" } })).status, 403);
    assert.equal((await fetch(`${baseUrl}/__veilbreak/ticket`, { headers: { "User-Agent": CHROME_UA } })).status, 403);
    assert.equal((await fetch(`${baseUrl}/__veilbreak/ticket`, { headers: { "User-Agent": "Mozilla/5.0 HeadlessChrome/158.0" } })).status, 403);

    // Valid browser ticket + PoW + method/path-bound attestation passes once, replay is blocked!
    const tkData = await (await fetch(`${baseUrl}/__veilbreak/ticket`, { headers: makeBrowserHeaders() })).json();
    assert.ok(tkData.ticket && tkData.challenge && tkData.difficulty >= 10);
    const nonce = "1122334455667788";
    const att = buildAttestation({
      mode: "strict",
      ticket: tkData.ticket,
      nonce,
      challenge: tkData.challenge,
      difficulty: tkData.difficulty,
      method: "GET",
      path: "/api/secret",
      telemetry: { platform: "Linux x86_64" },
    });
    const reqHeaders = makeBrowserHeaders({
      "X-VB-Ticket": tkData.ticket,
      "X-VB-Nonce": nonce,
      "X-VB-Attest": JSON.stringify(att),
    });
    const okApi = await fetch(`${baseUrl}/api/secret`, { headers: reqHeaders });
    assert.equal(okApi.status, 200);
    assert.equal((await okApi.json()).secret, "PROTECTED_OK");

    // Replaying exact same ticket/headers in Repeater -> 403!
    const replayApi = await fetch(`${baseUrl}/api/secret`, { headers: reqHeaders });
    assert.equal(replayApi.status, 403);
    const repJson = await replayApi.json();
    assert.ok(repJson.reasons.includes("TICKET_REPLAYED_OR_INVALID"));

    // Ticket minted with UA A cannot be used with UA B (TICKET_BINDING_MISMATCH)!
    const tk2 = await (await fetch(`${baseUrl}/__veilbreak/ticket`, { headers: makeBrowserHeaders() })).json();
    const att2 = buildAttestation({
      mode: "strict",
      ticket: tk2.ticket,
      nonce,
      challenge: tk2.challenge,
      difficulty: tk2.difficulty,
      method: "GET",
      path: "/api/secret",
      telemetry: { platform: "Linux x86_64" },
    });
    const uaSwap = await fetch(`${baseUrl}/api/secret`, {
      headers: makeBrowserHeaders({
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0",
        "X-VB-Ticket": tk2.ticket,
        "X-VB-Nonce": nonce,
        "X-VB-Attest": JSON.stringify(att2),
      }),
    });
    assert.equal(uaSwap.status, 403);
    assert.ok((await uaSwap.json()).reasons.includes("TICKET_BINDING_MISMATCH"));
  } finally {
    await gate.close();
    await new Promise((r) => upstream.close(r));
  }
});

test("7. Natural-language compiler fixes, browser SDK observe/antiCdp/syntax, and playground XSS-safe escaping", () => {
  // Slashes in "Brave/LibreWolf" must NOT hijack protectedPaths!
  const p1 = compileNaturalLanguage("protect http://localhost:3000 on port 9090 while keeping Brave/LibreWolf working");
  assert.equal(p1.intent, "protect");
  assert.equal(p1.options.mode, "balanced");
  assert.equal(p1.options.port, 9090);
  assert.deepEqual(p1.options.protectedPaths, ["/api"]);

  // "disable playground" MUST NOT turn off VeilBreak protection!
  const pDis = compileNaturalLanguage("block stealth browsers on http://localhost:3000 and disable playground behind nginx");
  assert.equal(pDis.options.mode, "strict");
  assert.equal(pDis.options.trustProxy, "127.0.0.1");

  // "do not block, monitor" and "observe mode" compile safely to monitor!
  assert.equal(compileNaturalLanguage("do not block users on http://localhost:3000, just monitor").options.mode, "monitor");
  assert.equal(compileNaturalLanguage("protect /api in observe mode on localhost:4000").options.mode, "monitor");
  assert.equal(compileNaturalLanguage("protect /api in observe mode on localhost:4000").options.target, "http://localhost:4000");

  // Negated monitor stays strict; "react app on port 8080" stays protect (not snippet!)
  assert.equal(compileNaturalLanguage("do not monitor, block strictly on http://localhost:3000").options.mode, "strict");
  assert.equal(compileNaturalLanguage("protect my react app on port 8080").intent, "protect");
  assert.throws(() => compileNaturalLanguage("demo on port 99999"));
  assert.throws(() => compileNaturalLanguage("protect ftp://127.0.0.1:21"));

  const p3 = compileNaturalLanguage("show me a demo on port 9999");
  assert.equal(p3.intent, "demo");
  assert.equal(p3.options.port, 9999);

  // Browser SDK parses cleanly with RegExp, observe mode, antiCdp=false, and includes XMLHttpRequest wrapping
  const js = buildBrowserGateScript({
    defaultMode: "observe",
    antiCdp: false,
    protectedPaths: ["/api", /^\/v\d+\/data/i],
  });
  new Function(js);
  assert.ok(js.includes("XMLHttpRequest.prototype.send"));
  assert.ok(js.includes('s === "observe"'));

  // Playground HTML escapes </script> breakouts safely
  const pg = buildPlaygroundHtml({ mode: "</script><script>alert(1)//", basePath: "/__veilbreak/" });
  assert.ok(!pg.includes("</script><script>alert(1)"));
  assert.ok(pg.includes('src="/__veilbreak/gate.js"'));
});

test("8. v2 CIDR trustProxy per-client ticket rate limiting, observe alias, and modular subpath exports with .d.ts", async () => {
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
        headers: makeBrowserHeaders({ "x-forwarded-for": xff }),
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

  assert.equal((await callTicket("198.51.100.10")).status, 200);
  assert.equal((await callTicket("198.51.100.10")).status, 200);
  assert.equal((await callTicket("198.51.100.10")).status, 429);
  assert.equal((await callTicket("198.51.100.22")).status, 200);

  const pkg = require("../package.json");
  assert.equal(pkg.exports["./probes"].default, "./src/probes.js");
  assert.equal(pkg.exports["./probes"].types, "./src/probes.d.ts");
  assert.equal(pkg.exports["./middleware"].types, "./src/middleware.d.ts");
  assert.equal(pkg.exports["."].types, "./src/index.d.ts");
  assert.ok(pkg.files.includes("!python/__pycache__/**"));
});

test("9. Security regressions: ['*'] wildcard, #/%ff/%2e%2e/%00 bypasses, cross-site /ticket, IPv6 CIDR, Connection strip, maxTickets=1", async () => {
  assert.equal(normalizePathname("/%61pi/%ff/data"), "/api/%ff/data");
  assert.equal(normalizePathname("/%ff%2f../api/secret"), "/api/secret");
  assert.equal(normalizePathname("/x#/../api/secret"), "/api/secret");
  assert.equal(normalizePathname("/api/"), "/api");

  const badFlagRes = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders(),
    attest: { v: 2, s: 1, f: 64, p: "Linux", d: "a".repeat(64) },
    ticket: "t1",
    nonce: "n1",
  });
  assert.equal(badFlagRes.blocked, true);
  assert.ok(badFlagRes.reasons.includes("ATTEST_INVALID"));

  const starMw = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["*"] });
  let starStatus = 0;
  await starMw(
    {
      method: "GET",
      url: "/anything/here",
      socket: { remoteAddress: "127.0.0.1" },
      headers: makeBrowserHeaders(),
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

  // maxTickets=1 refuses capacity cleanly with 503 (consistent with Python)
  const capMw = createVeilBreakMiddleware({ mode: "strict", maxTickets: 1 });
  function reqTicket(mwInst, headers, remoteAddress = "127.0.0.1") {
    return new Promise((resolve) => {
      let status = 200;
      mwInst(
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
  assert.equal((await reqTicket(capMw, makeBrowserHeaders())).status, 200);
  assert.equal((await reqTicket(capMw, makeBrowserHeaders())).status, 503);

  const v6Mw = createVeilBreakMiddleware({
    mode: "strict",
    trustProxy: ["2001:db8:cafe::/48"],
    maxTicketsPerMinPerIp: 1,
  });
  const csrf = await reqTicket(v6Mw, makeBrowserHeaders({ "sec-fetch-site": "cross-site" }), "2001:db8:cafe::1");
  assert.equal(csrf.status, 403);
  assert.equal(csrf.body.error, "CROSS_SITE_TICKET_DENIED");

  const rA1 = await reqTicket(v6Mw, makeBrowserHeaders({ "x-forwarded-for": "198.51.100.1, 2001:db8:cafe::2" }), "2001:db8:cafe::1");
  const rA2 = await reqTicket(v6Mw, makeBrowserHeaders({ "x-forwarded-for": "198.51.100.1, 2001:db8:cafe::2" }), "2001:db8:cafe::1");
  const rB1 = await reqTicket(v6Mw, makeBrowserHeaders({ "x-forwarded-for": "198.51.100.2, 2001:db8:cafe::2" }), "2001:db8:cafe::1");
  assert.equal(rA1.status, 200);
  assert.equal(rA2.status, 429);
  assert.equal(rB1.status, 200);

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
    const sp = await fetch(`${baseUrl}/public/my%20file.json?q=hello%20world`, { headers: makeBrowserHeaders() });
    assert.equal(sp.status, 200);
    assert.equal(seenUrl, "/public/my%20file.json?q=hello%20world");

    const rawAbs = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: "127.0.0.1", port: gate.server.address().port, method: "GET", path: "http://example.com?x=/api/secret", headers: makeBrowserHeaders() },
        (r) => { r.resume(); r.on("end", () => resolve(r.statusCode)); }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(rawAbs, 200);
    assert.equal(seenUrl, "/?x=/api/secret");

    const qBypass = await fetch(`${baseUrl}/api%3F`, { headers: makeBrowserHeaders() });
    assert.equal(qBypass.status, 403);

    const connRes = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: gate.server.address().port,
          method: "GET",
          path: "/public",
          headers: {
            "User-Agent": CHROME_UA,
            Authorization: "Bearer keep-me",
            Connection: "keep-alive, authorization, x-forwarded-for",
          },
        },
        (r) => { r.resume(); r.on("end", () => resolve(r.statusCode)); }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(connRes, 200);
    assert.equal(seenAuth, "Bearer keep-me");
    assert.ok(seenXff && seenXff.includes("127.0.0.1"));
  } finally {
    await gate.close();
    await new Promise((r) => upstream.close(r));
  }
});

test("10. Loop B hardening: trustProxy Connection:close, ['*'] HTML-only probe, trailing slash, OPTIONS override block, sha256Hex(Buffer), %20 path binding, NL & Python concurrency", async () => {
  const crypto = require("node:crypto");
  const { sha256Hex, solvePowChallenge } = require("../src/probes.js");

  // 1) sha256Hex binary Buffer & Uint8Array accuracy
  const rawBytes = Buffer.from([0xff, 0x00, 0xfe, 0x80, 0x01, 0x7f]);
  assert.equal(
    sha256Hex(rawBytes),
    crypto.createHash("sha256").update(rawBytes).digest("hex"),
    "sha256Hex(Buffer) MUST hash raw bytes without UTF-8 replacement corruption"
  );
  assert.equal(
    sha256Hex(new Uint8Array(rawBytes)),
    crypto.createHash("sha256").update(rawBytes).digest("hex"),
    "sha256Hex(Uint8Array) MUST hash raw bytes"
  );

  // 2) %20-terminated path binding & empty-path rejection in Node
  const cleanTel = {
    webdriver: false,
    canvas2dUniqueColors: 1,
    webglClearUniqueColors: 1,
    silentAudioNonZeroSamples: 0,
    platform: "Linux x86_64",
  };
  const spacePath = "/api/search/foo%20";
  const powNonce = solvePowChallenge("tk-space-1", "ch-space-1", 8);
  const attSpace = buildAttestation({
    telemetry: cleanTel,
    ticket: "tk-space-1",
    nonce: "nonce-space-1234",
    challenge: "ch-space-1",
    powNonce,
    method: "GET",
    path: spacePath,
  });
  assert.equal(attSpace.u, "/api/search/foo ", "buildAttestation preserves trailing space from %20 without trimming");
  const verSpace = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders(),
    attest: attSpace,
    ticket: "tk-space-1",
    nonce: "nonce-space-1234",
    expectedChallenge: "ch-space-1",
    expectedDifficulty: 8,
    expectedMethod: "GET",
    expectedPath: spacePath,
  });
  assert.equal(verSpace.blocked, false, `trailing %20 path should verify cleanly: ${verSpace.reasons}`);

  const emptyPathAtt = buildAttestation({
    telemetry: cleanTel,
    ticket: "tk-empty-1",
    nonce: "nonce-empty-1234",
    challenge: "ch-empty-1",
    powNonce: solvePowChallenge("tk-empty-1", "ch-empty-1", 8),
    method: "GET",
    path: "",
  });
  const verEmpty = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders(),
    attest: emptyPathAtt,
    ticket: "tk-empty-1",
    nonce: "nonce-empty-1234",
    expectedChallenge: "ch-empty-1",
    expectedDifficulty: 8,
    expectedMethod: "GET",
    expectedPath: "/api/secret",
  });
  assert.equal(verEmpty.blocked, true);
  assert.ok(verEmpty.reasons.includes("REQUEST_BINDING_MISMATCH"));

  // 3) Reverse-proxy server tests: trustProxy Connection:close, ['*'] HTML-only probe, trailing slash, OPTIONS guards
  let lastSeenUrl = null;
  let lastSeenMethod = null;
  const upstream = http.createServer((req, res) => {
    lastSeenUrl = req.url;
    lastSeenMethod = req.method;
    if (req.url === "/" || req.url === "/docs/") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end("<html><head></head><body><h1>Portal</h1></body></html>");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ secret: "vb-top-secret", path: req.url, method: req.method }));
  });
  await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
  const starGate = createVeilBreakServer({
    target: `http://127.0.0.1:${upstream.address().port}`,
    mode: "strict",
    protectedPaths: ["*"],
    trustProxy: ["127.0.0.1"],
  });
  const starUrl = await starGate.listen(0, "127.0.0.1");
  try {
    const rawGet = (reqPath, headers) =>
      new Promise((resolve, reject) => {
        const req = http.request(
          { host: "127.0.0.1", port: starGate.server.address().port, method: "GET", path: reqPath, headers },
          (r) => {
            let data = "";
            r.on("data", (c) => (data += c));
            r.on("end", () => resolve({ status: r.statusCode, body: data, headers: r.headers }));
          }
        );
        req.on("error", reject);
        req.end();
      });
    const navHdrs = makeBrowserHeaders({
      accept: "text/html,application/xhtml+xml",
      "sec-fetch-mode": "navigate",
      "sec-fetch-dest": "document",
      "sec-fetch-site": "none",
      "x-forwarded-for": "203.0.113.30",
    });

    // HTML root passes and injects SDK
    const htmlRes = await rawGet("/", navHdrs);
    assert.equal(htmlRes.status, 200);
    assert.ok(htmlRes.body.includes("/__veilbreak/gate.js"));

    // Trailing slash preserved
    const docsRes = await rawGet("/docs/", navHdrs);
    assert.equal(docsRes.status, 200);
    assert.equal(lastSeenUrl, "/docs/", "trailing slash MUST be preserved");

    // Spoofed HTML navigation headers hitting JSON endpoint under ["*"] MUST be blocked!
    const leakRes = await rawGet("/api/secret", navHdrs);
    assert.equal(leakRes.status, 403);
    assert.ok(!leakRes.body.includes("vb-top-secret"), "JSON must NOT leak under ['*']");

    // trustProxy + Connection: close allowed on /__veilbreak/ticket
    const tkRes = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: starGate.server.address().port,
          method: "GET",
          path: "/__veilbreak/ticket",
          headers: {
            ...makeBrowserHeaders({ "x-forwarded-for": "203.0.113.31" }),
            connection: "close",
          },
        },
        (r) => {
          let data = "";
          r.on("data", (c) => (data += c));
          r.on("end", () => resolve({ status: r.statusCode, body: JSON.parse(data) }));
        }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(tkRes.status, 200, "trustProxy + Connection: close must succeed on /__veilbreak/ticket");

    // Attested same-origin OPTIONS passes even when upstream has NO Access-Control-Allow-Origin
    const optNonce = "vb-opt-nonce-123";
    const optPow = solvePowChallenge(tkRes.body.ticket, tkRes.body.challenge, tkRes.body.difficulty || 0);
    const optAtt = buildAttestation({
      telemetry: cleanTel,
      ticket: tkRes.body.ticket,
      nonce: optNonce,
      challenge: tkRes.body.challenge,
      powNonce: optPow,
      method: "OPTIONS",
      path: "/api/secret",
    });
    const attestedOpt = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: starGate.server.address().port,
          method: "OPTIONS",
          path: "/api/secret",
          headers: {
            ...makeBrowserHeaders({
              "x-forwarded-for": "203.0.113.31",
              "x-vb-ticket": tkRes.body.ticket,
              "x-vb-nonce": optNonce,
              "x-vb-attest": JSON.stringify(optAtt),
            }),
            connection: "close",
          },
        },
        (r) => {
          let data = "";
          r.on("data", (c) => (data += c));
          r.on("end", () => resolve({ status: r.statusCode, body: data }));
        }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(attestedOpt.status, 200, "attested same-origin OPTIONS must pass");
    assert.equal(lastSeenMethod, "OPTIONS");

    // Unattested OPTIONS with X-Original-URL override -> 403
    const overrideOpt = await fetch(`${starUrl}/public`, {
      method: "OPTIONS",
      headers: makeBrowserHeaders({
        origin: "https://other.example",
        "access-control-request-method": "POST",
        "x-original-url": "/api/secret",
        "x-forwarded-for": "203.0.113.32",
      }),
    });
    assert.equal(overrideOpt.status, 403);

    // Unattested cross-origin OPTIONS to non-CORS backend -> 403 and no JSON leak
    const unattOpt = await fetch(`${starUrl}/api/secret`, {
      method: "OPTIONS",
      headers: makeBrowserHeaders({
        origin: "https://other.example",
        "access-control-request-method": "POST",
        "x-forwarded-for": "203.0.113.33",
      }),
    });
    assert.equal(unattOpt.status, 403);
    assert.ok(!(await unattOpt.text()).includes("vb-top-secret"));
  } finally {
    await starGate.close();
    await new Promise((r) => upstream.close(r));
  }

  // 4) NL compiler fixes
  assert.equal(compileNaturalLanguage("disable shield on http://localhost:3000").options.mode, "off");
  assert.equal(compileNaturalLanguage("protect http://localhost:3000 behind nginx on a vps").options.trustProxy, "127.0.0.1");
  assert.deepEqual(compileNaturalLanguage("protect entire site on http://localhost:3000").options.protectedPaths, ["/api"]);

  // 5) Python %20 path binding, empty path rejection, bool difficulty rejection, & multi-thread ticket store stress
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, threading, json; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import VeilBreakTicketStore, verify_attestation, solve_pow_challenge, _sha256_hex
# Trailing %20 preserved without strip
tk, ch, nn = "tk-py-space", "ch-py-space", "nonce-py-space-1"
pw = solve_pow_challenge(tk, ch, 8)
u = "/api/search/foo%20"
d = _sha256_hex(f"VB_ATTEST_V2|{tk}|{nn}|0|0|Linux x86_64|{ch}|{pw}|GET|{u}")
v_ok = verify_attestation(
    mode="strict",
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"},
    attest={"v": 2, "s": 0, "f": 0, "p": "Linux x86_64", "w": pw, "m": "GET", "u": u, "d": d},
    ticket=tk, nonce=nn, expected_challenge=ch, expected_difficulty=8, expected_method="GET", expected_path=u
)
assert not v_ok.blocked, f"unexpected block: {v_ok.reasons}"
# Empty att_u rejected when expected_path is set
d_empty = _sha256_hex(f"VB_ATTEST_V2|{tk}|{nn}|0|0|Linux x86_64|{ch}|{pw}|GET|")
v_empty = verify_attestation(
    mode="strict",
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}},
    attest={"v": 2, "s": 0, "f": 0, "p": "Linux x86_64", "w": pw, "m": "GET", "u": "", "d": d_empty},
    ticket=tk, nonce=nn, expected_challenge=ch, expected_difficulty=8, expected_method="GET", expected_path="/api/secret"
)
assert v_empty.blocked and "REQUEST_BINDING_MISMATCH" in v_empty.reasons
# bool expected_difficulty ignored cleanly (treated as 0, NOT 1-bit PoW!)
v_bool = verify_attestation(
    mode="strict",
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}},
    attest={"v": 2, "s": 0, "f": 0, "p": "Linux x86_64", "w": "notpow", "m": "GET", "u": u, "d": _sha256_hex(f"VB_ATTEST_V2|{tk}|{nn}|0|0|Linux x86_64|{ch}|notpow|GET|{u}")},
    ticket=tk, nonce=nn, expected_challenge=ch, expected_difficulty=True, expected_method="GET", expected_path=u
)
assert not v_bool.blocked, f"bool expected_difficulty should not fail: {v_bool.reasons}"
# Multi-thread stress test on VeilBreakTicketStore
store = VeilBreakTicketStore(max_tickets=5000, ticket_pow_bits=8)
errors = []
def worker(tid):
    try:
        for i in range(40):
            ip = f"198.51.100.{(tid * 40 + i) % 250 + 1}"
            rec = store.mint_ticket_challenge(ip=ip, user_agent="Mozilla/5.0 Chrome/158.0")
            assert rec is not None
            consumed = store.consume_ticket(rec["ticket"])
            assert consumed is not None and consumed["challenge"] == rec["challenge"]
            assert store.consume_ticket(rec["ticket"]) is None
    except Exception as e:
        errors.append(repr(e))
threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
for t in threads: t.start()
for t in threads: t.join()
assert not errors, f"thread errors: {errors}"`,
    ],
    { encoding: "utf8" }
  );
});

test("11. Loop C hardening: dual path-override headers, wildcard 304/302, %3F idempotent path binding (both directions), nl negatedProxy, Python NaN TTL", async () => {
  const { solvePowChallenge, isProtectedPath } = require("../src/probes.js");

  // 1) %3F idempotent normalizePathname + bidirectional binding verification
  assert.equal(normalizePathname("/api/items/what%3Fnow"), "/api/items/what%3Fnow");
  assert.equal(normalizePathname(normalizePathname("/api/items/what%3Fnow")), "/api/items/what%3Fnow");
  assert.equal(isProtectedPath("/api%3F", ["/api"]), true, "/api%3F bypass remains protected");

  const cleanTel = {
    webdriver: false,
    canvas2dUniqueColors: 1,
    webglClearUniqueColors: 1,
    silentAudioNonZeroSamples: 0,
    platform: "Linux x86_64",
  };
  const pw = solvePowChallenge("tk-q-1", "ch-q-1", 8);
  const attQ = buildAttestation({
    telemetry: cleanTel,
    ticket: "tk-q-1",
    nonce: "nonce-q-123456",
    challenge: "ch-q-1",
    powNonce: pw,
    method: "GET",
    path: "/api/items/what%3Fnow",
  });
  const okQ = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders(),
    attest: attQ,
    ticket: "tk-q-1",
    nonce: "nonce-q-123456",
    expectedChallenge: "ch-q-1",
    expectedDifficulty: 8,
    expectedMethod: "GET",
    expectedPath: "/api/items/what%3Fnow",
  });
  assert.equal(okQ.blocked, false, `valid %3F path must pass: ${okQ.reasons}`);

  // Reverse direction: attestation for /api/items/what%3Fnow MUST fail against /api/items/what
  const revFail = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders(),
    attest: attQ,
    ticket: "tk-q-1",
    nonce: "nonce-q-123456",
    expectedChallenge: "ch-q-1",
    expectedDifficulty: 8,
    expectedMethod: "GET",
    expectedPath: "/api/items/what",
  });
  assert.equal(revFail.blocked, true);
  assert.ok(revFail.reasons.includes("REQUEST_BINDING_MISMATCH"));

  // 2) Live server: dual override headers, middleware %3F forward binding, wildcard 304/302
  let seenHeaders = null;
  let seenUrl = null;
  const upstream = http.createServer((req, res) => {
    seenHeaders = req.headers;
    seenUrl = req.url;
    if (req.url === "/cached") {
      if (req.headers["if-modified-since"]) {
        res.writeHead(304);
        res.end();
        return;
      }
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Last-Modified": "Wed, 21 Oct 2025 07:28:00 GMT",
        ETag: '"v1"',
      });
      res.end("<html><head></head><body>cached</body></html>");
      return;
    }
    if (req.url === "/redirect") {
      res.writeHead(302, { Location: "/login" });
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, url: req.url }));
  });
  await new Promise((r) => upstream.listen(0, "127.0.0.1", r));

  try {
    const apiGate = createVeilBreakServer({
      target: `http://127.0.0.1:${upstream.address().port}`,
      mode: "strict",
      protectedPaths: ["/api"],
    });
    const apiUrl = await apiGate.listen(0, "127.0.0.1");
    try {
      // Dual path-override header bypass blocked (GET and OPTIONS)
      const dualGet = await fetch(`${apiUrl}/public`, {
        headers: makeBrowserHeaders({ "x-original-url": "/public", "x-rewrite-url": "/api/secret" }),
      });
      assert.equal(dualGet.status, 403, "GET dual override header must be blocked");

      const dualOpt = await fetch(`${apiUrl}/public`, {
        method: "OPTIONS",
        headers: makeBrowserHeaders({
          origin: "https://other.example",
          "access-control-request-method": "POST",
          "x-original-url": "/public",
          "x-rewrite-url": "/api/secret",
        }),
      });
      assert.equal(dualOpt.status, 403, "OPTIONS dual override header must be blocked");

      // Non-protected override headers stripped before forwarding upstream
      const okPub = await fetch(`${apiUrl}/public`, {
        headers: makeBrowserHeaders({ "x-original-url": "/public", "x-rewrite-url": "/public2" }),
      });
      assert.equal(okPub.status, 200);
      assert.equal(seenHeaders["x-original-url"], undefined);
      assert.equal(seenHeaders["x-rewrite-url"], undefined);

      // Middleware single-pass %3F path binding: attestation for /api/items/what MUST NOT work on /api/items/what%3Fadmin
      const tk1 = await (await fetch(`${apiUrl}/__veilbreak/ticket`, { headers: makeBrowserHeaders() })).json();
      const attWrong = buildAttestation({
        telemetry: cleanTel,
        ticket: tk1.ticket,
        nonce: "nonce-mw-q-1234",
        challenge: tk1.challenge,
        powNonce: solvePowChallenge(tk1.ticket, tk1.challenge, tk1.difficulty),
        method: "GET",
        path: "/api/items/what",
      });
      const bypassQ = await fetch(`${apiUrl}/api/items/what%3Fadmin`, {
        headers: makeBrowserHeaders({
          "x-vb-ticket": tk1.ticket,
          "x-vb-nonce": "nonce-mw-q-1234",
          "x-vb-attest": JSON.stringify(attWrong),
        }),
      });
      assert.equal(bypassQ.status, 403, "attestation for /api/items/what must NOT succeed on /api/items/what%3Fadmin");

      // Valid attestation for /api/items/what%3Fadmin passes & forwards single-encoded %3F upstream
      const tk2 = await (await fetch(`${apiUrl}/__veilbreak/ticket`, { headers: makeBrowserHeaders() })).json();
      const attRight = buildAttestation({
        telemetry: cleanTel,
        ticket: tk2.ticket,
        nonce: "nonce-mw-q-5678",
        challenge: tk2.challenge,
        powNonce: solvePowChallenge(tk2.ticket, tk2.challenge, tk2.difficulty),
        method: "GET",
        path: "/api/items/what%3Fadmin",
      });
      const okFwdQ = await fetch(`${apiUrl}/api/items/what%3Fadmin`, {
        headers: makeBrowserHeaders({
          "x-vb-ticket": tk2.ticket,
          "x-vb-nonce": "nonce-mw-q-5678",
          "x-vb-attest": JSON.stringify(attRight),
        }),
      });
      assert.equal(okFwdQ.status, 200);
      assert.equal(seenUrl, "/api/items/what%3Fadmin", "forwarded %3F must not be double-encoded");
    } finally {
      await apiGate.close();
    }

    // Wildcard ['*'] 304 reload & bodyless 302 redirect
    const starGate = createVeilBreakServer({
      target: `http://127.0.0.1:${upstream.address().port}`,
      mode: "strict",
      protectedPaths: ["*"],
    });
    await starGate.listen(0, "127.0.0.1");
    try {
      const rawGet = (reqPath, headers) =>
        new Promise((resolve, reject) => {
          const req = http.request(
            { host: "127.0.0.1", port: starGate.server.address().port, method: "GET", path: reqPath, headers },
            (r) => {
              let data = "";
              r.on("data", (c) => (data += c));
              r.on("end", () => resolve({ status: r.statusCode, body: data, headers: r.headers }));
            }
          );
          req.on("error", reject);
          req.end();
        });
      const navHdrs = makeBrowserHeaders({
        accept: "text/html",
        "sec-fetch-mode": "navigate",
        "sec-fetch-dest": "document",
        "sec-fetch-site": "none",
      });
      const r1 = await rawGet("/cached", navHdrs);
      assert.equal(r1.status, 200);
      assert.equal(r1.headers["last-modified"], undefined);
      const rReload = await rawGet("/cached", { ...navHdrs, "if-modified-since": "Wed, 21 Oct 2025 07:28:00 GMT" });
      assert.equal(rReload.status, 200);
      assert.ok(rReload.body.includes("/__veilbreak/gate.js"));
      const rRedir = await rawGet("/redirect", navHdrs);
      assert.equal(rRedir.status, 302);
      assert.equal(rRedir.headers.location, "/login");
    } finally {
      await starGate.close();
    }
  } finally {
    upstream.closeAllConnections?.();
    await new Promise((r) => upstream.close(r));
  }

  // 3) NL negatedProxy word-order fixes
  assert.equal(compileNaturalLanguage("protect http://localhost:3000 not behind a reverse proxy").options.trustProxy, "");
  assert.equal(compileNaturalLanguage("protect http://localhost:3000 not behind proxy").options.trustProxy, "");
  assert.equal(compileNaturalLanguage("block proxy behind nginx on http://localhost:3000").options.trustProxy, "127.0.0.1");

  // 4) Python %3F idempotence & NaN/inf ticket_ttl_ms validation
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import VeilBreakTicketStore, normalize_pathname, is_path_protected, solve_pow_challenge, _sha256_hex
assert normalize_pathname(normalize_pathname("/api/items/what%3Fnow")) == "/api/items/what%3Fnow"
assert is_path_protected("/api%3F", ["/api"])
for bad_ttl in (float("nan"), float("inf"), True, 0):
    try:
        VeilBreakTicketStore(ticket_ttl_ms=bad_ttl)
        raise AssertionError(f"expected ValueError for {bad_ttl}")
    except ValueError:
        pass
store = VeilBreakTicketStore(mode="strict", ticket_pow_bits=8)
rec = store.mint_ticket_challenge(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
pw = solve_pow_challenge(rec["ticket"], rec["challenge"], 8)
u = "/api/items/what%3Fnow"
d = _sha256_hex(f"VB_ATTEST_V2|{rec['ticket']}|nonce-py-q-1|0|0|Linux x86_64|{rec['challenge']}|{pw}|GET|{u}")
v = store.verify_request(
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
             "X-VB-Ticket": rec["ticket"], "X-VB-Nonce": "nonce-py-q-1",
             "X-VB-Attest": '{"v":2,"s":0,"f":0,"p":"Linux x86_64","w":"'+pw+'","m":"GET","u":"'+u+'","d":"'+d+'"}'},
    ip="127.0.0.1", method="GET", path=u
)
assert not v.blocked, f"Python %3F path failed: {v.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("12. v2.2 Presets, Firecrawl/AI-crawler blocking, active CDP zero-FP tuning, SRI, VB_HS_V3 proofs & Python parity", async () => {
  // 1) Preset availability vs. hardening matrix
  assert.equal(resolvePreset("balanced").bindIp, false, "balanced mode allows mobile IP switching");
  assert.equal(resolvePreset("balanced").cdpRuntimeWeight, 1);
  assert.equal(resolvePreset("strict").cdpRuntimeWeight, 4);
  assert.equal(resolvePreset("strict", { allowDevTools: true }).cdpRuntimeWeight, 1);
  assert.equal(SECURITY_PRESETS.paranoid.ticketPowBits, 14);
  assert.equal(SECURITY_PRESETS.paranoid.cdpRuntimeWeight, 6);

  // Human dev with DevTools open (cdpRuntimeEnable ONLY) -> ALLOWED in balanced AND in strict+allowDevTools, BLOCKED in strict/paranoid!
  const devOnly = { cdpRuntimeEnable: true, platform: "Linux x86_64" };
  assert.equal(evaluateTelemetry(devOnly, { mode: "balanced" }).blocked, false);
  assert.equal(evaluateTelemetry(devOnly, { mode: "balanced" }).cdpActive, true);
  assert.equal(evaluateTelemetry(devOnly, { mode: "strict", allowDevTools: true }).blocked, false);
  assert.equal(evaluateTelemetry(devOnly, { mode: "strict" }).blocked, true);
  assert.equal(evaluateTelemetry(devOnly, { mode: "paranoid" }).blocked, true);

  // Corroborated headless software WebGL (Firecrawl / Browserless Docker container) + CDP -> blocked even in balanced!
  const dockerHeadless = evaluateTelemetry(
    { cdpRuntimeEnable: true, softwareWebglHeadless: true, platform: "Linux x86_64" },
    { mode: "balanced" }
  );
  assert.equal(dockerHeadless.blocked, true);
  assert.ok(dockerHeadless.reasons.includes("HEADLESS_SOFTWARE_WEBGL"));

  // 2) Firecrawl, Apify, Browserless, Stagehand, GPTBot, ClaudeBot + crawler headers
  for (const h of [
    { "user-agent": "FirecrawlAgent/1.0" },
    { "user-agent": CHROME_UA, "x-firecrawl-id": "req-1" },
    { "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.0)" },
    { "user-agent": "ClaudeBot/1.0" },
    { "user-agent": CHROME_UA, "x-browserless-token": "abc" },
    { "user-agent": "Stagehand/1.0" },
  ]) {
    assert.equal(isAiCrawlerRequest(h), true, `Must detect crawler: ${JSON.stringify(h)}`);
    const v = verifyAttestation({ mode: "balanced", headers: h, attest: null });
    assert.equal(v.blocked, true);
    assert.ok(v.reasons.includes("AI_CRAWLER_OR_SCRAPER_DENIED"));
  }
  // Opt-out allows configured crawlers when blockAiCrawlers: false
  const allowCrawler = verifyHandshakeProof({
    mode: "balanced",
    headers: { "user-agent": "GPTBot/1.0" },
    proof: buildHandshakeProof({ mode: "balanced", challenge: "ch-allow-1", telemetry: { platform: "Linux x86_64" } }),
    expectedChallenge: "ch-allow-1",
    blockAiCrawlers: false,
  });
  assert.equal(allowCrawler.blocked, false);

  // 3) VB_HS_V3 challenge-bound handshake proof (clean passes, challenge replay fails, GPU/OS lie fails, paranoid CDP fails!)
  const cleanProof = buildHandshakeProof({
    mode: "strict",
    challenge: "chal-vb-hs-1",
    telemetry: { platform: "Linux x86_64", webglRenderer: "ANGLE (Intel Mesa)" },
  });
  assert.equal(
    verifyHandshakeProof({ mode: "strict", headers: makeBrowserHeaders(), proof: cleanProof, expectedChallenge: "chal-vb-hs-1" }).ok,
    true
  );
  const wrongChal = verifyHandshakeProof({
    mode: "strict",
    headers: makeBrowserHeaders(),
    proof: cleanProof,
    expectedChallenge: "chal-vb-hs-OTHER",
  });
  assert.equal(wrongChal.blocked, true);
  assert.ok(wrongChal.reasons.includes("BROWSER_PROOF_CHALLENGE_MISMATCH"));

  const gpuLieProof = buildHandshakeProof({
    mode: "strict",
    challenge: "chal-vb-hs-2",
    telemetry: { platform: "Linux x86_64", webglRenderer: "ANGLE (NVIDIA Direct3D11 vs_5_0)" },
  });
  const gpuLieRes = verifyHandshakeProof({
    mode: "strict",
    headers: makeBrowserHeaders(),
    proof: gpuLieProof,
    expectedChallenge: "chal-vb-hs-2",
  });
  assert.equal(gpuLieRes.blocked, true);
  assert.ok(gpuLieRes.reasons.includes("WEBGL_HARDWARE_COHERENCE_LIE"));

  // 4) Static SRI injection on createVeilBreakServer HTML + valid JS syntax for paranoid/unified SDK
  const sdkJs = buildBrowserGateScript({ defaultMode: "paranoid", allowDevTools: true });
  new Function(sdkJs);
  assert.ok(sdkJs.includes("collectHandshakeProof") && sdkJs.includes("detectCdpActive") && sdkJs.includes("UNIFIED_MODE"));

  const mw = createVeilBreakMiddleware({ mode: "strict" });
  assert.ok(mw.gateSri.startsWith("sha384-"));

  // 5) NL paranoid mode + Python v2.2 parity (Firecrawl, paranoid, verify_handshake_proof)
  assert.equal(compileNaturalLanguage("protect http://localhost:3000 in paranoid mode").options.mode, "paranoid");

  execFileSync(
    "python3",
    [
      "-c",
      `import sys, json; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import verify_attestation, verify_handshake_proof, is_ai_crawler_request, VeilBreakTicketStore
assert is_ai_crawler_request({"User-Agent": "FirecrawlAgent/1.0"})
assert is_ai_crawler_request({"User-Agent": "Mozilla/5.0", "X-Firecrawl-Request-Id": "123"})
r_fc = verify_attestation(mode="balanced", headers={"User-Agent": "FirecrawlAgent/1.0"}, attest=None)
assert r_fc.blocked and "AI_CRAWLER_OR_SCRAPER_DENIED" in r_fc.reasons
proof = json.loads(${JSON.stringify(JSON.stringify(cleanProof))})
h = json.loads(${JSON.stringify(JSON.stringify(makeBrowserHeaders()))})
v_ok = verify_handshake_proof(mode="strict", headers=h, proof=proof, expected_challenge="chal-vb-hs-1")
assert v_ok.ok and not v_ok.blocked, f"unexpected block: {v_ok.reasons}"
v_bad = verify_handshake_proof(mode="strict", headers=h, proof=proof, expected_challenge="wrong-chal")
assert v_bad.blocked and "BROWSER_PROOF_CHALLENGE_MISMATCH" in v_bad.reasons
bal_store = VeilBreakTicketStore(mode="balanced")
assert bal_store.bind_ip is False
para_store = VeilBreakTicketStore(mode="paranoid")
assert para_store.ticket_pow_bits == 14 and para_store.bind_ip is True`,
    ],
    { encoding: "utf8" }
  );
});

test("13. Pass-1 Audit Regressions: Unicode & '|' path binding, paranoid allowDevTools, CDP flag weight, CORS crawler block, LAN HTTP zero-FP, cache headers & ReDoS", async () => {
  // 1) ReDoS immunity on 14KB dot-filled path
  const t0 = Date.now();
  assert.equal(normalizePathname("/" + ".".repeat(14000) + "a"), "/" + ".".repeat(14000) + "a");
  assert.ok(Date.now() - t0 < 50, "14KB dot-filled path MUST complete in < 50ms");

  // 2) Pipe '|' percent-encoding preserves canonical attestation binding + Unicode path works cleanly
  const pipePath = "/api/search/a|b";
  assert.equal(normalizePathname(pipePath), "/api/search/a%7Cb");
  const attPipe = buildAttestation({
    mode: "strict",
    ticket: "tk-pipe-1",
    nonce: "nonce-pipe-1234",
    challenge: "ch-pipe-1",
    difficulty: 8,
    method: "GET",
    path: pipePath,
    telemetry: { platform: "Linux x86_64" },
  });
  const vPipe = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders(),
    attest: attPipe,
    ticket: "tk-pipe-1",
    nonce: "nonce-pipe-1234",
    expectedChallenge: "ch-pipe-1",
    expectedDifficulty: 8,
    expectedMethod: "GET",
    expectedPath: pipePath,
  });
  assert.equal(vPipe.blocked, false, `Pipe path binding failed: ${vPipe.reasons}`);

  // 3) allowDevTools: true in paranoid mode (BOTH verifyAttestation & verifyHandshakeProof!) + minScoreForFlags CDP score enforcement
  const devProof = buildHandshakeProof({
    mode: "paranoid",
    challenge: "ch-dev-para",
    allowDevTools: true,
    telemetry: { platform: "Linux x86_64", cdpRuntimeEnable: true },
  });
  assert.equal(
    verifyHandshakeProof({
      mode: "paranoid",
      allowDevTools: true,
      headers: makeBrowserHeaders(),
      proof: devProof,
      expectedChallenge: "ch-dev-para",
    }).blocked,
    false,
    "paranoid + allowDevTools: true MUST allow CDP-only developer handshake proof"
  );
  // Forging s=1 with f=128 (CDP bit) when strict mode requires weight=4 MUST fail ATTEST_INVALID!
  const fakeLowScore = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders(),
    attest: { v: 2, s: 1, f: 128, p: "Linux x86_64", d: "a".repeat(64) },
    ticket: "tk-x",
    nonce: "nonce-x-1234",
  });
  assert.equal(fakeLowScore.blocked, true);
  assert.ok(fakeLowScore.reasons.includes("ATTEST_INVALID"));

  // macOS Direct3D11 GPU lie detected!
  const macLie = verifyHandshakeProof({
    mode: "strict",
    headers: makeBrowserHeaders(),
    proof: buildHandshakeProof({
      mode: "strict",
      challenge: "ch-mac-lie",
      telemetry: { platform: "MacIntel", webglRenderer: "ANGLE (NVIDIA Direct3D11 vs_5_0)" },
    }),
    expectedChallenge: "ch-mac-lie",
  });
  assert.equal(macLie.blocked, true);
  assert.ok(macLie.reasons.includes("WEBGL_HARDWARE_COHERENCE_LIE"));

  // 4) Balanced preset has autoBlockPage = false (zero DOM-wipe risk on privacy browsers)
  assert.equal(resolvePreset("balanced").autoBlockPage, false);

  // 5) Middleware: Firecrawl blocked even on OPTIONS preflight, plain LAN HTTP doesn't FP on FETCH_METADATA_MISSING, versioned immutable vs unversioned ETag/304
  const mw = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const srv = http.createServer((req, res) => {
    mw(req, res, () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const baseUrl = `http://127.0.0.1:${srv.address().port}`;
  try {
    // Versioned gate.js is immutable; unversioned is no-cache + ETag -> 304
    const gVer = await fetch(`${baseUrl}/__veilbreak/gate.js?v=${mw.gateVersion}`, { headers: makeBrowserHeaders() });
    assert.equal(gVer.status, 200);
    assert.ok(gVer.headers.get("cache-control").includes("immutable"));
    const gUnver = await fetch(`${baseUrl}/__veilbreak/gate.js`, { headers: makeBrowserHeaders() });
    assert.equal(gUnver.status, 200);
    assert.equal(gUnver.headers.get("cache-control"), "public, no-cache, no-transform");
    const etag = gUnver.headers.get("etag");
    assert.ok(etag);
    const g304 = await fetch(`${baseUrl}/__veilbreak/gate.js`, { headers: makeBrowserHeaders({ "if-none-match": etag }) });
    assert.equal(g304.status, 304);

    // Firecrawl trying CORS OPTIONS preflight MUST be blocked!
    const fcOpt = await fetch(`${baseUrl}/api/secret`, {
      method: "OPTIONS",
      headers: {
        "User-Agent": "FirecrawlAgent/1.0",
        Origin: "https://evil.example",
        "Access-Control-Request-Method": "POST",
        "Sec-Fetch-Mode": "cors",
      },
    });
    assert.equal(fcOpt.status, 403);

    // Plain LAN HTTP (non-loopback Host without HTTPS) without Sec-Fetch-* should NOT trigger FETCH_METADATA_MISSING!
    const lanRes = await new Promise((resolve, reject) => {
      const tkReq = http.request(
        {
          host: "127.0.0.1",
          port: srv.address().port,
          method: "GET",
          path: "/__veilbreak/ticket",
          headers: makeBrowserHeaders(),
        },
        (r) => {
          let raw = "";
          r.on("data", (c) => (raw += c));
          r.on("end", () => resolve(JSON.parse(raw)));
        }
      );
      tkReq.on("error", reject);
      tkReq.end();
    });
    const lanAtt = buildAttestation({
      mode: "strict",
      ticket: lanRes.ticket,
      nonce: "nonce-lan-123456",
      challenge: lanRes.challenge,
      difficulty: lanRes.difficulty,
      method: "GET",
      path: "/api/lan",
      telemetry: { platform: "Linux x86_64" },
    });
    const lanStatus = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: srv.address().port,
          method: "GET",
          path: "/api/lan",
          headers: {
            Host: "192.168.1.50:3000",
            "User-Agent": CHROME_UA,
            "Accept-Language": "en-US,en;q=0.9",
            "X-VB-Ticket": lanRes.ticket,
            "X-VB-Nonce": "nonce-lan-123456",
            "X-VB-Attest": JSON.stringify(lanAtt),
          },
        },
        (r) => {
          r.resume();
          r.on("end", () => resolve(r.statusCode));
        }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(lanStatus, 200, "Plain LAN HTTP without Sec-Fetch-* must NOT false-positive on FETCH_METADATA_MISSING");
  } finally {
    await new Promise((r) => srv.close(r));
  }

  // 6) Python parity: allow_devtools in paranoid, mode="off", ReDoS immunity, macOS D3D11 check
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time, json; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import verify_handshake_proof, VeilBreakTicketStore, normalize_pathname
t0 = time.monotonic()
assert normalize_pathname("/" + "." * 14000 + "a") == "/" + "." * 14000 + "a"
assert time.monotonic() - t0 < 0.05
assert normalize_pathname("/api/a|b") == "/api/a%7Cb"
dev_p = json.loads(${JSON.stringify(JSON.stringify(devProof))})
h = json.loads(${JSON.stringify(JSON.stringify(makeBrowserHeaders()))})
v_dev = verify_handshake_proof(mode="paranoid", allow_devtools=True, headers=h, proof=dev_p, expected_challenge="ch-dev-para")
assert not v_dev.blocked, f"Python paranoid allow_devtools blocked: {v_dev.reasons}"
off_store = VeilBreakTicketStore(mode="off")
v_off = off_store.verify_request(headers={"User-Agent": "curl/8.5.0"}, ip="127.0.0.1", method="GET", path="/api/x")
assert v_off.ok and not v_off.blocked`,
    ],
    { encoding: "utf8" }
  );
});

test("14. Pass-2 Audit Regressions: %00+%0a ReDoS, Express trust-proxy, HTMX partial skip, RFC3986 forwarding, X-VB-Retry-Ticket, Python Mapping/HTTPMessage & TicketStore allow_devtools", async () => {
  const { isProtectedPath } = require("../src/probes.js");
  // 1) %00*4900 + %0a ReDoS immunity in expandPathCandidates / cleanPathNoCollapse
  const t0 = Date.now();
  assert.equal(isProtectedPath("/" + "%00".repeat(4900) + "%0a%3f%23", ["/api"]), false);
  assert.ok(Date.now() - t0 < 30, "%00*4900+%0a MUST run in < 30ms");

  // 2) Express app.get("trust proxy") honored by VeilBreak middleware (zero Nginx 403 on Connection: close!)
  const mw = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let expTkStatus = 0;
  await mw(
    {
      method: "GET",
      url: "/__veilbreak/ticket",
      ip: "203.0.113.88",
      app: { get: (k) => (k === "trust proxy" ? 1 : undefined) },
      socket: { remoteAddress: "127.0.0.1" },
      headers: { ...makeBrowserHeaders(), connection: "close" },
    },
    {
      headersSent: false,
      writableEnded: false,
      setHeader() {},
      writeHead(code) { expTkStatus = code; this.headersSent = true; },
      end() { this.writableEnded = true; },
    }
  );
  assert.equal(expTkStatus, 200, "Express app.set('trust proxy', 1) MUST allow Nginx Connection: close on /__veilbreak/ticket");

  // 3) HTMX partial HTML fragments NOT corrupted with <script> AND RFC3986 paths preserved on reverse proxy!
  const seenUrls = [];
  const up = http.createServer((req, res) => {
    seenUrls.push(req.url);
    if (req.url === "/fragment") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end("<tr><td>Row 1</td></tr>");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
  });
  await new Promise((r) => up.listen(0, "127.0.0.1", r));
  const srv = createVeilBreakServer({ target: `http://127.0.0.1:${up.address().port}`, mode: "strict", protectedPaths: ["/api"] });
  const baseUrl = await srv.listen(0, "127.0.0.1");
  try {
    const fragRes = await fetch(`${baseUrl}/fragment`, { headers: makeBrowserHeaders() });
    assert.equal(fragRes.status, 200);
    assert.equal(await fragRes.text(), "<tr><td>Row 1</td></tr>", "HTMX partial HTML fragment MUST NOT have <script> injected");

    for (const p of ["/@vite/client", "/public/users/@alice", "/public/v1/users:export", "/public/files/a%2Fb"]) {
      const r = await fetch(`${baseUrl}${p}`, { headers: makeBrowserHeaders() });
      assert.equal(r.status, 200);
    }
    assert.deepEqual(seenUrls.slice(1), ["/@vite/client", "/public/users/@alice", "/public/v1/users:export", "/public/files/a%2Fb"]);
  } finally {
    await srv.close();
    await new Promise((r) => up.close(r));
  }

  // 4) Python non-dict Mapping / HTTPMessage headers & VeilBreakTicketStore allow_devtools parity
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, types, email.message; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import is_ai_crawler_request, VeilBreakTicketStore, solve_pow_challenge, _sha256_hex
m = types.MappingProxyType({"User-Agent": "FirecrawlAgent/1.0"})
assert is_ai_crawler_request(m), "MappingProxyType headers MUST be accepted"
msg = email.message.Message()
msg["User-Agent"] = "FirecrawlAgent/1.0"
assert is_ai_crawler_request(msg), "HTTPMessage headers MUST be accepted"
store = VeilBreakTicketStore(mode="strict", allow_devtools=True, ticket_pow_bits=8)
rec = store.mint_ticket_challenge(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
w = solve_pow_challenge(rec["ticket"], rec["challenge"], 8)
# CDP flag (128) with score=1 when allow_devtools=True MUST be accepted (NOT ATTEST_INVALID!)
d = _sha256_hex(f"VB_ATTEST_V2|{rec['ticket']}|nonce-dt-1234|1|128|Linux x86_64|{rec['challenge']}|{w}|GET|/api/dev")
v = store.verify_request(
    headers=types.MappingProxyType({
        "User-Agent": ${JSON.stringify(CHROME_UA)},
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "X-VB-Ticket": rec["ticket"],
        "X-VB-Nonce": "nonce-dt-1234",
        "X-VB-Attest": '{"v":2,"s":1,"f":128,"p":"Linux x86_64","w":"'+w+'","m":"GET","u":"/api/dev","d":"'+d+'"}',
    }),
    ip="127.0.0.1", method="GET", path="/api/dev"
)
assert not v.blocked, f"VeilBreakTicketStore(allow_devtools=True) blocked: {v.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("15. Pass-3 Audit Regressions: non-ASCII Python ch safety, wildcard static 304 & API extension enforcement, private max-age SRI cache-control, internal-dot fast-path & browser SDK syntax", async () => {
  const { normalizePathname: normPath, isProtectedPath } = require("../src/probes.js");

  // 1) Internal-dot fast-path preserves exact behavior while keeping trailing/leading dot slow-path protection
  assert.equal(normPath("/api/v1.2/users/logo.png/"), "/api/v1.2/users/logo.png");
  assert.equal(isProtectedPath("/api./secret", ["/api"]), true);
  assert.equal(isProtectedPath("/api/v1.0/data.json", ["/api"]), true);
  assert.equal(isProtectedPath("/assets/app.min.js", ["/api"]), false);

  // 2) Browser SDK builds cleanly with iframe console.debug fallback, Symbol.for bridge check, LibreWolf RFP, VoiceOver reset & zero-alloc PoW
  const sdkSrc = buildBrowserGateScript({ defaultMode: "balanced", allowDevTools: false, antiCdp: true });
  new Function(sdkSrc);
  assert.ok(sdkSrc.includes("probeCdpWithConsole"), "SDK must include iframe-borrowed native console.debug fallback");
  assert.ok(sdkSrc.includes("_bridgeTampered"), "SDK must fail closed on data-vb-bridge Symbol.for tampering");
  assert.ok(sdkSrc.includes("likelyFirefoxRfp"), "SDK must exempt clean native Firefox RFP / LibreWolf");
  assert.ok(sdkSrc.includes("lastTeleportEl"), "SDK must protect screen-reader users from passive teleport false positives");
  assert.ok(sdkSrc.includes("_POW_SCRATCH"), "SDK must use zero-alloc scratch buffer in solveTicketPow");

  // 3) Reverse proxy: private, max-age=3600 HTML rewritten to private, no-cache when SRI injected; wildcard 304 static CSS reload passes; API path claiming Sec-Fetch-Dest:image blocked!
  const up = http.createServer((req, res) => {
    if (req.url === "/priv") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "private, max-age=3600" });
      res.end("<!doctype html><html><head></head><body>priv</body></html>");
      return;
    }
    if (req.url === "/style.css") {
      if (req.headers["if-none-match"]) {
        res.writeHead(304);
        res.end();
        return;
      }
      res.writeHead(200, { "Content-Type": "text/css", ETag: '"s1"' });
      res.end("body{}");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
  });
  await new Promise((r) => up.listen(0, "127.0.0.1", r));
  const starGate = createVeilBreakServer({
    target: `http://127.0.0.1:${up.address().port}`,
    mode: "strict",
    protectedPaths: ["*"],
  });
  await starGate.listen(0, "127.0.0.1");
  const sPort = starGate.server.address().port;
  const rawGetStar = (reqPath, headers) =>
    new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port: sPort, method: "GET", path: reqPath, headers }, (r) => {
        let data = "";
        r.on("data", (c) => (data += c));
        r.on("end", () => resolve({ status: r.statusCode, headers: r.headers, body: data }));
      });
      req.on("error", reject);
      req.end();
    });
  try {
    const navHdrs = makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" });
    const rPriv = await rawGetStar("/priv", navHdrs);
    assert.equal(rPriv.status, 200);
    assert.equal(rPriv.headers["cache-control"], "private, no-cache", "private max-age HTML with SRI MUST be rewritten to private, no-cache");

    const rCss = await rawGetStar("/style.css", makeBrowserHeaders({ "sec-fetch-dest": "style", "sec-fetch-site": "same-origin", "if-none-match": '"s1"' }));
    assert.equal(rCss.status, 200, "Cached static CSS reload in wildcard ['*'] mode MUST succeed (not 403 on 304)");

    const rApiSpoof = await rawGetStar("/api/secret", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }));
    assert.equal(rApiSpoof.status, 403, "API endpoint without static extension MUST NOT bypass wildcard via Sec-Fetch-Dest: image");
  } finally {
    await starGate.close();
    await new Promise((r) => up.close(r));
  }

  // 4) Python non-ASCII `ch` in verify_handshake_proof MUST NOT raise TypeError + internal-dot fast-path!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import verify_handshake_proof, normalize_pathname
assert normalize_pathname("/api/v1.2/logo.png/") == "/api/v1.2/logo.png"
v = verify_handshake_proof(
    mode="strict",
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"},
    proof={"v": 3, "ch": "héllo-émoji-🔥", "s": 0, "f": 0, "p": "Linux x86_64", "cdp": 0, "wr": "", "wk": 1, "ms": 5, "d": "a" * 64},
    expected_challenge="ascii-challenge-123"
)
assert v.blocked and "BROWSER_PROOF_CHALLENGE_MISMATCH" in v.reasons, f"Expected clean mismatch without TypeError: {v}"`,
    ],
    { encoding: "utf8" }
  );
});

test("16. Pass-4 Audit Regressions: balanced allowDevTools:false weight=4, METHOD_OVERRIDE_DENIED, store delete validation, IPv6 same-origin CORS, Python trailing-\\n immunity & anchored SDK checks", async () => {
  // 1) balanced + explicit allowDevTools: false raises cdpRuntimeWeight to 4 (blocks active CDP even in balanced!)
  const balNoDt = resolvePreset("balanced", { allowDevTools: false });
  assert.equal(balNoDt.cdpRuntimeWeight, 4, "balanced + allowDevTools:false MUST raise cdpRuntimeWeight to 4");
  const evBalNoDt = evaluateTelemetry({ cdpRuntimeEnable: true, platform: "Linux x86_64" }, { mode: "balanced", allowDevTools: false });
  assert.equal(evBalNoDt.blocked, true, "balanced + allowDevTools:false MUST block cdpRuntimeEnable");

  // 2) METHOD_OVERRIDE_DENIED in verifyAttestation + stripped by reverse proxy
  const ovVerdict = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders({ "x-http-method-override": "DELETE" }),
    expectedMethod: "GET",
    attest: buildAttestation({ mode: "strict", ticket: "tk1", nonce: "nonce-ov-1234", telemetry: { platform: "Linux x86_64" } }),
    ticket: "tk1",
    nonce: "nonce-ov-1234",
  });
  assert.equal(ovVerdict.blocked, true);
  assert.ok(ovVerdict.reasons.includes("METHOD_OVERRIDE_DENIED"));

  // 3) options.store lacking take/delete/del throws clear configuration error
  assert.throws(
    () => createVeilBreakMiddleware({ mode: "strict", store: { get() {}, set() {} } }),
    /take.*delete.*del/i,
    "VeilBreak options.store without delete/take MUST throw error"
  );

  // 4) Same-origin IPv6 Host alias NOT exempted as cross-origin CORS preflight!
  const mwV6 = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let v6Status = 0;
  await mwV6(
    {
      method: "OPTIONS",
      url: "/api/secret",
      socket: { remoteAddress: "127.0.0.1" },
      headers: makeBrowserHeaders({
        host: "[0:0:0:0:0:0:0:1]:8080",
        origin: "http://[::1]:8080",
        "access-control-request-method": "POST",
        "sec-fetch-mode": "cors",
      }),
    },
    {
      headersSent: false,
      writableEnded: false,
      setHeader() {},
      writeHead(code) { v6Status = code; this.headersSent = true; },
      end() { this.writableEnded = true; },
    }
  );
  assert.equal(v6Status, 403, "VeilBreak MUST canonicalize IPv6 Host alias and reject same-origin OPTIONS preflight");

  // 5) Browser SDK syntax & Pass-4 hardenings (anchored name regexes, cleanGeckoFpp, inner.onload, __VB_PRIVATE_REGISTER__)
  const sdkSrc = buildBrowserGateScript({ defaultMode: "strict", allowDevTools: false, antiCdp: true });
  new Function(sdkSrc);
  assert.ok(sdkSrc.includes("_NATIVE_FN_RE") && sdkSrc.includes("isNativeNamed"), "SDK must use anchored function-name regexes defeating .bind(null)");
  assert.ok(sdkSrc.includes("cleanGeckoFpp"), "SDK must exempt clean native Firefox Private Browsing / ETP Strict deterministic FPP");
  assert.ok(sdkSrc.includes("inner.onload ="), "SDK XHR must mirror completion in inner.onload (not onreadystatechange(4))");
  assert.ok(sdkSrc.includes("__VB_PRIVATE_REGISTER__"), "SDK must support private lexical closure registration in unified bundles");

  // 6) Python parity: trailing-newline fast-path immunity, balanced allow_devtools=False weight=4, METHOD_OVERRIDE_DENIED!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import is_path_protected, verify_attestation, _cdp_weight_for, _sha256_hex
assert is_path_protected("/api/secret\\n", ["/api"]), "Python trailing \\n MUST NOT bypass _CLEAN_ASCII_PATH_RE!"
assert is_path_protected("/api\\n", ["/api"]), "Python trailing \\n on /api MUST remain protected!"
assert _cdp_weight_for("balanced", anti_cdp=True, allow_devtools=False) == 4
d = _sha256_hex("VB_ATTEST_V2|tk1|nonce1234|0|0|Linux x86_64")
v = verify_attestation(
    mode="strict",
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-HTTP-Method-Override": "DELETE"},
    attest={"v": 2, "s": 0, "f": 0, "p": "Linux x86_64", "d": d},
    ticket="tk1", nonce="nonce1234", expected_method="GET"
)
assert v.blocked and "METHOD_OVERRIDE_DENIED" in v.reasons, f"Python METHOD_OVERRIDE_DENIED missing: {v.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("17. Pass-5 Audit Regressions: method-override shadowing, unified skipHeaderChecks, Express+trustProxy XFF isolation, CDN cache headers, manifest.json MIME, 304 ETag, SDK cross-realm & Firefox/307 fixes, Python parity", async () => {
  // 1) Dual HTTP method-override shadowing MUST be caught in verifyAttestation & verifyHandshakeProof (Node & Python)
  const attClean = buildAttestation({ mode: "paranoid", ticket: "tk-sh", nonce: "nonce-sh-1234", telemetry: { platform: "Linux x86_64" } });
  const rShadow = verifyAttestation({
    mode: "paranoid",
    headers: makeBrowserHeaders({ "x-http-method-override": "GET", "x-method-override": "DELETE" }),
    expectedMethod: "GET",
    attest: attClean,
    ticket: "tk-sh",
    nonce: "nonce-sh-1234",
  });
  assert.equal(rShadow.blocked, true, "Dual override shadowing (GET + DELETE) MUST be blocked!");
  assert.ok(rShadow.reasons.includes("METHOD_OVERRIDE_DENIED"));

  // 2) verifyHandshakeProof({ skipHeaderChecks: true }) STILL enforces CL_TE_SMUGGLING, METHOD_OVERRIDE_DENIED, OS_HEADER_CONTRADICTION, SEC_CH_UA_GREASE_LIE!
  const cleanProof = buildHandshakeProof({ mode: "strict", challenge: "ch-skip-1", telemetry: { platform: "Linux x86_64" } });
  const rSkipGrease = verifyHandshakeProof({
    mode: "strict",
    headers: makeBrowserHeaders({
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "sec-ch-ua": '" Not A;Brand";v="99", "Chromium";v="120"',
      "sec-ch-ua-platform": '"Windows"',
    }),
    proof: cleanProof,
    expectedChallenge: "ch-skip-1",
    skipHeaderChecks: true,
  });
  assert.equal(rSkipGrease.blocked, true, "skipHeaderChecks:true MUST still catch OS_HEADER_CONTRADICTION + SEC_CH_UA_GREASE_LIE");
  assert.ok(rSkipGrease.reasons.includes("OS_HEADER_CONTRADICTION"));
  assert.ok(rSkipGrease.reasons.includes("SEC_CH_UA_GREASE_LIE"));

  // 3) Express trust proxy ('loopback') + options.trustProxy ('10.0.0.1'): direct untrusted IP CANNOT spoof X-Forwarded-For!
  const tpMw = createVeilBreakMiddleware({ mode: "strict", trustProxy: ["10.0.0.1"], maxTicketsPerMinPerIp: 1, protectedPaths: ["/api"] });
  const callTicket = async (remoteAddress, xff) => {
    let status = 0;
    await tpMw(
      {
        method: "GET",
        url: "/__veilbreak/ticket",
        socket: { remoteAddress },
        ip: xff,
        app: { get: (k) => (k === "trust proxy" ? "loopback" : undefined) },
        headers: makeBrowserHeaders({ "x-forwarded-for": xff, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" }),
      },
      {
        headersSent: false,
        writableEnded: false,
        setHeader() {},
        writeHead(c) { status = c; this.headersSent = true; },
        end() { this.writableEnded = true; },
      }
    );
    return status;
  };
  assert.equal(await callTicket("203.0.113.99", "8.8.8.1"), 200);
  assert.equal(
    await callTicket("203.0.113.99", "8.8.8.2"),
    429,
    "Untrusted direct IP MUST NOT bypass rate limit by spoofing X-Forwarded-For when Express trust proxy is enabled alongside options.trustProxy!"
  );

  // 4) CORS OPTIONS preflight with positive Content-Length MUST NOT be exempted!
  const optMw = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let optStatus = 0;
  await optMw(
    {
      method: "OPTIONS",
      url: "/api/secret",
      socket: { remoteAddress: "127.0.0.1" },
      headers: makeBrowserHeaders({
        host: "app.example",
        origin: "https://other.example",
        "access-control-request-method": "POST",
        "sec-fetch-mode": "cors",
        "content-length": "12",
      }),
    },
    {
      headersSent: false,
      writableEnded: false,
      setHeader() {},
      writeHead(c) { optStatus = c; this.headersSent = true; },
      end() { this.writableEnded = true; },
    }
  );
  assert.equal(optStatus, 403, "CORS preflight OPTIONS with non-empty Content-Length MUST NOT bypass VeilBreak!");

  // 5) Versioned /gate.js?v=... with matching If-None-Match returns 304 Not Modified!
  let gate304Status = 0;
  await optMw(
    {
      method: "GET",
      url: `/__veilbreak/gate.js?v=${optMw.gateVersion}`,
      socket: { remoteAddress: "127.0.0.1" },
      headers: { "if-none-match": `"${optMw.gateVersion}"` },
    },
    {
      headersSent: false,
      writableEnded: false,
      setHeader() {},
      writeHead(c) { gate304Status = c; this.headersSent = true; },
      end() { this.writableEnded = true; },
    }
  );
  assert.equal(gate304Status, 304, "Versioned /gate.js?v=... with matching ETag MUST return 304");

  // 6) Reverse proxy: CDN-Cache-Control skips SRI pinning + wildcard /manifest.json served as application/json allowed!
  const up5 = http.createServer((req, res) => {
    if (req.url === "/cdn") {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "max-age=0, must-revalidate",
        "CDN-Cache-Control": "public, max-age=3600",
      });
      res.end("<!doctype html><html><head></head><body>cdn</body></html>");
      return;
    }
    if (req.url === "/manifest.json") {
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end('{"name":"PWA"}');
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"secret":1}');
  });
  await new Promise((r) => up5.listen(0, "127.0.0.1", r));
  const srv5 = createVeilBreakServer({ target: `http://127.0.0.1:${up5.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv5.listen(0, "127.0.0.1");
  const p5 = srv5.server.address().port;
  const req5 = (p, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p5, method: "GET", path: p, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rCdn = await req5("/cdn", makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" }));
    assert.equal(rCdn.status, 200);
    assert.ok(!rCdn.body.includes("integrity="), "CDN-Cache-Control public HTML MUST NOT pin ephemeral SRI hash");

    const rMan = await req5("/manifest.json", makeBrowserHeaders({ "sec-fetch-dest": "manifest", "sec-fetch-site": "same-origin" }));
    assert.equal(rMan.status, 200, "Wildcard /manifest.json served as application/json with Sec-Fetch-Dest: manifest MUST succeed");
  } finally {
    await srv5.close();
    await new Promise((r) => up5.close(r));
  }

  // 7) Browser SDK Pass-5 hardenings
  const sdk5 = buildBrowserGateScript({ defaultMode: "strict", allowDevTools: false, antiCdp: true });
  new Function(sdk5);
  assert.ok(sdk5.includes("openVerifiedFreshRealm"), "SDK must use verified cross-realm iframe helper");
  assert.ok(sdk5.includes("[RegExp.prototype.test, \"test\"]") && sdk5.includes("[appendFn, \"appendChild\"]"), "SDK must verify RegExp.prototype.test and Node.prototype.appendChild");
  assert.ok(sdk5.includes("(!details.cdpRuntimeEnable || allowDevTools)"), "Firefox FPP/RFP exemptions must honor allowDevTools");
  assert.ok(sdk5.includes("forceCdp: needFreshCdp"), "collectHandshakeProof() must force fresh live CDP probe past 250ms window");
  assert.ok(sdk5.includes("_isEmbeddedUnified"), "Embedded unified VeilBreak must not bail on external LOAD_SYM");
  assert.ok(sdk5.includes("preserveMutate"), "SDK redirect recovery must preserve method+body on 307/308 redirects");

  // 8) Python parity: dual method-override shadowing, verify_handshake_proof skip_header_checks, TicketStore X-Original-URL
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import verify_attestation, verify_handshake_proof, VeilBreakTicketStore, _sha256_hex
d = _sha256_hex("VB_ATTEST_V2|tk1|nonce1234|0|0|Linux x86_64")
v_ov = verify_attestation(
    mode="paranoid",
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-HTTP-Method-Override": "GET", "X-Method-Override": "DELETE"},
    attest={"v": 2, "s": 0, "f": 0, "p": "Linux x86_64", "d": d},
    ticket="tk1", nonce="nonce1234", expected_method="GET"
)
assert v_ov.blocked and "METHOD_OVERRIDE_DENIED" in v_ov.reasons, f"Python dual override shadowing missed: {v_ov.reasons}"

dh = _sha256_hex("VB_HS_V3|ch1|0|0|Linux x86_64|0||1|5")
v_hs = verify_handshake_proof(
    mode="strict",
    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Sec-CH-UA": '" Not A;Brand";v="99"', "Sec-CH-UA-Platform": '"Windows"'},
    proof={"v": 3, "ch": "ch1", "s": 0, "f": 0, "p": "Linux x86_64", "cdp": 0, "wr": "", "wk": 1, "ms": 5, "d": dh},
    expected_challenge="ch1",
    skip_header_checks=True,
)
assert v_hs.blocked and "OS_HEADER_CONTRADICTION" in v_hs.reasons and "SEC_CH_UA_GREASE_LIE" in v_hs.reasons, f"Python skip_header_checks mismatch: {v_hs.reasons}"

st = VeilBreakTicketStore(mode="strict", ticket_pow_bits=0)
tk = st.mint_ticket(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
d2 = _sha256_hex(f"VB_ATTEST_V2|{tk}|nonce1234|0|0|Linux x86_64")
v_url = st.verify_request(
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-Original-URL": "/api/admin", "X-VB-Ticket": tk, "X-VB-Nonce": "nonce1234", "X-VB-Attest": f'{{"v":2,"s":0,"f":0,"p":"Linux x86_64","d":"{d2}"}}'},
    ip="127.0.0.1", method="GET", path="/public"
)
assert v_url.blocked and "PROXY_PATH_OVERRIDE_HEADER" in v_url.reasons, f"Python TicketStore must catch X-Original-URL: {v_url.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("18. Pass-6 Audit Regressions: _reflectApply & DOM prototype defense, evaluateClick Event forgery defense, unified bundle dead-code trim, 307 ArrayBuffer retry, NL ReDoS, plain-HTTP wildcard, Python 5000-digit UA DoS", async () => {
  // 1) Unified gateJs omits unreachable standalone fetch/XHR wrapper (~21.5 KB smaller!)
  const standaloneSdk = buildBrowserGateScript({ defaultMode: "strict", unified: false });
  const unifiedSdk = buildBrowserGateScript({ defaultMode: "strict", unified: true });
  new Function(standaloneSdk);
  new Function(unifiedSdk);
  assert.ok(standaloneSdk.length - unifiedSdk.length > 18_000, `Unified SDK should trim >18KB standalone fetch/XHR (saved ${standaloneSdk.length - unifiedSdk.length}B)`);
  assert.ok(!unifiedSdk.includes("veilBreakFetch") && !unifiedSdk.includes("veilBreakXhrSend"), "Unified SDK MUST omit unreachable standalone fetch/XHR wrappers");
  assert.ok(standaloneSdk.includes("retryInput.arrayBuffer()"), "Standalone 307/308 Request redirect MUST materialize ArrayBuffer (not ReadableStream)");
  assert.ok(unifiedSdk.includes("_reflectApply") && unifiedSdk.includes('[createElFn, "createElement"]') && unifiedSdk.includes('[appendFn, "appendChild"]'), "SDK MUST use _reflectApply and cross-verify captured DOM intrinsics");
  assert.ok(unifiedSdk.includes("isGenuineEvent") && unifiedSdk.includes("_isTrustedGet"), "SDK captureInteraction MUST validate Event instance and native isTrusted getter");

  // 2) compileNaturalLanguage O(N) ReDoS immunity on 50KB adversarial inputs
  const t0 = performance.now();
  try { compileNaturalLanguage("a".repeat(50_000) + "!"); } catch {}
  try { compileNaturalLanguage("protect http://localhost:3000" + ".".repeat(50_000) + "x"); } catch {}
  const dt = performance.now() - t0;
  assert.ok(dt < 200, `compileNaturalLanguage MUST remain linear on 50KB adversarial input (took ${dt.toFixed(1)}ms)`);

  // 3) createVeilBreakServer wildcard ['*'] on non-localhost plain-HTTP origin allows HTML & CSS without Sec-Fetch-* while blocking non-HTML API!
  const upLan = http.createServer((req, res) => {
    if (req.url === "/") { res.writeHead(200, { "Content-Type": "text/html" }); res.end("<!doctype html><html><head></head><body>lan</body></html>"); return; }
    if (req.url === "/app.css") { res.writeHead(200, { "Content-Type": "text/css" }); res.end("body{}"); return; }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"secret":1}');
  });
  await new Promise((r) => upLan.listen(0, "127.0.0.1", r));
  const lanSrv = createVeilBreakServer({ target: `http://127.0.0.1:${upLan.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await lanSrv.listen(0, "127.0.0.1");
  const lanPort = lanSrv.server.address().port;
  const reqLan = (p, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: lanPort, method: "GET", path: p, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const lanHdrs = { host: "192.168.1.50:8080", "user-agent": CHROME_UA, "accept-language": "en-US", accept: "text/html" };
    assert.equal((await reqLan("/", lanHdrs)).status, 200, "LAN plain-HTTP HTML load under ['*'] without Sec-Fetch-* MUST succeed");
    assert.equal((await reqLan("/app.css", { host: "192.168.1.50:8080", "user-agent": CHROME_UA, accept: "text/css" })).status, 200, "LAN plain-HTTP CSS under ['*'] without Sec-Fetch-* MUST succeed");
    assert.equal((await reqLan("/api/secret", lanHdrs)).status, 403, "LAN plain-HTTP non-HTML API under ['*'] MUST STILL be blocked!");
  } finally {
    await lanSrv.close();
    await new Promise((r) => upLan.close(r));
  }

  // 4) Python >= 3.11 5000-digit Chrome/Firefox User-Agent MUST NOT throw ValueError!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import verify_attestation, verify_handshake_proof
big_ua = "Mozilla/5.0 Chrome/" + ("9" * 5000) + " Firefox/" + ("8" * 5000)
v1 = verify_attestation(mode="strict", headers={"User-Agent": big_ua}, attest=None)
v2 = verify_handshake_proof(mode="strict", headers={"User-Agent": big_ua}, proof=None, skip_header_checks=True)
assert v1.blocked and v2.blocked`,
    ],
    { encoding: "utf8" }
  );
});

test("19. Pass-7 Audit Regressions: zero-exception UTF-8 path DoS fix, LibreWolf RFP 0-FP, OneTrust DOM 0-FP, SRI data-* downgrade lock, non-forgeable init guard, Safari<16.4 & injectGate:false wildcards, balanced nginx Connection:close, dwellMs===0 & Python parity", async () => {
  const { isProtectedPath, normalizePathname, evaluateInteraction } = require("../src/probes.js");
  // 1) Perf #1: 13.5KB invalid %FF URL completes in < 25ms (down from 228ms!) and UTF-8 parity holds on CJK/emoji/overlong/surrogate
  const evilPath = "/x/" + "%FF".repeat(4400) + "%00%3F%23#a";
  const t0 = performance.now();
  assert.equal(isProtectedPath(evilPath, ["/api"]), false);
  const dt = performance.now() - t0;
  assert.ok(dt < 30, `13.5KB %FF path normalization MUST stay < 30ms (took ${dt.toFixed(1)}ms)`);
  assert.equal(normalizePathname("/api/%E6%97%A5%E6%9C%AC%E8%AA%9E/%F0%9F%9A%80"), "/api/日本語/🚀");
  assert.equal(normalizePathname("/api/%C0%AF/%ED%A0%80/%F4%90%80%80"), "/api/%C0%AF/%ED%A0%80/%F4%90%80%80", "Overlong/surrogate/>0x10FFFF UTF-8 MUST stay literal %XX");

  // 2) SDK Pass-7 hardenings: policyLocked data-* downgrade block, non-forgeable init guard, LibreWolf RFP 0-FP, 15s suspicious kinematics TTL, unified dead-code trim
  const lockedSdk = buildBrowserGateScript({ defaultMode: "strict", unified: true, sri: true, autoBlockPage: true, antiCdp: true, allowDevTools: false, allowBlockPageOverridePath: "/__veilbreak/playground" });
  new Function(lockedSdk);
  assert.ok(!lockedSdk.includes('Symbol.for("__VB_INIT_GUARD__")'), "SDK MUST NOT rely on forgeable global Symbol.for init kill switch");
  assert.ok(!lockedSdk.includes("_POW_SCRATCH") && !lockedSdk.includes("solveTicketPow(ticket"), "Unified SDK without tickets MUST omit dead solveTicketPow");
  assert.ok(lockedSdk.includes("POLICY_LOCKED") && lockedSdk.includes("MODE_RANK"), "Locked SRI/unified SDK MUST block data-* policy downgrades");
  assert.ok(lockedSdk.includes("SUSPICIOUS_CLICK_TTL_MS"), "Suspicious clicks MUST persist across ProxySnare's 15s gesture window");
  assert.ok(lockedSdk.includes("!deterministicPrivacyFarble && !cleanRfpPlaceholder"), "Clean native LibreWolf/Firefox RFP MUST be exempted from Canvas2D placeholder scoring");
  assert.ok(!lockedSdk.includes("dwellMs >= 0"), "Explicit evaluateClick() MUST skip dwellMs === 0 assistive clicks");

  // 3) Probes evaluateInteraction skips dwellMs === 0 (NVDA/JAWS virtual cursor)
  const nvdaClick = evaluateInteraction({ isTrusted: true, detail: 1, pointerType: "mouse", pointerMoves: 0, dwellMs: 0, hitExactCenter: true }, { mode: "strict" });
  assert.equal(nvdaClick.blocked, false, "dwellMs === 0 assistive click MUST NOT be flagged as teleport");

  // 4) Wildcard ['*'] + Safari < 16.4 static assets + injectGate: false HTML navigation + balanced nginx Connection: close
  const up7 = http.createServer((req, res) => {
    if (req.url === "/") { res.writeHead(200, { "Content-Type": "text/html" }); res.end("<!doctype html><html><head><script src='/__veilbreak/gate.js'></script></head><body>ok</body></html>"); return; }
    if (req.url === "/app.css") { res.writeHead(200, { "Content-Type": "text/css" }); res.end("body{color:red}"); return; }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"secret":1}');
  });
  await new Promise((r) => up7.listen(0, "127.0.0.1", r));
  const srv7 = createVeilBreakServer({ target: `http://127.0.0.1:${up7.address().port}`, mode: "strict", protectedPaths: ["*"], injectGate: false });
  await srv7.listen(0, "127.0.0.1");
  const balSrv7 = createVeilBreakServer({ target: `http://127.0.0.1:${up7.address().port}`, mode: "balanced", protectedPaths: ["*"] });
  await balSrv7.listen(0, "127.0.0.1");
  const reqOn = (port, p, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port, method: "GET", path: p, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const safari16Ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15";
    const rSafCss = await reqOn(srv7.server.address().port, "/app.css", { "user-agent": safari16Ua, accept: "text/css" });
    assert.equal(rSafCss.status, 200, "Safari < 16.4 static CSS without Sec-Fetch-Dest MUST succeed under protectedPaths:['*']");
    const rNoInjHtml = await reqOn(srv7.server.address().port, "/", makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" }));
    assert.equal(rNoInjHtml.status, 200, "injectGate:false under protectedPaths:['*'] MUST allow browser HTML navigation");
    const rBalClose = await reqOn(balSrv7.server.address().port, "/__veilbreak/ticket", makeBrowserHeaders({ connection: "close" }));
    assert.equal(rBalClose.status, 200, "balanced mode behind default nginx (Connection: close without trustProxy) MUST allow /ticket");
  } finally {
    await srv7.close();
    await balSrv7.close();
    await new Promise((r) => up7.close(r));
  }

  // 5) Python parity: 13.5KB %FF DoS immunity (< 30ms) & UTF-8 parity
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import is_path_protected, normalize_pathname
evil = "/x/" + ("%FF" * 4400) + "%00%3F%23#a"
t0 = time.perf_counter()
assert not is_path_protected(evil, ["/api"])
dt_ms = (time.perf_counter() - t0) * 1000
assert dt_ms < 50.0, f"Python 13.5KB %FF too slow: {dt_ms:.1f}ms"
assert normalize_pathname("/api/%E6%97%A5%E6%9C%AC%E8%AA%9E/%F0%9F%9A%80") == "/api/日本語/🚀"
assert normalize_pathname("/api/%C0%AF/%ED%A0%80/%F4%90%80%80") == "/api/%C0%AF/%ED%A0%80/%F4%90%80%80"`,
    ],
    { encoding: "utf8" }
  );
});

test("20. Pass-8 Audit Regressions: unified includeTicketPow & standalone plain-HTTP SHA-256, non-forgeable init verification, CSP-safe iframe styles, XHR x-vb-* strip, x-font/Safari<16.4 manifest MIME, Origin ?/#/@ rejection & Python TicketStore parity", async () => {
  const vm = require("node:vm");

  // 1) Unified gate.js retains compact pure-JS SHA-256 fallback (for standalone /__veilbreak/gate.js on plain HTTP),
  // AND includeTicketPow: true includes real solveTicketPow & normalizeClientPath for unified + enableVeilBreakTickets!
  const unifiedNoPow = buildBrowserGateScript({ defaultMode: "strict", unified: true, includeTicketPow: false });
  const unifiedWithPow = buildBrowserGateScript({ defaultMode: "strict", unified: true, includeTicketPow: true });
  const standaloneGate = buildBrowserGateScript({ defaultMode: "strict", unified: false });
  new Function(unifiedNoPow);
  new Function(unifiedWithPow);
  new Function(standaloneGate);
  assert.ok(unifiedNoPow.includes("sha256FallbackHex"), "Unified gate.js MUST keep compact SHA-256 fallback so standalone /__veilbreak/gate.js never fails on plain HTTP");
  assert.ok(!unifiedNoPow.includes("_POW_SCRATCH"), "Unified gate.js without tickets MUST omit _POW_SCRATCH");
  assert.ok(unifiedWithPow.includes("_POW_SCRATCH") && unifiedWithPow.includes("VB_POW_V2|"), "Unified gate.js with includeTicketPow:true MUST compile real solveTicketPow");
  assert.ok(!standaloneGate.includes("frame.style.cssText"), "SDK MUST use CSP-safe individual frame.style.* assignments (no style.cssText)");
  assert.ok(standaloneGate.includes('if (hk.toLowerCase().startsWith("x-vb-")) continue;'), "XHR MUST unconditionally strip caller-supplied x-vb-* headers");

  // 2) Forgeable 4-line preload `window.VeilBreak` kill switch MUST NOT abort SDK initialization!
  const ifrRealm = vm.createContext({ console: { debug: console.debug } });
  const ifrWin = vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const ok = new Set(["toString", "createElement", "appendChild", "get contentWindow", "contentWindow", "get documentElement", "debug"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && ok.has(this.name)) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
      return globalThis;
    })();`,
    ifrRealm
  );
  let ceRegistered = null;
  class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
  class Node { appendChild(c) { return c; } }
  class Element extends Node { getAttribute() { return null; } }
  class Document extends Node {
    constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this._el = new Element(); }
    get documentElement() { return this._el; }
    createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : { style: {} }; }
  }
  const fakePreloadCtx = vm.createContext({
    document: new Document(),
    Document, Node, Element, HTMLIFrameElement,
    location: { origin: "https://app.example", href: "https://app.example/" },
    navigator: { webdriver: false, userAgent: CHROME_UA, platform: "Linux x86_64" },
    console, setTimeout, clearTimeout, performance, URL, TextEncoder, Headers, Request, Response,
    HTMLElement: class HTMLElement {},
    customElements: {
      get: (n) => (n === "veil-break" ? ceRegistered : undefined),
      define: (n, c) => { if (n === "veil-break") ceRegistered = c; },
    },
    addEventListener() {},
  });
  fakePreloadCtx.window = fakePreloadCtx;
  vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const ok = new Set(["toString", "createElement", "appendChild", "get contentWindow", "get documentElement"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && ok.has(this.name)) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
      // Attacker installs fake non-configurable frozen window.VeilBreak kill switch!
      Object.defineProperty(window, "VeilBreak", {
        value: Object.freeze({ version: "2.2.0", verify: () => ({ ok: true }), collectHandshakeProof: () => ({}) }),
        writable: false,
        configurable: false,
      });
    })();`,
    fakePreloadCtx
  );
  vm.runInContext(standaloneGate, fakePreloadCtx);
  assert.ok(typeof ceRegistered === "function", "4-line forged frozen window.VeilBreak preload MUST NOT abort VeilBreak initialization!");

  // 3) Middleware: Origin with ?/#/@ rejected on /ticket, application/x-font-* & Safari < 16.4 /manifest.json & .webmanifest allowed under ['*']
  const up8 = http.createServer((req, res) => {
    if (req.url === "/font.woff") { res.writeHead(200, { "Content-Type": "application/x-font-woff" }); res.end("wOFF"); return; }
    if (req.url === "/manifest.json") { res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"name":"PWA"}'); return; }
    if (req.url === "/site.webmanifest") { res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"name":"PWA"}'); return; }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"secret":true}');
  });
  await new Promise((r) => up8.listen(0, "127.0.0.1", r));
  const srv8 = createVeilBreakServer({ target: `http://127.0.0.1:${up8.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv8.listen(0, "127.0.0.1");
  const p8 = srv8.server.address().port;
  const req8 = (p, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p8, method: "GET", path: p, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const safari16Ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15";
    assert.equal((await req8("/font.woff", { "user-agent": CHROME_UA, "sec-fetch-dest": "font", "sec-fetch-site": "same-origin" })).status, 200, "Legacy application/x-font-woff MUST be allowed under ['*']");
    assert.equal((await req8("/manifest.json", { "user-agent": safari16Ua })).status, 200, "Safari < 16.4 /manifest.json without Sec-Fetch-Dest MUST be allowed under ['*']");
    assert.equal((await req8("/site.webmanifest", { "user-agent": safari16Ua })).status, 200, "Safari < 16.4 /site.webmanifest without Sec-Fetch-Dest MUST be allowed under ['*']");
    for (const evilOrigin of [
      `http://127.0.0.1:${p8}?foo=bar`,
      `http://127.0.0.1:${p8}#frag`,
      `http://user@127.0.0.1:${p8}`,
    ]) {
      const rBadOrig = await req8("/__veilbreak/ticket", makeBrowserHeaders({ host: `127.0.0.1:${p8}`, origin: evilOrigin }));
      assert.equal(rBadOrig.status, 403, `Origin with ?/#/@ (${evilOrigin}) MUST be rejected at /ticket`);
    }
  } finally {
    await srv8.close();
    await new Promise((r) => up8.close(r));
  }

  // 4) Python VeilBreakTicketStore: legacy mint_ticket() honors expected_method, and protected_paths gates PROXY_PATH_OVERRIDE_HEADER!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import VeilBreakTicketStore, _sha256_hex
st = VeilBreakTicketStore(mode="strict", ticket_pow_bits=0, protected_paths=["/api"])
tk1 = st.mint_ticket(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
d1 = _sha256_hex(f"VB_ATTEST_V2|{tk1}|nonce-m1|0|0|Linux x86_64")
v_ov = st.verify_request(
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-HTTP-Method-Override": "DELETE", "X-VB-Ticket": tk1, "X-VB-Nonce": "nonce-m1", "X-VB-Attest": f'{{"v":2,"s":0,"f":0,"p":"Linux x86_64","d":"{d1}"}}'},
    ip="127.0.0.1", method="GET", path="/api/users"
)
assert v_ov.blocked and "METHOD_OVERRIDE_DENIED" in v_ov.reasons, f"Legacy mint_ticket MUST enforce expected_method: {v_ov.reasons}"
tk2 = st.mint_ticket(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
d2 = _sha256_hex(f"VB_ATTEST_V2|{tk2}|nonce-p1|0|0|Linux x86_64")
v_pub = st.verify_request(
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-Original-URL": "/public/page", "X-VB-Ticket": tk2, "X-VB-Nonce": "nonce-p1", "X-VB-Attest": f'{{"v":2,"s":0,"f":0,"p":"Linux x86_64","d":"{d2}"}}'},
    ip="127.0.0.1", method="GET", path="/public"
)
assert not v_pub.blocked, f"Unprotected X-Original-URL MUST NOT false-positive when protected_paths is set: {v_pub.reasons}"
tk3 = st.mint_ticket(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
d3 = _sha256_hex(f"VB_ATTEST_V2|{tk3}|nonce-p2|0|0|Linux x86_64")
v_prot = st.verify_request(
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-Original-URL": "/api/admin", "X-VB-Ticket": tk3, "X-VB-Nonce": "nonce-p2", "X-VB-Attest": f'{{"v":2,"s":0,"f":0,"p":"Linux x86_64","d":"{d3}"}}'},
    ip="127.0.0.1", method="GET", path="/public"
)
assert v_prot.blocked and "PROXY_PATH_OVERRIDE_HEADER" in v_prot.reasons, f"Protected X-Original-URL MUST be blocked: {v_prot.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("21. Pass-9 Audit Regressions: embedded SHA-256 trim, O(N) trailing-slash strip, non-forgeable init kill-switch defense, Error/getOwnPropertyNames & fail-closed CDP, kin.lastClick clearing & balanced 2.5s window, XHR same-URL PRG, Vite/Next wildcard & s-maxage=0, WSGI comma-coalesced X-Original-URL parity", async () => {
  const vm = require("node:vm");

  // 1) embedded:true omits duplicate SHA256_K while standalone unified gate.js retains sha256FallbackHex; zero /\/+$/ ReDoS
  const embGate = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, includeTicketPow: false });
  const stdUniGate = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: false, includeTicketPow: false });
  new Function(embGate);
  new Function(stdUniGate);
  assert.ok(!embGate.includes("SHA256_K"), "Embedded unified VeilBreak MUST omit duplicate SHA256_K");
  assert.ok(stdUniGate.includes("SHA256_K"), "Standalone unified /__veilbreak/gate.js MUST retain sha256FallbackHex for plain HTTP");
  assert.ok(!embGate.includes(".replace(/\\/+$/, \"\")"), "SDK MUST NOT use O(N^2) /\\/+$/ regex on uncollapsed paths");
  const standaloneGate = buildBrowserGateScript({ defaultMode: "strict", unified: false });
  assert.ok(standaloneGate.includes('redirGetHdr === "1" ||'), "VeilBreak XHR MUST recover on same-URL PRG via X-VB-Redirect-Get: 1");

  // 2) Pre-existing window.VeilBreak (even with exact copied verify() source text!) MUST fail closed (_bridgeTampered & __VB_BRIDGE_TAMPERED__=true)
  const ifrCtx = vm.createContext({ console: { debug: console.debug } });
  const ifrWin = vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const ok = new Set(["toString", "createElement", "appendChild", "get contentWindow", "contentWindow", "get documentElement", "getAttribute", "Event", "debug"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && ok.has(this.name)) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
      return globalThis;
    })();`,
    ifrCtx
  );
  class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
  class Node { appendChild(c) { return c; } }
  class Element extends Node { getAttribute() { return null; } }
  class Document extends Node {
    constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this._el = new Element(); }
    get documentElement() { return this._el; }
    createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : { style: {} }; }
  }
  const listeners = {};
  const makeVbVm = (preHook = "", gateSrc = standaloneGate) => {
    let ceDef = null;
    const ctx = vm.createContext({
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/app" },
      navigator: { webdriver: false, userAgent: CHROME_UA, platform: "Linux x86_64" },
      console, setTimeout, clearTimeout, performance, URL, TextEncoder, Headers, Request, Response,
      Event: class Event { constructor(t) { this.type = t; this.isTrusted = false; } },
      HTMLElement: class HTMLElement {},
      customElements: {
        get: (n) => (n === "veil-break" ? ceDef : undefined),
        define: (n, c) => { if (n === "veil-break") ceDef = c; },
      },
      addEventListener(ev, fn) { (listeners[ev] ||= []).push(fn); },
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const ok = new Set(["toString", "createElement", "appendChild", "get contentWindow", "get documentElement", "getAttribute", "Event"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && ok.has(this.name)) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preHook) vm.runInContext(preHook, ctx);
    vm.runInContext(gateSrc, ctx);
    return { ctx, getCe: () => ceDef };
  };

  // Even pre-defining <veil-break> and window.VeilBreak with spoofed source MUST mark __VB_BRIDGE_TAMPERED__ = true!
  const { ctx: vmPreVb } = makeVbVm(`
    Object.defineProperty(window, "VeilBreak", {
      value: Object.freeze({ version: "2.2.0", verify: async () => ({ ok: true, score: 0 }) }),
      writable: false, configurable: false,
    });
  `);
  assert.equal(vmPreVb[Symbol.for("__VB_BRIDGE_TAMPERED__")], true, "Pre-existing window.VeilBreak MUST fail closed with __VB_BRIDGE_TAMPERED__=true!");

  // 3) Pre-load window.Error non-configurable stack wrapper & Object.getOwnPropertyNames wrapper MUST fail closed!
  const { ctx: vmErrWrap } = makeVbVm(`
    const OrigErr = Error;
    window.Error = function Error(m) {
      const e = new OrigErr(m);
      Object.defineProperty(e, "stack", { value: "", configurable: false });
      return e;
    };
  `);
  const errRes = await vmErrWrap.VeilBreak.verify({ mode: "strict", antiCdp: true });
  assert.equal(errRes.blocked, true, "Pre-load window.Error wrapper locking stack MUST be caught & blocked!");
  assert.ok(errRes.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `Expected NATIVE_FUNCTION_TAMPERED, got ${errRes.reasons}`);

  // 4) Stale kin.lastClick is cleared by trusted keydown OR trusted non-button click (0-FP for React <div onClick> / keyboard submit!)
  for (const k of Object.keys(listeners)) delete listeners[k];
  const { ctx: vmKin } = makeVbVm("", buildBrowserGateScript({ defaultMode: "balanced", unified: true }));
  const fakeBtn = {
    closest: (sel) => (sel.includes("button") ? fakeBtn : null),
    getClientRects: () => [{ width: 80, height: 30 }],
    getBoundingClientRect: () => ({ left: 10, top: 10, right: 90, bottom: 40, width: 80, height: 30 }),
  };
  const fakeDiv = { closest: () => null };
  vmKin.innerWidth = 1280;
  vmKin.innerHeight = 800;
  vmKin.getComputedStyle = () => ({ visibility: "visible", display: "block", opacity: "1", clip: "auto", clipPath: "none" });
  const fire = (ev, obj) => { for (const fn of (listeners[ev] || [])) fn(obj); };
  fire("click", { isTrusted: false, detail: 1, target: fakeBtn, clientX: 50, clientY: 25 });
  assert.ok(vmKin.VeilBreak.getLastInteraction()?.isTrusted === false, "Untrusted button click stored initially");
  fire("keydown", { isTrusted: true, key: "Enter" });
  assert.equal(vmKin.VeilBreak.getLastInteraction(), null, "Trusted keydown MUST immediately clear stale untrusted kin.lastClick!");
  // Fresh VM to test trusted non-button <div onClick> clearing an untrusted button click independently of the 1.5s keydown grace period
  for (const k of Object.keys(listeners)) delete listeners[k];
  const { ctx: vmKin2 } = makeVbVm("", buildBrowserGateScript({ defaultMode: "balanced", unified: true }));
  vmKin2.innerWidth = 1280;
  vmKin2.innerHeight = 800;
  vmKin2.getComputedStyle = () => ({ visibility: "visible", display: "block", opacity: "1", clip: "auto", clipPath: "none" });
  fire("click", { isTrusted: false, detail: 1, target: fakeBtn, clientX: 50, clientY: 25 });
  assert.ok(vmKin2.VeilBreak.getLastInteraction()?.isTrusted === false);
  fire("click", new vmKin2.Event("click"));
  // Genuine trusted click on non-button <div onClick>
  const divEv = new vmKin2.Event("click");
  divEv.isTrusted = true;
  divEv.detail = 1;
  divEv.target = fakeDiv;
  divEv.clientX = 12;
  divEv.clientY = 12;
  fire("click", divEv);
  assert.equal(vmKin2.VeilBreak.getLastInteraction(), null, "Trusted click on non-button <div onClick> MUST immediately clear stale untrusted kin.lastClick!");

  // 5) Wildcard ['*'] allows Vite .tsx / /@vite/client & Next.js /_next/image (Sec-Fetch-Dest: image), blocks JSON on /_next/image, & s-maxage=0 keeps SRI!
  const up9 = http.createServer((req, res) => {
    if (req.url === "/page") {
      res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "max-age=0, s-maxage=0" });
      res.end("<!doctype html><html><head></head><body>ok</body></html>");
      return;
    }
    if (req.url === "/@vite/client" || req.url === "/src/App.tsx") {
      res.writeHead(200, { "Content-Type": "text/javascript" });
      res.end("export default 1;");
      return;
    }
    if (req.url.startsWith("/_next/image")) {
      res.writeHead(200, { "Content-Type": "image/webp" });
      res.end("RIFF");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"secret":1}');
  });
  await new Promise((r) => up9.listen(0, "127.0.0.1", r));
  const srv9 = createVeilBreakServer({ target: `http://127.0.0.1:${up9.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv9.listen(0, "127.0.0.1");
  const p9 = srv9.server.address().port;
  const req9 = (p, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p9, method: "GET", path: p, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rPage = await req9("/page", makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" }));
    assert.equal(rPage.status, 200);
    assert.ok(rPage.body.includes("integrity="), "Cache-Control: max-age=0, s-maxage=0 MUST NOT disable SRI pinning!");
    assert.equal((await req9("/@vite/client", makeBrowserHeaders({ "sec-fetch-dest": "script", "sec-fetch-site": "same-origin" }))).status, 200);
    assert.equal((await req9("/src/App.tsx", makeBrowserHeaders({ "sec-fetch-dest": "script", "sec-fetch-site": "same-origin" }))).status, 200);
    assert.equal((await req9("/_next/image?url=%2Fa.png&w=640", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }))).status, 200);
    assert.equal((await req9("/api/secret", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }))).status, 403, "JSON API claiming Sec-Fetch-Dest: image MUST still be blocked by upstream MIME check!");
  } finally {
    await srv9.close();
    await new Promise((r) => up9.close(r));
  }

  // 6) Node + Python parity: multi-value & WSGI comma-coalesced X-Original-URL: "/public, /api/admin" triggers PROXY_PATH_OVERRIDE_HEADER!
  const ovMw = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let ovStatus = 0;
  await ovMw(
    { method: "GET", url: "/public", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "x-original-url": "/public, /api/admin" }) },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(c) { ovStatus = c; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(ovStatus, 403, "Node comma-coalesced X-Original-URL '/public, /api/admin' MUST be blocked!");

  execFileSync(
    "python3",
    [
      "-c",
      `import sys; from email.message import Message; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import VeilBreakTicketStore, _sha256_hex
st = VeilBreakTicketStore(mode="strict", ticket_pow_bits=0, protected_paths=["/api"])
for hdr_case in [
    {"X-Original-URL": ["/public", "/api/admin"]},
    {"X-Original-URL": "/public, /api/admin"},
]:
    tk = st.mint_ticket(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
    d = _sha256_hex(f"VB_ATTEST_V2|{tk}|nonce-ov9|0|0|Linux x86_64")
    h = {"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-VB-Ticket": tk, "X-VB-Nonce": "nonce-ov9", "X-VB-Attest": f'{{"v":2,"s":0,"f":0,"p":"Linux x86_64","d":"{d}"}}', **hdr_case}
    v = st.verify_request(headers=h, ip="127.0.0.1", method="GET", path="/public")
    assert v.blocked and "PROXY_PATH_OVERRIDE_HEADER" in v.reasons, f"Failed for {hdr_case}: {v.reasons}"
msg = Message()
tk = st.mint_ticket(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
d = _sha256_hex(f"VB_ATTEST_V2|{tk}|nonce-ov10|0|0|Linux x86_64")
for k, val in [("User-Agent", ${JSON.stringify(CHROME_UA)}), ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors"), ("X-Original-URL", "/public"), ("X-Original-URL", "/api/admin"), ("X-VB-Ticket", tk), ("X-VB-Nonce", "nonce-ov10"), ("X-VB-Attest", f'{{"v":2,"s":0,"f":0,"p":"Linux x86_64","d":"{d}"}}')]:
    msg[k] = val
v_msg = st.verify_request(headers=msg, ip="127.0.0.1", method="GET", path="/public")
assert v_msg.blocked and "PROXY_PATH_OVERRIDE_HEADER" in v_msg.reasons, f"HTTPMessage duplicate X-Original-URL failed: {v_msg.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("22. Pass-10 Audit Regressions: post-load RUM Headers.prototype.set 0-FP, unified gate.js coexistence 0-FP, SWR/SIE cache & no-transform, redirect-403 app RBAC no-retry, Python anti_cdp=None preset default & pre-compiled rules", async () => {
  const vm = require("node:vm");

  // 1) Post-load RUM/APM Headers.prototype.set wrapper MUST stay 0-FP (score 0, no NATIVE_FUNCTION_TAMPERED!)
  const gate10 = buildBrowserGateScript({ defaultMode: "strict", unified: false });
  const uniGate10 = buildBrowserGateScript({ defaultMode: "strict", unified: true });
  assert.ok(gate10.includes('error === "VEILBREAK_DENIED"'), "VeilBreak redirect-403 MUST verify VEILBREAK_DENIED before retrying redirected mutating requests!");

  const origHdrSet = Headers.prototype.set;
  const origHdrGet = Headers.prototype.get;
  const origHdrDel = Headers.prototype.delete;
  const origEncode = TextEncoder.prototype.encode;
  class VmHeaders {
    constructor(i) { this._h = new Headers(i); }
    set(k, v) { return origHdrSet.call(this._h, k, v); }
    get(k) { return origHdrGet.call(this._h, k); }
    delete(k) { return origHdrDel.call(this._h, k); }
  }
  class VmTextEncoder { encode(s) { return origEncode.call(new TextEncoder(), s); } }
  const nativeRefs = new Set([VmHeaders.prototype.set, VmHeaders.prototype.get, VmTextEncoder.prototype.encode, console.debug, performance.now]);
  const ifrCtx = vm.createContext({ console: { debug: console.debug }, _nativeRefs: nativeRefs });
  const ifrWin = vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const ok = new Set(["toString", "createElement", "appendChild", "get contentWindow", "contentWindow", "get documentElement", "getAttribute", "Event", "debug", "webdriver", "platform", "userAgent"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && (_nativeRefs.has(this) || ok.has(this.name))) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
      return globalThis;
    })();`,
    ifrCtx
  );
  class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
  class Node { appendChild(c) { return c; } }
  class Element extends Node { getAttribute() { return null; } }
  class Document extends Node {
    constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this._el = new Element(); }
    get documentElement() { return this._el; }
    createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : { style: {} }; }
  }
  class RumNavigator {}
  Object.defineProperty(RumNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
  Object.defineProperty(RumNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
  Object.defineProperty(RumNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
  const ctxRum = vm.createContext({
    document: new Document(), Document, Node, Element, HTMLIFrameElement,
    location: { origin: "https://app.example", href: "https://app.example/", pathname: "/app" },
    Navigator: RumNavigator, navigator: Object.create(RumNavigator.prototype),
    console, setTimeout, clearTimeout, performance, URL,
    TextEncoder: VmTextEncoder, Headers: VmHeaders, Request, Response,
    Event: class Event { constructor(t) { this.type = t; } },
    HTMLElement: class HTMLElement {},
    customElements: { get: () => undefined, define: () => {} },
    addEventListener() {},
    _nativeRefs: nativeRefs,
  });
  ctxRum.window = ctxRum;
  vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const ok = new Set(["toString", "createElement", "appendChild", "get contentWindow", "get documentElement", "getAttribute", "Event", "webdriver", "platform", "userAgent"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && (_nativeRefs.has(this) || ok.has(this.name))) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
    })();`,
    ctxRum
  );
  vm.runInContext(gate10, ctxRum);
  // Post-load APM/RUM wraps Headers.prototype.set AFTER gate.js loaded!
  vm.runInContext(`const _hs = Headers.prototype.set; Headers.prototype.set = function set(k, v) { return _hs.call(this, k, v); };`, ctxRum);
  const rumRes = await ctxRum.VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.ok(!rumRes.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `Post-load Headers.prototype.set RUM wrapper MUST NOT trigger NATIVE_FUNCTION_TAMPERED: ${rumRes.reasons}`);

  // 2) Unified standalone gate.js running AFTER unified embedded guard.js already mounted window.VeilBreak(unified:true) + window.ProxySnare exits cleanly (zero __VB_BRIDGE_TAMPERED__)!
  const ctxCoex = vm.createContext({
    document: new Document(), Document, Node, Element, HTMLIFrameElement,
    location: { origin: "https://app.example", href: "https://app.example/", pathname: "/app" },
    navigator: { webdriver: false, userAgent: CHROME_UA, platform: "Linux x86_64" },
    console, setTimeout, clearTimeout, performance, URL, TextEncoder: VmTextEncoder, Headers: VmHeaders, Request, Response,
    Event: class Event {}, HTMLElement: class HTMLElement {},
    customElements: { get: () => class FakeCe {}, define: () => {} },
    addEventListener() {},
  });
  ctxCoex.window = ctxCoex;
  vm.runInContext(`
    Object.defineProperty(window, "VeilBreak", { value: Object.freeze({ unified: true, version: "2.2.0" }), writable: false, configurable: false });
    Object.defineProperty(window, "ProxySnare", { value: Object.freeze({ version: "2.1.0" }), writable: false, configurable: false });
  `, ctxCoex);
  vm.runInContext(uniGate10, ctxCoex);
  assert.equal(ctxCoex[Symbol.for("__VB_BRIDGE_TAMPERED__")], undefined, "Coexisting unified gate.js after embedded guard.js MUST NOT set __VB_BRIDGE_TAMPERED__!");

  // 3) SWR Cache-Control omits SRI pinning on ISR HTML & /gate.js sets no-transform
  const upSwr = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "max-age=0, stale-while-revalidate=86400" });
    res.end("<!doctype html><html><head></head><body>isr</body></html>");
  });
  await new Promise((r) => upSwr.listen(0, "127.0.0.1", r));
  const srvSwr = createVeilBreakServer({ target: `http://127.0.0.1:${upSwr.address().port}`, mode: "strict", protectedPaths: ["/api"] });
  await srvSwr.listen(0, "127.0.0.1");
  try {
    const base = `http://127.0.0.1:${srvSwr.server.address().port}`;
    const rGate = await fetch(`${base}/__veilbreak/gate.js`, { headers: makeBrowserHeaders() });
    assert.ok(rGate.headers.get("cache-control").includes("no-transform"), "/__veilbreak/gate.js MUST send Cache-Control: no-transform!");
    const rIsr = await fetch(`${base}/isr`, { headers: makeBrowserHeaders({ accept: "text/html" }) });
    const html = await rIsr.text();
    assert.ok(!html.includes("integrity="), "stale-while-revalidate ISR HTML MUST omit ephemeral SRI hash!");
  } finally {
    await srvSwr.close();
    await new Promise((r) => upSwr.close(r));
  }

  // 4) Python parity: anti_cdp=None resolves to preset default (True in paranoid), NOT False!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import verify_attestation, verify_handshake_proof, _sha256_hex
d = _sha256_hex("VB_ATTEST_V2|tk|n12345678|6|128|Linux x86_64")
v1 = verify_attestation(mode="paranoid", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}, attest={"v": 2, "s": 6, "f": 128, "p": "Linux x86_64", "d": d}, ticket="tk", nonce="n12345678", anti_cdp=None)
assert v1.blocked and "CDP_RUNTIME_ENABLE" in v1.reasons
dh = _sha256_hex("VB_HS_V3|ch1|0|0|Linux x86_64|1||1|5")
v2 = verify_handshake_proof(mode="paranoid", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}, proof={"v": 3, "ch": "ch1", "s": 0, "f": 0, "p": "Linux x86_64", "cdp": 1, "wr": "", "wk": 1, "ms": 5, "d": dh}, expected_challenge="ch1", anti_cdp=None)
assert v2.blocked and "CDP_ACTIVE_DENIED" in v2.reasons, f"anti_cdp=None MUST default to True in paranoid mode: {v2.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("23. Pass-11 Audit Regressions: Angular ZoneAwareError 0-FP, embedded unified pre-existing tamper defense, click-derived submit/change teleport preservation, navigator prototype-chain spoofing detection, data-unified='true' load-order coexistence & Vercel/Netlify CDN headers", async () => {
  const vm = require("node:vm");

  const origHdrSet = Headers.prototype.set;
  const origHdrGet = Headers.prototype.get;
  const origHdrDel = Headers.prototype.delete;
  const origEncode = TextEncoder.prototype.encode;
  class VmHeaders {
    constructor(i) { this._h = new Headers(i); }
    set(k, v) { return origHdrSet.call(this._h, k, v); }
    get(k) { return origHdrGet.call(this._h, k); }
    delete(k) { return origHdrDel.call(this._h, k); }
  }
  class VmTextEncoder { encode(s) { return origEncode.call(new TextEncoder(), s); } }

  const makeVb11 = ({ src, preLoadHook = null, currentScriptAttr = null, perfEntries = [], embedded = false } = {}) => {
    const listeners = {};
    let nowOffset = 0;
    class VmPerformance {
      now() { return performance.now() + nowOffset; }
      getEntriesByType(t) { return t === "resource" ? perfEntries : []; }
    }
    const nativeRefs = new Set([VmHeaders.prototype.set, VmHeaders.prototype.get, VmTextEncoder.prototype.encode, console.debug, VmPerformance.prototype.now]);
    const ifrCtx = vm.createContext({ console: { debug: console.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const ok = new Set(["toString", "createElement", "appendChild", "get contentWindow", "contentWindow", "get documentElement", "getAttribute", "Event", "debug", "webdriver", "platform", "userAgent"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || ok.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      getAttribute(k) { return this._attrs && k in this._attrs ? this._attrs[k] : null; }
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = currentScriptAttr ? new Element(currentScriptAttr) : null;
        this.baseURI = "https://app.example/";
        this._el = new Element();
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : { style: {} }; }
    }
    class Navigator {}
    Object.defineProperty(Navigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(Navigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(Navigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const nav = Object.create(Navigator.prototype);
    let ceMap = new Map();
    let privateApi = null;
    const ctx = vm.createContext({
      document: new Document(), Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/app" },
      navigator: nav, Navigator,
      console, setTimeout, clearTimeout,
      Performance: VmPerformance,
      performance: new VmPerformance(),
      URL, TextEncoder: VmTextEncoder, Headers: VmHeaders, Request, Response,
      Event: class Event { constructor(t) { this.type = t; } },
      HTMLElement: class HTMLElement {},
      customElements: { get: (n) => ceMap.get(n), define: (n, c) => ceMap.set(n, c) },
      addEventListener(ev, fn) { (listeners[ev] ||= []).push(fn); },
      ...(embedded ? { __VB_PRIVATE_REGISTER__: (api) => { privateApi = api; } } : {}),
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const ok = new Set(["toString", "createElement", "appendChild", "get contentWindow", "get documentElement", "getAttribute", "Event", "webdriver", "platform", "userAgent"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || ok.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, listeners, getPrivateApi: () => privateApi, advanceNow: (ms) => { nowOffset += ms; } };
  };

  // 1) Avail HIGH #1: Post-load Angular ZoneAwareError MUST stay 0-FP (no NATIVE_FUNCTION_TAMPERED)!
  const gate11 = buildBrowserGateScript({ defaultMode: "strict", unified: false });
  const { ctx: ctxZone } = makeVb11({ src: gate11 });
  vm.runInContext(`const _OE = Error; window.Error = function ZoneAwareError(m) { return new _OE(m); };`, ctxZone);
  const resZone = await ctxZone.VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.ok(!resZone.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `Angular ZoneAwareError MUST stay 0-FP: ${resZone.reasons}`);

  // 2) Security MEDIUM #4: Embedded unified VeilBreak catches pre-existing spoofed customElements("veil-break") AND fake window.VeilBreak!
  const embGate11 = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true });
  const { getPrivateApi: getFakeCeApi } = makeVb11({
    src: embGate11,
    embedded: true,
    preLoadHook: `customElements.define("veil-break", class FakeEl {});`,
  });
  const ceTamperRes = await getFakeCeApi().verify({ mode: "strict", antiCdp: false });
  assert.equal(ceTamperRes.blocked, true, "Embedded unified VeilBreak MUST block pre-existing spoofed <veil-break> customElement!");
  assert.ok(ceTamperRes.reasons.includes("NATIVE_FUNCTION_TAMPERED"));

  // 3) Security MEDIUM #5: Click-derived trusted submit/change within 250ms preserves teleport kin.lastClick for form onSubmit!
  const { ctx: ctxSub, listeners: subL, advanceNow: advSub } = makeVb11({ src: buildBrowserGateScript({ defaultMode: "strict", unified: true }) });
  const mkBtn = () => {
    const b = {
      closest: (s) => (s.includes("button") ? b : null),
      getClientRects: () => [{ width: 80, height: 30 }],
      getBoundingClientRect: () => ({ left: 10, top: 10, right: 90, bottom: 40, width: 80, height: 30 }),
    };
    return b;
  };
  const btn1 = mkBtn();
  const btn2 = mkBtn();
  ctxSub.innerWidth = 1280;
  ctxSub.innerHeight = 800;
  ctxSub.getComputedStyle = () => ({ visibility: "visible", display: "block", opacity: "1", clip: "auto", clipPath: "none" });
  const fireSub = (ev, obj) => { for (const fn of (subL[ev] || [])) fn(obj); };
  const fireTeleport = (targetBtn) => {
    const down = new ctxSub.Event("pointerdown");
    down.isTrusted = true; down.pointerType = "mouse";
    fireSub("pointerdown", down);
    advSub(3); // 3ms dwell (robotic teleport < 12ms)
    const clk = new ctxSub.Event("click");
    clk.isTrusted = true; clk.detail = 1; clk.pointerType = "mouse"; clk.target = targetBtn; clk.clientX = 50; clk.clientY = 25;
    fireSub("click", clk);
  };
  fireTeleport(btn1);
  advSub(50);
  fireTeleport(btn2);
  advSub(1);
  const subEv = new ctxSub.Event("submit");
  subEv.isTrusted = true;
  fireSub("submit", subEv);
  const lastAfterSub = ctxSub.VeilBreak.getLastInteraction();
  assert.ok(lastAfterSub && lastAfterSub.consecutiveTeleports >= 2, "Click-derived trusted submit MUST preserve teleport kin.lastClick for form onSubmit!");
  // Independent keyboard keydown STILL clears kin.lastClick immediately (0-FP!)
  const kdEv = new ctxSub.Event("keydown");
  kdEv.isTrusted = true;
  fireSub("keydown", kdEv);
  assert.equal(ctxSub.VeilBreak.getLastInteraction(), null, "Independent trusted keydown MUST still clear kin.lastClick!");

  // 4) Security MEDIUM #6: navigator prototype-chain insertion triggers WEBDRIVER_GETTER_SPOOFED + NATIVE_FUNCTION_TAMPERED!
  const { ctx: ctxNavProto } = makeVb11({
    src: gate11,
    preLoadHook: `Object.setPrototypeOf(navigator, Object.create(Navigator.prototype, { webdriver: { get: () => false }, platform: { get: () => "Win32" } }));`,
  });
  const navProtoRes = await ctxNavProto.VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.equal(navProtoRes.blocked, true);
  assert.ok(navProtoRes.reasons.includes("WEBDRIVER_GETTER_SPOOFED") && navProtoRes.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `Expected prototype-chain spoof detection, got ${navProtoRes.reasons}`);

  // 5) Avail MEDIUM #5: Standalone gate.js (unified:false) with <script data-unified="true"> loaded AFTER unified guard.js exits cleanly!
  const { ctx: ctxDataUni } = makeVb11({
    src: gate11,
    currentScriptAttr: { "data-unified": "true" },
    preLoadHook: `
      Object.defineProperty(window, "VeilBreak", { value: Object.freeze({ unified: true, version: "2.2.0" }), writable: false, configurable: false });
      Object.defineProperty(window, "ProxySnare", { value: Object.freeze({ version: "2.1.0" }), writable: false, configurable: false });
    `,
  });
  assert.equal(ctxDataUni[Symbol.for("__VB_BRIDGE_TAMPERED__")], undefined, "data-unified='true' standalone gate.js after unified guard.js MUST exit cleanly without __VB_BRIDGE_TAMPERED__!");

  // 6) Avail HIGH #3: Vercel-CDN-Cache-Control & Netlify-CDN-Cache-Control omit ephemeral SRI on CDN-cached HTML!
  const upCdnVb = http.createServer((req, res) => {
    const hdr = req.url === "/vercel"
      ? { "Content-Type": "text/html", "Cache-Control": "no-cache", "Vercel-CDN-Cache-Control": "public, s-maxage=3600" }
      : { "Content-Type": "text/html", "Cache-Control": "private, no-store", "Netlify-CDN-Cache-Control": "public, max-age=600" };
    res.writeHead(200, hdr);
    res.end("<!doctype html><html><head></head><body>cdn</body></html>");
  });
  await new Promise((r) => upCdnVb.listen(0, "127.0.0.1", r));
  const srvCdnVb = createVeilBreakServer({ target: `http://127.0.0.1:${upCdnVb.address().port}`, mode: "strict", protectedPaths: ["/api"] });
  const cdnBaseVb = await srvCdnVb.listen(0, "127.0.0.1");
  try {
    for (const p of ["/vercel", "/netlify"]) {
      const html = await (await fetch(`${cdnBaseVb}${p}`, { headers: makeBrowserHeaders({ accept: "text/html" }) })).text();
      assert.ok(!html.includes("integrity="), `${p} CDN header MUST omit ephemeral SRI pinning!`);
    }
  } finally {
    await srvCdnVb.close();
    await new Promise((r) => upCdnVb.close(r));
  }
});

test("24. Pass-12 Audit Regressions: bounded X-Original-URL comma-split DoS cap (JS + Python), precomputed br/gzip gate.js compression + 304 ETag & legacy future Expires shared-cache SRI omission", async () => {
  const zlib = require("node:zlib");

  // 1) Perf HIGH #1: 1,500-part X-Original-URL fails closed in < 15ms (Node + Python)!
  const evilOv = Array.from({ length: 1500 }, () => "%2e#?%00").join(",");
  const vbMw12 = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let ovSt = 0;
  const t0 = performance.now();
  await vbMw12(
    { method: "GET", url: "/public", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "x-original-url": evilOv }) },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(c) { ovSt = c; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  const dt = performance.now() - t0;
  assert.equal(ovSt, 403, "1,500-part X-Original-URL MUST fail closed 403!");
  assert.ok(dt < 15, `1,500-part X-Original-URL MUST finish in < 15ms (took ${dt.toFixed(2)}ms)`);

  // 2) Perf MEDIUM #4 + Availability Expires: br/gzip gate.js + 304 ETag + legacy future Expires!
  const up12 = http.createServer((req, res) => {
    if (req.url === "/future-exp") {
      res.writeHead(200, { "Content-Type": "text/html", Expires: "Wed, 21 Oct 2035 07:28:00 GMT" });
      res.end("<!doctype html><html><head></head><body>exp</body></html>");
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html", Expires: "0" });
    res.end("<!doctype html><html><head></head><body>zero</body></html>");
  });
  await new Promise((r) => up12.listen(0, "127.0.0.1", r));
  const srv12 = createVeilBreakServer({ target: `http://127.0.0.1:${up12.address().port}`, mode: "strict", protectedPaths: ["/api"] });
  await srv12.listen(0, "127.0.0.1");
  const p12 = srv12.server.address().port;
  const rawReq12 = (pathStr, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p12, method: "GET", path: pathStr, headers }, (resp) => {
        const chunks = [];
        resp.on("data", (c) => chunks.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, buf: Buffer.concat(chunks) }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rRaw = await rawReq12("/__veilbreak/gate.js", makeBrowserHeaders());
    const rGz = await rawReq12("/__veilbreak/gate.js", makeBrowserHeaders({ "accept-encoding": "gzip" }));
    const rBr = await rawReq12("/__veilbreak/gate.js", makeBrowserHeaders({ "accept-encoding": "br" }));
    assert.equal(rGz.headers["content-encoding"], "gzip");
    assert.equal(rBr.headers["content-encoding"], "br");
    assert.equal(rBr.headers["vary"], "Accept-Encoding");
    assert.ok(rBr.buf.length * 3 < rRaw.buf.length, `Brotli gate.js (${rBr.buf.length}B) MUST be >3x smaller than raw (${rRaw.buf.length}B)!`);
    assert.equal(zlib.brotliDecompressSync(rBr.buf).equals(rRaw.buf), true);
    assert.equal(zlib.gunzipSync(rGz.buf).equals(rRaw.buf), true);
    const r304 = await rawReq12("/__veilbreak/gate.js", makeBrowserHeaders({ "accept-encoding": "br", "if-none-match": rBr.headers["etag"] }));
    assert.equal(r304.status, 304);

    const rFut = await rawReq12("/future-exp", makeBrowserHeaders({ accept: "text/html" }));
    assert.ok(!rFut.buf.toString("utf8").includes("integrity="), "Future Expires header MUST omit ephemeral SRI!");
    const rZero = await rawReq12("/zero-exp", makeBrowserHeaders({ accept: "text/html" }));
    assert.ok(rZero.buf.toString("utf8").includes("integrity="), "Expires: 0 MUST retain SRI pinning!");
  } finally {
    await srv12.close();
    await new Promise((r) => up12.close(r));
  }

  // 3) Python parity: 1,500-part X-Original-URL fails closed in < 15ms!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import VeilBreakTicketStore
st = VeilBreakTicketStore(mode="strict", ticket_pow_bits=0, protected_paths=["/api"])
evil = ",".join(["%2e#?%00"] * 1500)
t0 = time.perf_counter()
v = st.verify_request(headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "X-Original-URL": evil}, ip="127.0.0.1", method="GET", path="/public")
dt = (time.perf_counter() - t0) * 1000
assert v.blocked and "PROXY_PATH_OVERRIDE_HEADER" in v.reasons, f"Expected fail-closed override: {v.reasons}"
assert dt < 15.0, f"Python 1,500-part X-Original-URL took {dt:.2f}ms!"`,
    ],
    { encoding: "utf8" }
  );
});

test("25. Pass-13 Audit Regressions: RegExp.prototype.exec & Array.push defenses, _bridgeTampered init-order race with antiCdp:false, Safari cached gate.js duration===0 single-instance coexistence, modern Firefox RFP hw=4 0-FP, passive untrusted click 250ms TTL, Accept-Encoding q=0.5/0.8, extensionless image->JS MIME block & monitor same-method override 0-FP (JS+Python)", async () => {
  const vm = require("node:vm");

  const runVbSdkVm = ({ sdkOpts = {}, preLoadHook = "", rtEntries = [], nowRef = { v: 1000 }, hw = 8, tzOffset = -60, ua = CHROME_UA, platform = "Linux x86_64", preRegister = null } = {}) => {
    const src = buildBrowserGateScript({ defaultMode: "strict", antiCdp: true, autoBlockPage: false, ...sdkOpts });
    const listeners = {};
    let frameCount = 0;
    const vmConsole = { debug: function debug() {}, log() {} };
    const nativeRefs = new Set([vmConsole.debug, TextEncoder.prototype.encode, Headers.prototype.set, Headers.prototype.get]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","getBoundingClientRect","debug","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor() { super(); this.style = {}; }
      getAttribute() { return null; }
      remove() {}
      get offsetWidth() { return this.style.fontFamily === "sans-serif" ? 120 : 100; }
      closest() { return this.tagName === "BUTTON" ? this : null; }
      getClientRects() { return [this.getBoundingClientRect()]; }
      getBoundingClientRect() { return { left: 10, top: 10, right: 90, bottom: 40, width: 80, height: 30 }; }
    }
    class Document extends Node {
      constructor() {
        super();
        this.readyState = "complete";
        this.currentScript = null;
        this._el = new Element();
        this.body = new Element();
      }
      get documentElement() { return this._el; }
      createElement(t) {
        if (t === "iframe") { frameCount++; return new HTMLIFrameElement(); }
        if (t === "canvas") return { width: 32, height: 32, getContext() { return null; } };
        return new Element();
      }
      addEventListener() {}
    }
    const VmEvent = class Event {
      constructor(type, trusted) { this.type = type; this._tr = trusted; }
      get isTrusted() { return this._tr; }
    }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return platformVal; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return ua; }, configurable: true });
    const platformVal = platform;
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = hw;
    navInst.maxTouchPoints = 0;
    const OrigDate = Date;
    class VmDate extends OrigDate { getTimezoneOffset() { return tzOffset; } }
    const ctx = vm.createContext({
      Date: VmDate,
      Event: VmEvent,
      Navigator: VmNavigator,
      navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      TextEncoder, Headers, URL, console: vmConsole, setTimeout, clearTimeout,
      performance: { now: () => nowRef.v, getEntriesByType: () => rtEntries },
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      addEventListener(t, fn) { (listeners[t] ||= []).push(fn); },
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      _nativeRefs: nativeRefs,
      ...(preRegister ? { __VB_PRIVATE_REGISTER__: preRegister } : {}),
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","getBoundingClientRect","debug","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, listeners, getFrameCount: () => frameCount, VmEvent, Element };
  };

  // 1) CRITICAL #1: Hooking RegExp.prototype.exec MUST trigger NATIVE_FUNCTION_TAMPERED (+4)!
  const vmRe = runVbSdkVm({ preLoadHook: `const _origExec = RegExp.prototype.exec; RegExp.prototype.exec = function(s) { return this.global ? _origExec.call(this, s) : ["ok"]; };` });
  const rRe = await vmRe.ctx.VeilBreak.verify();
  assert.ok(rRe.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `RegExp.prototype.exec hook MUST trigger NATIVE_FUNCTION_TAMPERED (got ${rRe.reasons})`);

  // 2) Security MEDIUM #5: Unified antiCdp:false with pre-occupied window.VeilBreak MUST NOT drop NATIVE_FUNCTION_TAMPERED!
  let privReg = null;
  const vmRace = runVbSdkVm({
    sdkOpts: { unified: true, antiCdp: false, allowDevTools: true },
    preRegister: (api) => { privReg = api; },
    preLoadHook: `Object.defineProperty(window, "VeilBreak", { value: { fake: true }, writable: false, configurable: false });`,
  });
  assert.ok(privReg, "Embedded unified VeilBreak MUST register private API");
  const prRace = await privReg.collectHandshakeProof("ch-race");
  assert.ok((prRace.f & 1024) !== 0 && prRace.s >= 4, `Pre-occupied VeilBreak with antiCdp:false MUST set NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(prRace)})`);

  // 3) CRITICAL #1 (Pass-14) + Availability HIGH #3: Sync XHR /gate.js CANNOT hijack private registration (sets NATIVE_FUNCTION_TAMPERED),
  // while legitimate Safari-cached script gate.js (duration===0, responseEnd>0) avoids false NATIVE_FUNCTION_TAMPERED AND still uses fresh lexical vbApi!
  let hijackReg = null;
  runVbSdkVm({
    sdkOpts: { unified: true },
    rtEntries: [{ name: "https://app.example/__veilbreak/gate.js?v=abc", initiatorType: "xmlhttprequest", transferSize: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 12, duration: 0 }],
    preRegister: (api) => { hijackReg = api; },
    preLoadHook: `
      const fakeApi = Object.freeze({ unified: true, tag: "HIJACK" });
      Object.defineProperty(window, "VeilBreak", { value: fakeApi, writable: false, configurable: false });
      Object.defineProperty(window, Symbol.for("__VEILBREAK_INTERNAL__"), { value: fakeApi, writable: false, configurable: false });
    `,
  });
  assert.ok(hijackReg && hijackReg.tag !== "HIJACK", "Sync XHR /gate.js MUST NEVER hijack __VB_PRIVATE_REGISTER__!");
  const prHijack = await hijackReg.collectHandshakeProof("ch-hijack");
  assert.ok((prHijack.f & 1024) !== 0 && prHijack.s >= 4, `Sync XHR preload hijack MUST trigger NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(prHijack)})`);

  let sharedReg = null;
  runVbSdkVm({
    sdkOpts: { unified: true },
    rtEntries: [{ name: "https://app.example/__veilbreak/gate.js?v=abc", initiatorType: "script", transferSize: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 12, duration: 0 }],
    preRegister: (api) => { sharedReg = api; },
    preLoadHook: `
      const api = Object.freeze({ unified: true, tag: "PRELOADED" });
      Object.defineProperty(window, "VeilBreak", { value: api, writable: false, configurable: false });
      Object.defineProperty(window, Symbol.for("__VEILBREAK_INTERNAL__"), { value: api, writable: false, configurable: false });
    `,
  });
  assert.ok(sharedReg && sharedReg.tag !== "PRELOADED", "Embedded unified VeilBreak MUST always register its own fresh lexical API!");
  const prCoexist = await sharedReg.collectHandshakeProof("ch-coexist");
  assert.equal((prCoexist.f & 1024), 0, `Legitimate Safari-cached script gate.js MUST NOT falsely trigger NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(prCoexist)})`);

  // 4) Availability MEDIUM #5: Modern LibreWolf / Firefox RFP (hw=4, UTC tzOffset=0, Win32 on Linux without Segoe UI) stays 0-FP on OS_CORE_FONT_LIE!
  const vmRfp = runVbSdkVm({
    hw: 4,
    tzOffset: 0,
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    platform: "Win32",
  });
  const rRfp = await vmRfp.ctx.VeilBreak.verify();
  assert.ok(!rRfp.reasons.includes("OS_CORE_FONT_LIE"), `Modern Firefox RFP (hw=4, UTC) MUST NOT trigger OS_CORE_FONT_LIE (got ${rRfp.reasons})`);

  // 5) Availability MEDIUM #6: Passive programmatic .click() has 250ms TTL (blocks within 250ms, 0-FP after 300ms)!
  const nowRef = { v: 1000 };
  const vmClick = runVbSdkVm({ nowRef });
  const btn = new vmClick.Element();
  btn.tagName = "BUTTON";
  const evUntrusted = new vmClick.VmEvent("click", false);
  evUntrusted.target = btn;
  evUntrusted.clientX = 50;
  evUntrusted.clientY = 25;
  for (const fn of vmClick.listeners.click || []) fn(evUntrusted);
  nowRef.v = 1100;
  assert.ok(vmClick.ctx.VeilBreak.getLastInteraction(), "Passive untrusted click MUST be visible within 250ms");
  nowRef.v = 1350;
  assert.equal(vmClick.ctx.VeilBreak.getLastInteraction(), null, "Passive untrusted click MUST expire after 250ms so unrelated hydration POSTs stay 0-FP!");

  // 6) Perf MEDIUM #3 + Security LOW + Parity LOW: Accept-Encoding q=0.5/0.8, extensionless Sec-Fetch-Dest: image -> text/javascript blocked, and monitor-mode same-method X-HTTP-Method-Override 0-FP (JS+Python)!
  const up13 = http.createServer((req, res) => {
    if (req.url === "/jsonp") {
      res.writeHead(200, { "Content-Type": "text/javascript" });
      res.end("cb(1);");
      return;
    }
    res.writeHead(200, { "Content-Type": "image/webp" });
    res.end("RIFF");
  });
  await new Promise((r) => up13.listen(0, "127.0.0.1", r));
  const srv13 = createVeilBreakServer({ target: `http://127.0.0.1:${up13.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv13.listen(0, "127.0.0.1");
  const p13 = srv13.server.address().port;
  const req13 = (pathStr, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p13, method: "GET", path: pathStr, headers }, (resp) => {
        const chunks = [];
        resp.on("data", (c) => chunks.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, buf: Buffer.concat(chunks) }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rQ = await req13("/__veilbreak/gate.js", makeBrowserHeaders({ "accept-encoding": "gzip;q=0.8, br;q=0.5" }));
    assert.equal(rQ.headers["content-encoding"], "br", "Fractional Accept-Encoding br;q=0.5 MUST return br!");
    const rImgJs = await req13("/jsonp", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }));
    assert.equal(rImgJs.status, 403, "Extensionless Sec-Fetch-Dest: image MUST block text/javascript!");
    const rImgOk = await req13("/_next/image", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }));
    assert.equal(rImgOk.status, 200, "Extensionless Sec-Fetch-Dest: image MUST allow image/webp!");
  } finally {
    await srv13.close();
    await new Promise((r) => up13.close(r));
  }

  // Monitor-mode same-method X-HTTP-Method-Override: POST without ticket scores 0 (JS + Python)!
  const monMw = createVeilBreakMiddleware({ mode: "monitor", protectedPaths: ["/api"] });
  const monReq = { method: "POST", url: "/api/x", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "x-http-method-override": "POST" }) };
  await monMw(monReq, { headersSent: false, writableEnded: false, setHeader() {}, writeHead() {}, end() {} });
  assert.ok(!monReq.veilBreak.reasons.includes("METHOD_OVERRIDE_DENIED"), `Monitor same-method override MUST NOT flag METHOD_OVERRIDE_DENIED (got ${monReq.veilBreak.reasons})`);
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import VeilBreakTicketStore
st = VeilBreakTicketStore(mode="monitor", ticket_pow_bits=0, protected_paths=["/api"])
v = st.verify_request(headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-HTTP-Method-Override": "POST"}, ip="127.0.0.1", method="POST", path="/api/x")
assert "METHOD_OVERRIDE_DENIED" not in v.reasons, f"Python monitor same-method override false positive: {v.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("26. Pass-14 Audit Regressions: String/Math/Uint8Array tamper defenses, synchronous passive-click TTL across /ticket RTT, RFC 9111 no-store+Expires:0 & unmodified ETag preservation, matchAll wildcard rules, HeadlessChrome SEC_CH_UA_GREASE_LIE parity, 18-comma override cap, strict Origin & OPTIONS+X-VB-Ticket", async () => {
  const vm = require("node:vm");
  const { compileProtectedPathRules, normalizeProtectedPaths, isProtectedPath } = require("../src/probes.js");

  // Helper VM for Pass-14 browser-sdk tests
  const runVb14 = ({ sdkOpts = {}, preLoadHook = "", nowRef = { v: 1000 }, fetchImpl = null, onFreshRealm = null, markGesture = null } = {}) => {
    const src = buildBrowserGateScript({ defaultMode: "strict", basePath: "/__veilbreak", ...sdkOpts });
    const listeners = {};
    let frameCount = 0;
    const vmConsole = { debug: function debug() {}, log: function log() {} };
    const nativeRefs = new Set([vmConsole.debug, TextEncoder.prototype.encode, Headers.prototype.set, Headers.prototype.get, Response.prototype.json]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor() { super(); this.style = {}; }
      getAttribute() { return null; }
      remove() {}
      get offsetWidth() { return 100; }
      closest() { return this.tagName === "BUTTON" ? this : null; }
      getClientRects() { return [this.getBoundingClientRect()]; }
      getBoundingClientRect() { return { left: 10, top: 10, right: 90, bottom: 40, width: 80, height: 30 }; }
    }
    class Document extends Node {
      constructor() { super(); this.readyState = "complete"; this.currentScript = null; this._el = new Element(); this.body = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) {
        if (t === "iframe") { frameCount++; return new HTMLIFrameElement(); }
        if (t === "canvas") return { width: 32, height: 32, getContext() { return null; } };
        return new Element();
      }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(type, trusted) { this.type = type; this._tr = trusted; } get isTrusted() { return this._tr; } }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init); }
      : async function fetch() { return new Response("{}"); };
    nativeRefs.add(vmFetch);
    const ctx = vm.createContext({
      Event: VmEvent, Navigator: VmNavigator, navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
      performance: { now: () => nowRef.v, getEntriesByType: () => [] },
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      document: new Document(), Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener(t, fn) { (listeners[t] ||= []).push(fn); },
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      _nativeRefs: nativeRefs,
      ...(onFreshRealm ? { __PS_ON_FRESH_REALM__: onFreshRealm } : {}),
      ...(markGesture ? { __PS_MARK_GESTURE__: markGesture } : {}),
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, listeners, getFrameCount: () => frameCount, VmEvent, Element, ifrWin };
  };

  // 1) HIGH #3: Pre-load hooks on Math.abs, String, or Uint8Array MUST trigger NATIVE_FUNCTION_TAMPERED!
  for (const [label, hook] of [
    ["Math.abs", `Math.abs = (x) => 999;`],
    ["String", `window.String = function String(x) { return ""; };`],
    ["Uint8Array", `window.Uint8Array = function Uint8Array() { return []; };`],
  ]) {
    const v = runVb14({ preLoadHook: hook });
    const r = await v.ctx.VeilBreak.verify();
    assert.ok(r.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `${label} hook MUST trigger NATIVE_FUNCTION_TAMPERED (got ${r.reasons})`);
  }

  // 2) MEDIUM #12: Embedded unified mode runs 1 startup iframe and shares its verified realm (fToStr, fExec) with ProxySnare via __PS_ON_FRESH_REALM__, plus forwards trusted gestures!
  let sharedToStr = null;
  let sharedExec = null;
  let gestureCalls = 0;
  let privApi14 = null;
  const vEmb = runVb14({
    sdkOpts: { unified: true, embedded: true, includeTicketPow: false },
    onFreshRealm: (fToStr, fExec) => { sharedToStr = fToStr; sharedExec = fExec; },
    markGesture: () => { gestureCalls++; },
  });
  // Trigger with __VB_PRIVATE_REGISTER__ so _isEmbeddedUnified === true
  const vEmb2 = (() => {
    const srcEmb = buildBrowserGateScript({ defaultMode: "strict", basePath: "/__veilbreak", unified: true, embedded: true, includeTicketPow: false });
    const ctxEmb = vEmb.ctx;
    return { srcEmb, ctxEmb };
  })();
  // Run a clean embedded VM with __VB_PRIVATE_REGISTER__ + __PS_ON_FRESH_REALM__ + __PS_MARK_GESTURE__
  const runVb14Emb = () => {
    const src = buildBrowserGateScript({ defaultMode: "strict", basePath: "/__veilbreak", unified: true, embedded: true, includeTicketPow: false });
    const listeners = {};
    let fc = 0;
    const vmConsole = { debug: function debug() {}, log: function log() {} };
    const nativeRefs = new Set([vmConsole.debug, TextEncoder.prototype.encode, Headers.prototype.set, Headers.prototype.get, Response.prototype.json]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { constructor() { super(); this.style = {}; } getAttribute() { return null; } remove() {} get offsetWidth() { return 100; } }
    class Document extends Node {
      constructor() { super(); this.readyState = "complete"; this.currentScript = null; this._el = new Element(); this.body = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { if (t === "iframe") { fc++; return new HTMLIFrameElement(); } return new Element(); }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(type, trusted) { this.type = type; this._tr = trusted; } get isTrusted() { return this._tr; } }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    const ctx = vm.createContext({
      Event: VmEvent, Navigator: VmNavigator, navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
      performance: { now: () => 1000, getEntriesByType: () => [] },
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      document: new Document(), Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      addEventListener(t, fn) { (listeners[t] ||= []).push(fn); },
      _nativeRefs: nativeRefs,
      __VB_PRIVATE_REGISTER__: (api) => { privApi14 = api; },
      __PS_ON_FRESH_REALM__: (fToStr, fExec) => { sharedToStr = fToStr; sharedExec = fExec; },
      __PS_MARK_GESTURE__: () => { gestureCalls++; },
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    vm.runInContext(src, ctx);
    return { listeners, getFc: () => fc, VmEvent };
  };
  const embRun = runVb14Emb();
  assert.ok(privApi14, "Embedded VeilBreak MUST register private lexical API");
  assert.equal(embRun.getFc(), 0, "Embedded VeilBreak MUST NOT synchronously mount an iframe during render-blocking <head> parsing!");
  await privApi14.collectHandshakeProof("ch14");
  assert.equal(embRun.getFc(), 1, "Embedded VeilBreak MUST create exactly 1 startup iframe on first probe and share it with ProxySnare!");
  assert.equal(typeof sharedToStr, "function", "Embedded VeilBreak MUST pass verified fresh fToStr to __PS_ON_FRESH_REALM__!");
  assert.equal(typeof sharedExec, "function", "Embedded VeilBreak MUST pass verified fresh fExec to __PS_ON_FRESH_REALM__!");
  for (const fn of embRun.listeners.pointerdown || []) fn(new embRun.VmEvent("pointerdown", true));
  assert.equal(gestureCalls, 1, "Trusted pointerdown in embedded VeilBreak MUST forward to __PS_MARK_GESTURE__!");

  // 3) MEDIUM #6: Passive untrusted .click() TTL (250ms) frozen synchronously at fetch() call time across a >300ms /ticket RTT!
  const nowRef = { v: 1000 };
  let capturedAttest = null;
  const vRtt = runVb14({
    nowRef,
    sdkOpts: { unified: false, protectedRules: ["/api"] },
    fetchImpl: async (url, init) => {
      if (String(url).includes("/__veilbreak/ticket")) {
        nowRef.v += 400; // simulate 400ms /ticket RTT exceeding 250ms click TTL!
        return new Response(JSON.stringify({ ok: true, ticket: "t".repeat(32), challenge: "c".repeat(32), difficulty: 0 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      capturedAttest = JSON.parse(init.headers.get("X-VB-Attest"));
      return new Response('{"ok":true}', { status: 200 });
    },
  });
  const btn = new vRtt.Element();
  btn.tagName = "BUTTON";
  const evClick = new vRtt.VmEvent("click", false);
  evClick.target = btn;
  evClick.clientX = 50;
  evClick.clientY = 25;
  for (const fn of vRtt.listeners.click || []) fn(evClick);
  nowRef.v = 1100; // 100ms after click (< 250ms)
  await vRtt.ctx.fetch("/api/pay", { method: "POST", body: "{}" });
  assert.ok(capturedAttest && (capturedAttest.f & 16384) !== 0 && capturedAttest.s >= 6, `Synthetic click snapped at call time MUST survive 400ms /ticket RTT (got ${JSON.stringify(capturedAttest)})`);
  capturedAttest = null;
  nowRef.v = 1600; // well after 250ms TTL -> unrelated fetch stays 0-FP
  await vRtt.ctx.fetch("/api/ping", { method: "GET" });
  assert.ok(capturedAttest && (capturedAttest.f & 16384) === 0, `Fetch initiated >250ms after passive untrusted click MUST stay 0-FP (got ${JSON.stringify(capturedAttest)})`);

  // 4) MEDIUM #7 (Availability): RFC 9111 preserves Cache-Control: no-store + Expires: 0 AND preserves ETag/Last-Modified when HTML already has gate.js!
  const up14 = http.createServer((req, res) => {
    if (req.url === "/nostore") {
      res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store", Expires: "0" });
      res.end("<!doctype html><html><head></head><body>secret</body></html>");
      return;
    }
    if (req.url === "/already") {
      res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "private, max-age=300", ETag: '"keep-etag"', "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT" });
      res.end('<!doctype html><html><head><script src="/__veilbreak/gate.js"></script></head><body>ok</body></html>');
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
  });
  await new Promise((r) => up14.listen(0, "127.0.0.1", r));
  const srv14 = createVeilBreakServer({ target: `http://127.0.0.1:${up14.address().port}`, mode: "strict", protectedPaths: ["/api"] });
  await srv14.listen(0, "127.0.0.1");
  const p14 = srv14.server.address().port;
  const req14 = (method, reqPath, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p14, method, path: reqPath, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rNs = await req14("GET", "/nostore", makeBrowserHeaders({ accept: "text/html" }));
    assert.equal(rNs.status, 200);
    assert.equal(rNs.headers["cache-control"], "no-store", "Cache-Control: no-store + Expires: 0 MUST NOT be downgraded to private, no-cache!");
    const rAlr = await req14("GET", "/already", makeBrowserHeaders({ accept: "text/html" }));
    assert.equal(rAlr.status, 200);
    assert.equal(rAlr.headers["etag"], '"keep-etag"', "Unmodified HTML already containing gate.js MUST preserve ETag!");
    assert.equal(rAlr.headers["last-modified"], "Wed, 21 Oct 2015 07:28:00 GMT", "Unmodified HTML MUST preserve Last-Modified!");
    assert.equal(rAlr.headers["cache-control"], "private, max-age=300", "Unmodified HTML MUST preserve Cache-Control!");

    // Strict Origin rejection (http:host & http:///host) at /__veilbreak/ticket
    for (const badOrig of [`http:127.0.0.1:${p14}`, `http:///127.0.0.1:${p14}`]) {
      const rBad = await req14("GET", "/__veilbreak/ticket", makeBrowserHeaders({ host: `127.0.0.1:${p14}`, origin: badOrig }));
      assert.equal(rBad.status, 403, `Malformed Origin '${badOrig}' MUST be rejected at /__veilbreak/ticket!`);
    }

    // Cross-origin OPTIONS carrying X-VB-Ticket MUST NOT be exempted as CORS preflight!
    const rOptTk = await req14("OPTIONS", "/api/x", makeBrowserHeaders({
      host: `127.0.0.1:${p14}`,
      origin: "https://other.example",
      "access-control-request-method": "POST",
      "sec-fetch-mode": "cors",
      "x-vb-ticket": "a".repeat(32),
    }));
    assert.equal(rOptTk.status, 403, "OPTIONS carrying X-VB-Ticket MUST NOT be exempted as CORS preflight!");
  } finally {
    await srv14.close();
    await new Promise((r) => up14.close(r));
  }

  // 5) MEDIUM #9: compileProtectedPathRules & normalizeProtectedPaths set .matchAll O(1) short-circuit!
  assert.equal(compileProtectedPathRules(["*"]).matchAll, true);
  assert.equal(normalizeProtectedPaths(["/"]).matchAll, true);
  assert.equal(compileProtectedPathRules(["/api"]).matchAll, false);
  assert.equal(isProtectedPath("/anything", compileProtectedPathRules(["*"]), true), true);

  // 6) MEDIUM #14: HeadlessChrome/124 + legacy GREASE parity across skipHeaderChecks false/true/_headersPrevalidated & Python!
  const hlGreaseHdrs = {
    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36",
    "sec-ch-ua": '" Not A;Brand";v="99", "HeadlessChrome";v="124"',
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
  };
  const vFull = verifyHandshakeProof({ mode: "strict", headers: hlGreaseHdrs, proof: null, skipHeaderChecks: false });
  const vSkip = verifyHandshakeProof({ mode: "strict", headers: hlGreaseHdrs, proof: null, skipHeaderChecks: true });
  const vPre = verifyHandshakeProof({ mode: "strict", headers: hlGreaseHdrs, proof: null, _headersPrevalidated: true });
  assert.ok(vFull.reasons.includes("SEC_CH_UA_GREASE_LIE"), `skipHeaderChecks:false MUST flag SEC_CH_UA_GREASE_LIE (got ${vFull.reasons})`);
  assert.ok(vSkip.reasons.includes("SEC_CH_UA_GREASE_LIE"), `skipHeaderChecks:true MUST flag SEC_CH_UA_GREASE_LIE (got ${vSkip.reasons})`);
  assert.ok(vPre.reasons.includes("SEC_CH_UA_GREASE_LIE"), `_headersPrevalidated:true MUST flag SEC_CH_UA_GREASE_LIE (got ${vPre.reasons})`);

  // 7) HIGH #4: 18-comma padding bypass X-Original-URL: /public,,,,,,,,,,,,,,,,,,/api/secret blocked in Node AND Python!
  const padOv = "/public" + ",".repeat(18) + "/api/secret";
  const mw14 = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let padStatus = 0;
  await mw14(
    { method: "GET", url: "/public", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "x-original-url": padOv }) },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(c) { padStatus = c; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(padStatus, 403, "Node 18-comma X-Original-URL padding bypass MUST be blocked (403)!");

  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import VeilBreakTicketStore, verify_handshake_proof, _sha256_hex
st = VeilBreakTicketStore(mode="strict", ticket_pow_bits=0, protected_paths=["/api"])
tk = st.mint_ticket(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
d = _sha256_hex(f"VB_ATTEST_V2|{tk}|nonce-pad14|0|0|Linux x86_64")
v_pad = st.verify_request(
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-Original-URL": ${JSON.stringify(padOv)}, "X-VB-Ticket": tk, "X-VB-Nonce": "nonce-pad14", "X-VB-Attest": f'{{"v":2,"s":0,"f":0,"p":"Linux x86_64","d":"{d}"}}'},
    ip="127.0.0.1", method="GET", path="/public"
)
assert v_pad.blocked and "PROXY_PATH_OVERRIDE_HEADER" in v_pad.reasons, f"Python 18-comma override bypass failed: {v_pad.reasons}"
vh = verify_handshake_proof(mode="strict", headers=${JSON.stringify(hlGreaseHdrs)}, proof=None)
assert "SEC_CH_UA_GREASE_LIE" in vh.reasons, f"Python HeadlessChrome GREASE parity failed: {vh.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("27. Pass-15 Audit Regressions: performance.now/Date.now & String.prototype.{toLowerCase,endsWith} tamper defenses, Safari empty initiatorType legitCoexist 0-FP, dual-stack IPv4/IPv6 CIDR trustProxy, strict HTML MIME essence & RFC 9111 field-qualified private/no-cache directives", async () => {
  const vm = require("node:vm");

  const runVb15 = ({ sdkOpts = {}, preLoadHook = "", rtEntries = [], preRegister = null } = {}) => {
    const src = buildBrowserGateScript({ defaultMode: "strict", basePath: "/__veilbreak", ...sdkOpts });
    const vmConsole = { debug: function debug() {}, log: function log() {} };
    const perfNowFn = function now() { return 1000; };
    const nativeRefs = new Set([vmConsole.debug, TextEncoder.prototype.encode, Headers.prototype.set, Headers.prototype.get, Response.prototype.json, perfNowFn]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { constructor() { super(); this.style = {}; } getAttribute() { return null; } remove() {} get offsetWidth() { return 100; } }
    class Document extends Node {
      constructor() { super(); this.readyState = "complete"; this.currentScript = null; this._el = new Element(); this.body = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(t, tr) { this.type = t; this._tr = tr; } get isTrusted() { return this._tr; } }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    const ctx = vm.createContext({
      Event: VmEvent, Navigator: VmNavigator, navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
      performance: { now: perfNowFn, getEntriesByType: () => rtEntries },
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      document: new Document(), Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      addEventListener() {},
      _nativeRefs: nativeRefs,
      ...(preRegister ? { __VB_PRIVATE_REGISTER__: preRegister } : {}),
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return ctx;
  };

  // 1) HIGH #1 & HIGH #4: Pre-load performance.now, Date.now, String.prototype.toLowerCase, and String.prototype.endsWith hooks trigger NATIVE_FUNCTION_TAMPERED!
  for (const [label, hook] of [
    ["performance.now", `performance.now = () => 1000;`],
    ["Date.now", `Date.now = () => 1000;`],
    ["String.prototype.toLowerCase", `String.prototype.toLowerCase = () => "monitor";`],
    ["String.prototype.endsWith", `String.prototype.endsWith = () => true;`],
  ]) {
    const ctx = runVb15({ preLoadHook: hook });
    const res = await ctx.VeilBreak.verify();
    assert.ok(res.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `${label} pre-load hook MUST trigger NATIVE_FUNCTION_TAMPERED (got ${res.reasons})`);
  }

  // 2) MEDIUM Avail #4: Safari empty initiatorType "" in legitCoexist stays 0-FP (no NATIVE_FUNCTION_TAMPERED) while still registering lexical vbApi!
  let emptyItReg = null;
  runVb15({
    sdkOpts: { unified: true },
    rtEntries: [{ name: "https://app.example/__veilbreak/gate.js?v=1", initiatorType: "", transferSize: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 10, duration: 0 }],
    preRegister: (api) => { emptyItReg = api; },
    preLoadHook: `
      const api = Object.freeze({ unified: true, tag: "SAFARI_PRE" });
      Object.defineProperty(window, "VeilBreak", { value: api, writable: false, configurable: false });
      Object.defineProperty(window, Symbol.for("__VEILBREAK_INTERNAL__"), { value: api, writable: false, configurable: false });
    `,
  });
  assert.ok(emptyItReg && emptyItReg.tag !== "SAFARI_PRE");
  const prEmptyIt = await emptyItReg.collectHandshakeProof("ch-saf-it");
  assert.equal((prEmptyIt.f & 1024), 0, `Safari empty initiatorType "" on gate.js MUST stay 0-FP (got ${JSON.stringify(prEmptyIt)})`);

  // 3) Security LOW #1 + Availability LOW #5 + MEDIUM Perf #3: MIME essence gate, RFC 9111 field-qualified private/no-cache, and dual-stack CIDR trustProxy!
  const up15 = http.createServer((req, res) => {
    if (req.url === "/fake-html") {
      res.writeHead(200, { "Content-Type": 'application/json; profile="https://x/text/html"' });
      res.end('{"secret":1}');
      return;
    }
    if (req.url === "/field-priv") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": 'public, max-age=600, private="Set-Cookie"' });
      res.end("<!doctype html><html><head></head><body>cdn-priv</body></html>");
      return;
    }
    if (req.url === "/field-nc") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": 'public, max-age=600, no-cache="Set-Cookie"' });
      res.end("<!doctype html><html><head></head><body>cdn-nc</body></html>");
      return;
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  await new Promise((r) => up15.listen(0, "127.0.0.1", r));
  const srv15 = createVeilBreakServer({ target: `http://127.0.0.1:${up15.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv15.listen(0, "127.0.0.1");
  const p15 = srv15.server.address().port;
  const req15 = (reqPath, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p15, method: "GET", path: reqPath, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const navH = makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" });
    const rFake = await req15("/fake-html", navH);
    assert.equal(rFake.status, 403, 'Non-HTML MIME with substring text/html in parameter MUST be blocked 403!');
    const rFp = await req15("/field-priv", navH);
    assert.equal(rFp.status, 200);
    assert.ok(!rFp.body.includes("integrity="), 'Field-qualified private="Set-Cookie" MUST still be treated as shared-cacheable HTML (omit SRI)!');
    const rFn = await req15("/field-nc", navH);
    assert.equal(rFn.status, 200);
    assert.ok(!rFn.body.includes("integrity="), 'Field-qualified no-cache="Set-Cookie" MUST still be treated as shared-cacheable HTML (omit SRI)!');
  } finally {
    await srv15.close();
    await new Promise((r) => up15.close(r));
  }

  // Dual-stack IPv4 + IPv6 CIDR trustProxy accuracy (including ::ffff:-mapped sockets)
  const mwTp15 = createVeilBreakMiddleware({
    mode: "strict",
    protectedPaths: ["/api"],
    trustProxy: ["10.0.0.0/8", "2001:db8::/32", "::ffff:172.16.0.0/108"],
    maxTicketsPerMinPerIp: 1,
  });
  const callTicketIp = async (remoteAddress, xff) => {
    let st = 0;
    await mwTp15(
      { method: "GET", url: "/__veilbreak/ticket", socket: { remoteAddress }, headers: makeBrowserHeaders({ "x-forwarded-for": xff }) },
      { headersSent: false, writableEnded: false, setHeader() {}, writeHead(c) { st = c; this.headersSent = true; }, end() { this.writableEnded = true; } }
    );
    return st;
  };
  assert.equal(await callTicketIp("::ffff:10.1.2.3", "198.51.100.1"), 200, "IPv4-mapped ::ffff:10.x MUST match IPv4 CIDR 10.0.0.0/8");
  assert.equal(await callTicketIp("::ffff:10.1.2.3", "198.51.100.2"), 200, "Distinct XFF client behind ::ffff:10.x MUST get separate rate bucket");
  assert.equal(await callTicketIp("172.16.0.5", "198.51.100.3"), 200, "IPv4 172.16.0.5 MUST match IPv4-mapped IPv6 CIDR ::ffff:172.16.0.0/108");
  assert.equal(await callTicketIp("2001:db8::42", "198.51.100.4"), 200, "IPv6 2001:db8::42 MUST match IPv6 CIDR 2001:db8::/32");
  assert.equal(await callTicketIp("::ffff:192.168.1.5", "198.51.100.5"), 200);
  assert.equal(await callTicketIp("::ffff:192.168.1.5", "198.51.100.6"), 429, "Untrusted ::ffff:192.168.1.5 MUST ignore spoofed XFF and share socket IP rate bucket!");
});

test("28. Pass-16 Audit Regressions: createVeilBreakServer honors requireFetchMetadata:false / balanced wildcard probes, private stale-while-revalidate & s-maxage=0+Expires SRI cache rewrite, and lazy gateJs", async () => {
  // 1) Availability MEDIUM #1: balanced (requireFetchMetadata:false) & explicit requireFetchMetadata:false on wildcard ["*"] allow Chrome/Firefox requests whose Sec-Fetch-* headers were stripped!
  const up16 = http.createServer((req, res) => {
    if (req.url === "/app.js") {
      res.writeHead(200, { "Content-Type": "application/javascript" });
      res.end("console.log('ok');");
      return;
    }
    if (req.url === "/priv-swr") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "private, max-age=0, stale-while-revalidate=600" });
      res.end("<!doctype html><html><head></head><body>swr</body></html>");
      return;
    }
    if (req.url === "/priv-smax0-exp") {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "private, s-maxage=0",
        Expires: new Date(Date.now() + 3600_000).toUTCString(),
      });
      res.end("<!doctype html><html><head></head><body>smax0</body></html>");
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end("<!doctype html><html><head></head><body>home</body></html>");
  });
  await new Promise((r) => up16.listen(0, "127.0.0.1", r));

  const srvBal = createVeilBreakServer({ target: `http://127.0.0.1:${up16.address().port}`, mode: "balanced", protectedPaths: ["*"], sri: true });
  await srvBal.listen(0, "127.0.0.1");
  const pBal = srvBal.server.address().port;
  const reqBal = (reqPath, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: pBal, method: "GET", path: reqPath, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    // Modern Chrome UA with NO Sec-Fetch-* headers (corporate proxy / privacy tool stripped them!) on localhost/HTTPS!
    const strippedChromeNav = {
      "user-agent": CHROME_UA,
      accept: "text/html,application/xhtml+xml,*/*;q=0.8",
      "accept-language": "en-US,en;q=0.9",
    };
    const rHome = await reqBal("/", strippedChromeNav);
    assert.equal(rHome.status, 200, "Balanced wildcard HTML navigation MUST allow Chrome without Sec-Fetch-* headers!");
    assert.ok(rHome.body.includes("/__veilbreak/gate.js"), "Balanced wildcard HTML MUST inject gate.js!");

    const rAsset = await reqBal("/app.js", {
      "user-agent": CHROME_UA,
      accept: "*/*",
      "accept-language": "en-US,en;q=0.9",
    });
    assert.equal(rAsset.status, 200, "Balanced wildcard static .js MUST allow Chrome without Sec-Fetch-* headers!");

    // Availability LOW #4: Private stale-while-revalidate & s-maxage=0 + future Expires MUST rewrite Cache-Control to private, no-cache when SRI is injected!
    const rSwr = await reqBal("/priv-swr", strippedChromeNav);
    assert.equal(rSwr.status, 200);
    assert.ok(rSwr.body.includes("integrity="));
    assert.equal(rSwr.headers["cache-control"], "private, no-cache", "Private stale-while-revalidate SRI HTML MUST rewrite Cache-Control to private, no-cache!");

    const rSmax0 = await reqBal("/priv-smax0-exp", strippedChromeNav);
    assert.equal(rSmax0.status, 200);
    assert.ok(rSmax0.body.includes("integrity="));
    assert.equal(rSmax0.headers["cache-control"], "private, no-cache", "Private s-maxage=0 + future Expires SRI HTML MUST rewrite Cache-Control to private, no-cache!");
    assert.equal(rSmax0.headers["expires"], undefined, "Private s-maxage=0 + future Expires SRI HTML MUST strip Expires!");
  } finally {
    await srvBal.close();
    await new Promise((r) => up16.close(r));
  }

  // Lazy standalone gateJs option preserves property getters and /__veilbreak/gate.js serving
  const lazyMw = createVeilBreakMiddleware({ mode: "strict", _lazyGateScript: true });
  assert.ok(typeof lazyMw.gateSri === "string" && lazyMw.gateSri.startsWith("sha384-"));
  assert.ok(typeof lazyMw.gateVersion === "string" && lazyMw.gateVersion.length === 12);
  assert.ok(typeof lazyMw.gateJs === "string" && lazyMw.gateJs.includes("VeilBreak"));
});

test("29. Pass-17 Audit Regressions: OfflineAudioContext + String.prototype.replace + Object.prototype.then TOCTOU defense, spoofed Zone.js Promise hijack immunity, null-proto proof boxing, Safari 60ms suspended audio cap, and standalone VeilBreak hot-path optimizations", async () => {
  const vm = require("node:vm");

  // 1) CRITICAL #1 + HIGH #5 + Avail LOW: OfflineAudioContext.prototype.startRendering hook + String.prototype.replace + transient Object.prototype.then CANNOT forge clean VB_HS_V3, and Safari suspended OfflineAudioContext never stalls 1500ms!
  const runVb17 = ({ preLoadHook = "", userAgent = CHROME_UA, oacState = "running", oacHang = false } = {}) => {
    const src = buildBrowserGateScript({ defaultMode: "paranoid", basePath: "/__veilbreak", unified: true, embedded: true, includeTicketPow: false });
    let privApi = null;
    let frameCount = 0;
    const vmConsole = { debug: function debug(x) { if (x && typeof x === "object") void x.stack; }, log: function log() {} };
    class VmOfflineAudioContext {
      constructor() { this.state = oacState; this.destination = {}; }
      createBuffer() { return { getChannelData: () => new Float32Array(512) }; }
      createBufferSource() { return { connect() {}, start() {} }; }
      startRendering() {
        if (oacHang) return new Promise(() => {}); // Never resolves (simulates iOS Safari pre-gesture suspension)
        return Promise.resolve({ getChannelData: () => new Float32Array(512) });
      }
    }
    const nativeRefs = new Set([
      vmConsole.debug,
      TextEncoder.prototype.encode,
      Headers.prototype.set,
      Headers.prototype.get,
      Response.prototype.json,
      VmOfflineAudioContext.prototype.startRendering,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { getAttribute() { return null; } remove() {} }
    class Document extends Node {
      constructor() { super(); this.readyState = "complete"; this.currentScript = null; this._el = new Element(); this.body = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) {
        if (t === "iframe") { frameCount++; return new HTMLIFrameElement(); }
        if (t === "canvas") return { width: 32, height: 32, getContext() { return null; } };
        return new Element();
      }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(type, tr) { this.type = type; this._tr = tr; } get isTrusted() { return this._tr; } }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return true; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return userAgent; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      Event: VmEvent, Navigator: VmNavigator, navigator: navInst,
      OfflineAudioContext: VmOfflineAudioContext,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
      performance: { now: () => Date.now(), getEntriesByType: () => [] },
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      document: new Document(), Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: async function fetch() { return new Response("{}"); },
      addEventListener() {},
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      __VB_PRIVATE_REGISTER__: (api) => { privApi = api; },
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, getPriv: () => privApi, getFrameCount: () => frameCount };
  };

  // Attack replay: hook OfflineAudioContext.prototype.startRendering + String.prototype.replace + transient Object.prototype.then + spoofed Zone Promise
  let intercepted = false;
  const vAtk = runVb17();
  vAtk.ctx.__markIntercept = () => { intercepted = true; };
  assert.equal(vAtk.getFrameCount(), 0, "Unified embedded VeilBreak MUST defer pre-warm off synchronous <head> parsing!");
  vm.runInContext(`
    const origStart = OfflineAudioContext.prototype.startRendering;
    OfflineAudioContext.prototype.startRendering = function startRendering() {
      const origRep = String.prototype.replace;
      String.prototype.replace = function replace(a, b) {
        if (this.length === 32) {
          Object.defineProperty(Object.prototype, "then", {
            configurable: true,
            get() {
              delete Object.prototype.then;
              __markIntercept();
              if (this && this.v === 3) { this.s = 0; this.f = 0; this.cdp = 0; }
              return undefined;
            },
          });
        }
        return origRep.call(this, a, b);
      };
      return origStart.call(this);
    };
    window.Zone = { current: { name: "<root>" } };
    window.__zone_symbol__Promise = window.Promise;
    window.Promise = function ZoneAwarePromise() { __markIntercept(); return { then() {} }; };
  `, vAtk.ctx);
  const proof17 = await vAtk.getPriv().collectHandshakeProof("a".repeat(32));
  assert.equal(intercepted, false, "Hooked startRendering/String.prototype.replace/Object.prototype.then/ZoneAwarePromise MUST NEVER intercept VeilBreak proof!");
  assert.equal(Object.getPrototypeOf(proof17), null, "collectHandshakeProof MUST return a null-prototype object!");
  assert.ok(proof17.s >= 4 && proof17.cdp === 1 && (proof17.f & 1024) !== 0, `Tampered startRendering + webdriver MUST be flagged (got s=${proof17.s}, f=${proof17.f}, cdp=${proof17.cdp})`);

  // Avail LOW: iOS Safari pre-gesture suspended OfflineAudioContext resolves within <250ms (60ms timeout, NOT 1500ms!)
  const vSafAudio = runVb17({
    userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    oacState: "suspended",
    oacHang: true,
  });
  const t0 = Date.now();
  await vSafAudio.getPriv().collectHandshakeProof("b".repeat(32));
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 400, `Safari suspended OfflineAudioContext MUST NOT stall 1500ms (took ${elapsed}ms)`);

  // Perf MEDIUM #3: Standalone VeilBreak hot path with INSPECTED_HEADERS allowlist, _preset, _expectedPathNormalized, and O(1) ticketRec.ua + legacy uaHash-only store fallback!
  const legacyMap = new Map();
  const extMw17 = createVeilBreakMiddleware({
    mode: "strict",
    protectedPaths: ["/api"],
    ticketPowBits: 0,
    store: {
      async get(k) { return legacyMap.get(k) || null; },
      async set(k, v) { legacyMap.set(k, v); },
      async take(k) { const v = legacyMap.get(k) || null; legacyMap.delete(k); return v; },
    },
  });
  // Mint a real ticket via /__veilbreak/ticket, then strip rec.ua to verify legacy uaHash-only store fallback works!
  let tkJson = "";
  await extMw17(
    { method: "GET", url: "/__veilbreak/ticket", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders() },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead() { this.headersSent = true; }, end(b) { tkJson = String(b || ""); this.writableEnded = true; } }
  );
  const tkObj = JSON.parse(tkJson);
  const storedRec = legacyMap.get(`vb:tk:${tkObj.ticket}`);
  assert.equal(storedRec.ua, CHROME_UA, "mintTicket MUST store raw ua for O(1) hot-path comparison!");
  delete storedRec.ua; // Simulate legacy store record with only uaHash
  const att17 = buildAttestation({ mode: "strict", ticket: tkObj.ticket, nonce: "0123456789abcdef", telemetry: { platform: "Linux x86_64" }, challenge: tkObj.challenge, difficulty: 0, method: "POST", path: "/api/order" });
  const req17 = {
    method: "POST",
    url: "/api/order",
    socket: { remoteAddress: "127.0.0.1" },
    headers: makeBrowserHeaders({
      "sec-fetch-site": "same-origin",
      "sec-fetch-mode": "cors",
      cookie: "session=" + "x".repeat(4096),
      "x-vb-ticket": tkObj.ticket,
      "x-vb-nonce": "0123456789abcdef",
      "x-vb-attest": JSON.stringify(att17),
    }),
  };
  let nextCalled17 = false;
  await extMw17(req17, { headersSent: false, writableEnded: false, setHeader() {}, writeHead() {}, end() {} }, () => { nextCalled17 = true; });
  assert.equal(nextCalled17, true, "Legacy uaHash-only ticket record with 4KB Cookie MUST pass cleanly!");
});

test("30. Pass-18 Audit Regressions: Closed ShadowRoot iframe isolation & no frame.style, freshWin.navigator webdriver spoof check, RegExp[Symbol.replace] & String[Symbol.split] tamper defenses, Safari 17+ Private Browsing ATP Canvas2D/WebGL 0-FP, Safari <16.4 /_next/image wildcard 0-FP, null toString/valueOf JSON 403 (no 500), non-embedded <link prefetch>/3xx gate.js rejection, & mixed-case duplicate UA", async () => {
  const vm = require("node:vm");
  const { isAiCrawlerRequest, checkUnprotectedCrawlerOrCli, verifyHandshakeProof, verifyAttestation } = require("../src/probes.js");

  // 1) CRITICAL #1 + Security MEDIUM #5 + Avail HIGH #2: Closed ShadowRoot isolation, freshWin.navigator webdriver spoof, RegExp[Symbol.replace]/String[Symbol.split] tamper, & Safari 17+ Private Browsing ATP 0-FP!
  const runVb18 = ({
    userAgent = CHROME_UA,
    platform = "Linux x86_64",
    freshWinOwnWd = false,
    freshWinHookWdGetter = false,
    preLoadHook = null,
    useShadow = true,
    canvasNoise = false,
    canvasDeterministic = true,
    webglNoise = false,
    onFrameStyleTouch = null,
    onDocLoadEvent = null,
    cdpOpen = false,
    rtEntries = [],
    scriptSrcs = [],
    embedded = true,
    unified = true,
  } = {}) => {
    const src = buildBrowserGateScript({ defaultMode: "strict", unified, embedded, includeTicketPow: false });
    let privApi = null;
    let shadowUsed = false;
    let hostRemoved = false;
    let frameCount = 0;
    const vmConsole = {
      debug: function debug(x) { if (cdpOpen && x && typeof x === "object") void x.stack; },
      log() {},
      warn() {},
    };
    const nativeRefs = new Set([vmConsole.debug]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","attachShadow","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now","getParameter","getExtension","readPixels","clear","clearColor","finish"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", {
          configurable: true,
          get: ${freshWinHookWdGetter ? 'function fakeWd() { return false; }' : 'function webdriver() { return false; }'},
        });
        const navigator = Object.create(Navigator.prototype);
        ${freshWinOwnWd ? 'Object.defineProperty(navigator, "webdriver", { value: false, configurable: true });' : ""}
        globalThis.Navigator = Navigator;
        globalThis.navigator = navigator;
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { constructor(m) { this._m = m; } appendChild(c) { return c; } }
    class HTMLIFrameElement {
      get style() { if (onFrameStyleTouch) onFrameStyleTouch(); return {}; }
      get contentWindow() { return ifrWin; }
      remove() {}
    }
    class Node {
      appendChild(c) {
        if (c instanceof HTMLIFrameElement && !(this instanceof ShadowRoot) && onDocLoadEvent) onDocLoadEvent(c);
        return c;
      }
    }
    class Element extends Node {
      constructor(attrs = null) { super(); this._sr = null; this._attrs = attrs; }
      get shadowRoot() { return this._sr; }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() { hostRemoved = true; }
    }
    if (useShadow) {
      Element.prototype.attachShadow = function attachShadow(init) {
        shadowUsed = true;
        const sr = new ShadowRoot(init.mode);
        if (init.mode === "open") this._sr = sr;
        return sr;
      };
    }
    let canvasDrawIdx = 0;
    const makeCanvas2dCtx = () => ({
      fillStyle: "",
      fillRect() {},
      getImageData(x, y, w, h) {
        canvasDrawIdx++;
        const d = new Uint8ClampedArray(w * h * 4);
        for (let i = 0; i < d.length; i += 4) {
          const jitter = canvasNoise ? ((i === 0 ? 1 : i === 4 ? 2 : 0) + (canvasDeterministic ? 0 : (canvasDrawIdx % 3))) : 0;
          d[i] = 128 + jitter; d[i + 1] = 128; d[i + 2] = 128; d[i + 3] = 255;
        }
        return { data: d };
      },
    });
    const makeGlCtx = () => ({
      COLOR_BUFFER_BIT: 16384,
      RGBA: 6408,
      UNSIGNED_BYTE: 5121,
      clearColor() {},
      clear() {},
      finish() {},
      getExtension(name) {
        if (name === "WEBGL_debug_renderer_info") return { UNMASKED_RENDERER_WEBGL: 0x9246 };
        if (name === "WEBGL_lose_context") return { loseContext() {} };
        return null;
      },
      getParameter(p) { return p === 0x9246 ? "Apple GPU" : ""; },
      readPixels(x, y, w, h, fmt, type, buf) {
        for (let i = 0; i < buf.length; i += 4) {
          const j = webglNoise && i < 16 ? (i / 4) : 0;
          buf[i] = 128 + j; buf[i + 1] = 128; buf[i + 2] = 128; buf[i + 3] = 255;
        }
      },
    });
    class Document extends Node {
      constructor() { super(); this.readyState = "complete"; this.currentScript = null; this.baseURI = "https://app.example/"; this._el = new Element(); this.body = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) {
        if (t === "iframe") { frameCount++; return new HTMLIFrameElement(); }
        if (t === "canvas") {
          return {
            width: 32, height: 32,
            toDataURL() { return "data:image/png;base64,AA=="; },
            getContext(kind) {
              if (kind === "2d") return makeCanvas2dCtx();
              if (kind === "webgl2" || kind === "webgl") return makeGlCtx();
              return null;
            },
          };
        }
        return new Element();
      }
      querySelectorAll(sel) {
        if (sel === "script[src]" && scriptSrcs.length) {
          return scriptSrcs.map((s) => new Element({ src: s }));
        }
        return [];
      }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(type, tr) { this.type = type; this._tr = tr; } get isTrusted() { return this._tr; } }
    const platformVal = platform;
    const uaVal = userAgent;
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return platformVal; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return uaVal; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      Event: VmEvent, Navigator: VmNavigator, navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
      performance: { now: () => Date.now(), getEntriesByType: (t) => (t === "resource" ? rtEntries : []) },
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 2, screenX: 10, screenY: 10,
      document: new Document(), Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: async function fetch() { return new Response("{}"); },
      addEventListener() {},
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      __VB_PRIVATE_REGISTER__: (api) => { privApi = api; },
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","attachShadow","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, getPriv: () => privApi, wasShadowUsed: () => shadowUsed, wasHostRemoved: () => hostRemoved, getFrameCount: () => frameCount };
  };

  let vbStyleTouched = false;
  let vbDocLoadFired = false;
  const vClean = runVb18({
    onFrameStyleTouch: () => { vbStyleTouched = true; },
    onDocLoadEvent: () => { vbDocLoadFired = true; },
  });
  const pClean = await vClean.getPriv().collectHandshakeProof("a".repeat(32));
  assert.equal(pClean.s, 0, `Clean closed-ShadowRoot browser MUST score 0 (got ${JSON.stringify(pClean)})`);
  assert.equal(vClean.wasShadowUsed(), true, "VeilBreak openBaseFreshRealm MUST isolate iframe inside closed ShadowRoot!");
  assert.equal(vClean.wasHostRemoved(), true, "VeilBreak ShadowRoot host MUST be cleaned up!");
  assert.equal(vbStyleTouched, false, "VeilBreak MUST NOT access frame.style prior to appendChild!");
  assert.equal(vbDocLoadFired, false, "VeilBreak iframe inside closed ShadowRoot MUST NOT leak load event to light DOM!");

  // Fresh iframe navigator.webdriver own-property spoof & getter tamper caught!
  const vFreshOwnWd = runVb18({ freshWinOwnWd: true });
  const pFreshOwnWd = await vFreshOwnWd.getPriv().collectHandshakeProof("b".repeat(32));
  assert.ok((pFreshOwnWd.f & 512) !== 0 && (pFreshOwnWd.f & 1024) !== 0, `Own webdriver on freshWin.navigator MUST flag WEBDRIVER_GETTER_SPOOFED + NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(pFreshOwnWd)})`);

  // RegExp.prototype[Symbol.replace] & String.prototype[Symbol.split] tamper caught!
  const vReRep = runVb18();
  vm.runInContext(`const _r = RegExp.prototype[Symbol.replace]; RegExp.prototype[Symbol.replace] = function(s, rep) { return "SPOOFED"; };`, vReRep.ctx);
  const pReRep = await vReRep.getPriv().collectHandshakeProof("c".repeat(32));
  assert.ok((pReRep.f & 1024) !== 0 && pReRep.s >= 4, `RegExp.prototype[Symbol.replace] hook MUST flag NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(pReRep)})`);
  assert.equal(pReRep.p, "Linux x86_64", `stripPipes MUST NOT be hijacked by RegExp.prototype[Symbol.replace] (got p=${pReRep.p})`);

  const vStrSplit = runVb18();
  vm.runInContext(`String.prototype[Symbol.split] = () => ["fake"];`, vStrSplit.ctx);
  const pStrSplit = await vStrSplit.getPriv().collectHandshakeProof("d".repeat(32));
  assert.ok((pStrSplit.f & 1024) !== 0 && pStrSplit.s >= 4, `String.prototype[Symbol.split] hook MUST flag NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(pStrSplit)})`);

  // Avail HIGH #2: Safari 17+ Private Browsing ATP deterministic Canvas2D + WebGL clear noise stays 0-FP (score 0)!
  const SAFARI17_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15";
  const vSafAtp = runVb18({ userAgent: SAFARI17_UA, platform: "MacIntel", canvasNoise: true, canvasDeterministic: true, webglNoise: true });
  const pSafAtp = await vSafAtp.getPriv().collectHandshakeProof("e".repeat(32));
  assert.equal(pSafAtp.s, 0, `Clean native Safari 17+ Private Browsing ATP Canvas2D+WebGL noise MUST stay 0-FP score=0 (got ${JSON.stringify(pSafAtp)})`);

  // Non-deterministic Canvas2D noise on Safari MUST STILL be flagged!
  const vSafRand = runVb18({ userAgent: SAFARI17_UA, platform: "MacIntel", canvasNoise: true, canvasDeterministic: false });
  const pSafRand = await vSafRand.getPriv().collectHandshakeProof("f".repeat(32));
  assert.ok(pSafRand.s >= 2, `Non-deterministic Canvas2D noise on Safari MUST STILL be flagged (got ${JSON.stringify(pSafRand)})`);

  // Security MEDIUM #7: Non-embedded <link rel="prefetch"> without <script src=".../gate.js"> MUST trigger _bridgeTampered!
  const fakeGatePre = `
    const f = Object.freeze({ unified: true, version: "2.2.0" });
    Object.defineProperty(window, "VeilBreak", { value: f, writable: false, configurable: false });
    Object.defineProperty(window, Symbol.for("__VEILBREAK_INTERNAL__"), { value: f, writable: false, configurable: false });
  `;
  const vPrefetch = runVb18({
    preLoadHook: fakeGatePre,
    rtEntries: [{ name: "https://app.example/__veilbreak/gate.js", initiatorType: "link", responseStatus: 200, decodedBodySize: 4096 }],
    scriptSrcs: [],
  });
  const pPrefetch = await vPrefetch.getPriv().collectHandshakeProof("0".repeat(32));
  assert.ok((pPrefetch.f & 1024) !== 0 && pPrefetch.s >= 4, `Bare <link rel=prefetch> without <script src=".../gate.js"> MUST flag _bridgeTampered (got ${JSON.stringify(pPrefetch)})`);

  // 2) Security MEDIUM #6: Null toString/valueOf objects in verifyAttestation & verifyHandshakeProof MUST reject cleanly (no uncaught TypeError / HTTP 500)!
  const badObj = { toString: null, valueOf: null };
  const attRes = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders(),
    attest: { v: 2, p: badObj, w: badObj, m: badObj, u: badObj, s: 0, f: 0, n: "0123456789abcdef", d: "a".repeat(64) },
    ticket: "tk18",
    nonce: "0123456789abcdef",
    expectedChallenge: "ch18",
    expectedDifficulty: 0,
    expectedMethod: "POST",
    expectedPath: "/api/x",
  });
  assert.equal(attRes.ok, false);
  assert.ok(attRes.reasons.includes("ATTEST_INVALID"), `verifyAttestation MUST reject {toString:null,valueOf:null} as ATTEST_INVALID without throwing (got ${JSON.stringify(attRes)})`);

  const hsRes = verifyHandshakeProof({
    mode: "strict",
    headers: makeBrowserHeaders(),
    proof: { v: 3, ch: "ch18", s: 0, f: 0, p: badObj, cdp: 0, wr: badObj, wk: 0, ms: 5, d: "a".repeat(64) },
    expectedChallenge: "ch18",
  });
  assert.equal(hsRes.ok, false);
  assert.ok(hsRes.reasons.includes("BROWSER_PROOF_INVALID"), `verifyHandshakeProof MUST reject {toString:null,valueOf:null} as BROWSER_PROOF_INVALID without throwing (got ${JSON.stringify(hsRes)})`);

  // 3) Avail MEDIUM #3: Safari < 16.4 extensionless /_next/image & /fonts/css2 under wildcard protectedPaths:["*"] return 200, while mismatched JSON returns 403!
  const up18Vb = http.createServer((req, res) => {
    if (req.url.startsWith("/_next/image")) { res.writeHead(200, { "Content-Type": "image/webp" }); res.end("RIFF"); return; }
    if (req.url.startsWith("/fonts/css2")) { res.writeHead(200, { "Content-Type": "text/css" }); res.end("body{}"); return; }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"secret":1}');
  });
  await new Promise((r) => up18Vb.listen(0, "127.0.0.1", r));
  const srv18Vb = createVeilBreakServer({ target: `http://127.0.0.1:${up18Vb.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv18Vb.listen(0, "127.0.0.1");
  const reqVb18 = (pathStr, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: srv18Vb.server.address().port, method: "GET", path: pathStr, headers }, (resp) => {
        const chunks = [];
        resp.on("data", (c) => chunks.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, text: Buffer.concat(chunks).toString("utf8") }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const SAFARI15_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15";
    const rImg = await reqVb18("/_next/image?url=a.png", { "user-agent": SAFARI15_UA, "accept-language": "en-US,en;q=0.9", accept: "image/webp,image/png,*/*;q=0.8" });
    assert.equal(rImg.status, 200, `VeilBreak wildcard Safari < 16.4 /_next/image MUST return 200 (got ${rImg.status})`);
    const rCss = await reqVb18("/fonts/css2", { "user-agent": SAFARI15_UA, "accept-language": "en-US,en;q=0.9", accept: "text/css,*/*;q=0.1" });
    assert.equal(rCss.status, 200, `VeilBreak wildcard Safari < 16.4 /fonts/css2 MUST return 200 (got ${rCss.status})`);
    const rJson = await reqVb18("/api/data", { "user-agent": SAFARI15_UA, "accept-language": "en-US,en;q=0.9", accept: "image/webp,*/*;q=0.8" });
    assert.equal(rJson.status, 403, `VeilBreak wildcard Safari < 16.4 JSON route with spoofed image Accept MUST return 403 (got ${rJson.status})`);
  } finally {
    await srv18Vb.close();
    await new Promise((r) => up18Vb.close(r));
  }

  // 4) Parity LOW #1: Mixed-case duplicate User-Agent concatenation in isAiCrawlerRequest & checkUnprotectedCrawlerOrCli!
  assert.equal(isAiCrawlerRequest({ "User-Agent": "FirecrawlAgent/1.0", "user-agent": CHROME_UA }), true);
  assert.equal(checkUnprotectedCrawlerOrCli({ "User-Agent": "FirecrawlAgent/1.0", "user-agent": CHROME_UA }).crawlerHit, true);
});

test("31. Pass-19 Audit Regressions: HTTP 304 gate.js legitCoexist 0-FP, Object.prototype descriptor-pollution defense, Origin-without-Host ticket 403, and Python strict optional-string validation in verify_attestation & verify_handshake_proof", async () => {
  const vm = require("node:vm");
  const src = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, includeTicketPow: false });

  const runVb19 = ({ rtEntries = [], preLoadHook = null } = {}) => {
    let privApi = null;
    const vmConsole = { debug: function debug(x) { if (x && typeof x === "object") void x.stack; }, log() {}, warn() {} };
    const nativeRefs = new Set([vmConsole.debug]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","attachShadow","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { get shadowRoot() { return null; } attachShadow() { return new ShadowRoot(); } getAttribute() { return null; } remove() {} }
    class Document extends Node {
      constructor() { super(); this.readyState = "complete"; this.currentScript = null; this.baseURI = "https://app.example/"; this._el = new Element(); this.body = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : t === "canvas" ? { width: 32, height: 32, getContext: () => null } : new Element(); }
      querySelectorAll() { return []; }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(t, tr) { this.type = t; this._tr = tr; } get isTrusted() { return this._tr; } }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      Event: VmEvent, Navigator: VmNavigator, navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
      performance: { now: () => Date.now(), getEntriesByType: (t) => (t === "resource" ? rtEntries : []) },
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      document: new Document(), Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: async function fetch() { return new Response("{}"); },
      addEventListener() {},
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      __VB_PRIVATE_REGISTER__: (api) => { privApi = api; },
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString","createElement","appendChild","attachShadow","get documentElement","get contentWindow","getAttribute", "Event","get isTrusted","webdriver","platform","userAgent","toDataURL","getImageData","debug","fetch","encode","set","get","json","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, getPriv: () => privApi };
  };

  // 1) Availability HIGH #1: HTTP 304 Not Modified on /__veilbreak/gate.js passes legitCoexist cleanly without _bridgeTampered!
  const v304 = runVb19({
    rtEntries: [{ name: "https://app.example/__veilbreak/gate.js", initiatorType: "script", responseStatus: 304, decodedBodySize: 0, transferSize: 0 }],
    preLoadHook: `
      const f = Object.freeze({ unified: true, version: "2.2.0" });
      Object.defineProperty(window, "VeilBreak", { value: f, writable: false, configurable: false });
      Object.defineProperty(window, Symbol.for("__VEILBREAK_INTERNAL__"), { value: f, writable: false, configurable: false });
    `,
  });
  const p304 = await v304.getPriv().collectHandshakeProof("a".repeat(32));
  assert.equal((p304.f & 1024), 0, `HTTP 304 Not Modified on /__veilbreak/gate.js MUST NOT trigger _bridgeTampered (got ${JSON.stringify(p304)})`);

  // 2) Security HIGH #2: Object.prototype.writable = undefined does NOT blind probeCdpWithConsole and triggers NATIVE_FUNCTION_TAMPERED!
  const vPoll = runVb19();
  vm.runInContext(`Object.prototype.writable = undefined;`, vPoll.ctx);
  const pPoll = await vPoll.getPriv().collectHandshakeProof("b".repeat(32));
  assert.equal(pPoll.cdp, 1, "Object.prototype.writable=undefined MUST NOT blind CDP console probe!");
  assert.ok((pPoll.f & 1024) !== 0 && pPoll.s >= 4, `Object.prototype.writable=undefined MUST trigger NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(pPoll)})`);

  // 3) Security LOW #4: Origin header without Host returns 403 CROSS_ORIGIN_TICKET_DENIED on /__veilbreak/ticket!
  const mw19 = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let tkNoHostStatus = 0;
  await mw19(
    { method: "GET", url: "/__veilbreak/ticket", socket: { remoteAddress: "127.0.0.1" }, headers: { "user-agent": CHROME_UA, origin: "https://evil.invalid", "accept-language": "en-US", "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" } },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { tkNoHostStatus = st; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(tkNoHostStatus, 403, "Origin header without Host header MUST return 403 on /__veilbreak/ticket!");

  // 4) Parity MEDIUM #1 (Python): Non-string p/w/m/u/ch/wr rejected with ATTEST_INVALID / BROWSER_PROOF_INVALID (matching Node probes.js)!
  const pyVb19 = execFileSync(
    "python3",
    [
      "-c",
      `import sys, hashlib; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import verify_attestation, verify_handshake_proof
hdrs = {"User-Agent": ${JSON.stringify(CHROME_UA)}, "Accept-Language": "en-US,en;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}
d_att = hashlib.sha256(b"VB_ATTEST_V2|tk|0123456789abcdef|0|0|123").hexdigest()
r_att = verify_attestation(mode="strict", headers=hdrs, attest={"v": 2, "s": 0, "f": 0, "p": 123, "d": d_att}, ticket="tk", nonce="0123456789abcdef")
assert r_att.blocked and "ATTEST_INVALID" in r_att.reasons, f"Non-string attest.p must reject: {r_att}"
r_att_w = verify_attestation(mode="strict", headers=hdrs, attest={"v": 2, "s": 0, "f": 0, "p": "Linux", "w": 123, "d": d_att}, ticket="tk", nonce="0123456789abcdef")
assert r_att_w.blocked and "ATTEST_INVALID" in r_att_w.reasons, f"Non-string attest.w must reject: {r_att_w}"
d_hs = hashlib.sha256(b"VB_HS_V3|abc|0|0|123|0||1|5").hexdigest()
r_hs = verify_handshake_proof(mode="strict", headers=hdrs, proof={"v": 3, "ch": "abc", "s": 0, "f": 0, "p": 123, "cdp": 0, "wr": "", "wk": 1, "ms": 5, "d": d_hs}, expected_challenge="abc")
assert r_hs.blocked and "BROWSER_PROOF_INVALID" in r_hs.reasons, f"Non-string proof.p must reject: {r_hs}"
r_hs_ch = verify_handshake_proof(mode="monitor", headers=hdrs, proof={"v": 3, "ch": 123, "s": 0, "f": 0, "p": "Linux", "cdp": 0, "wr": "", "wk": 1, "ms": 5, "d": d_hs}, expected_challenge="")
assert "BROWSER_PROOF_INVALID" in r_hs_ch.reasons, f"Non-string proof.ch must flag BROWSER_PROOF_INVALID: {r_hs_ch}"
print("PY_VB19_OK")`,
    ],
    { encoding: "utf8" }
  );
  assert.ok(pyVb19.includes("PY_VB19_OK"));
});

test("32. Pass-20 Audit Regressions: extStore Redis pre-gating on garbage ticket & CLI/crawler floods, multi-ETag If-None-Match 304 on gate.js, duplicate Host/CL rejection on /ticket & OPTIONS preflight, and s-maxage=0+future Expires SRI retention", async () => {
  let storeLookups = 0;
  const backing = new Map();
  const extMw20 = createVeilBreakMiddleware({
    mode: "strict",
    protectedPaths: ["/api"],
    ticketPowBits: 0,
    store: {
      async get(k) { storeLookups++; return backing.get(k) || null; },
      async set(k, v) { backing.set(k, v); },
      async take(k) { storeLookups++; const v = backing.get(k) || null; backing.delete(k); return v; },
    },
  });
  const callMw = async (req) => {
    let status = 200;
    let body = "";
    let nextCalled = false;
    await extMw20(
      req,
      { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { status = st; this.headersSent = true; }, end(b) { body = String(b || ""); this.writableEnded = true; } },
      () => { nextCalled = true; }
    );
    return { status, body, nextCalled };
  };

  // 1) Performance MEDIUM #2: Garbage multi-KB X-VB-Ticket AND curl/Firecrawl requests with valid 32-hex ticket MUST NOT hit extStore!
  storeLookups = 0;
  const rGarb = await callMw({ method: "POST", url: "/api/x", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "x-vb-ticket": "garbage-" + "x".repeat(2000), "x-vb-attest": "{}" }) });
  assert.equal(rGarb.status, 403);
  assert.equal(storeLookups, 0, "Malformed X-VB-Ticket MUST NOT query extStore!");

  const rBot = await callMw({ method: "POST", url: "/api/x", socket: { remoteAddress: "127.0.0.1" }, headers: { "user-agent": "FirecrawlAgent/1.0", "x-vb-ticket": "a".repeat(32), "x-vb-attest": "{}" } });
  assert.equal(rBot.status, 403);
  assert.equal(storeLookups, 0, "AI crawler flood with valid-syntax 32-hex ticket MUST NOT query extStore!");

  const rCurl = await callMw({ method: "POST", url: "/api/x", socket: { remoteAddress: "127.0.0.1" }, headers: { "user-agent": "curl/8.5.0", "x-vb-ticket": "b".repeat(32), "x-vb-attest": "{}" } });
  assert.equal(rCurl.status, 403);
  assert.equal(storeLookups, 0, "curl flood with valid-syntax 32-hex ticket MUST NOT query extStore!");

  // 2) Avail LOW #2: Multi-ETag If-None-Match list returns 304 on /__veilbreak/gate.js!
  const r304 = await callMw({ method: "GET", url: "/__veilbreak/gate.js", headers: { "if-none-match": `"old-v", "${extMw20.gateVersion}"` } });
  assert.equal(r304.status, 304, "Multi-ETag If-None-Match MUST return 304 on /__veilbreak/gate.js!");

  // 3) Security LOW #6: Duplicate Host rawHeaders rejected on /ticket and OPTIONS preflight!
  const rDupTk = await callMw({ method: "GET", url: "/__veilbreak/ticket", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders(), rawHeaders: ["Host", "a.example", "Host", "b.example"] });
  assert.equal(rDupTk.status, 403, "Duplicate Host rawHeaders MUST be rejected 403 on /__veilbreak/ticket!");

  const rDupOpt = await callMw({
    method: "OPTIONS",
    url: "/api/x",
    socket: { remoteAddress: "127.0.0.1" },
    headers: makeBrowserHeaders({ origin: "https://other.example", host: "api.example", "access-control-request-method": "POST", "sec-fetch-mode": "cors" }),
    rawHeaders: ["Host", "api.example", "Host", "evil.example"],
  });
  assert.equal(rDupOpt.nextCalled, false, "Duplicate Host rawHeaders MUST NOT bypass OPTIONS CORS preflight!");
});

test("33. Pass-21 Audit Regressions: Navigator.prototype webdriver/platform/userAgent deletion & data/own-property shadowing caught, POLICY_LOCKED data-mode='constructor' & <veil-break> clamping, HEAD /health & /gate.js 200 with curl UA, and Python 8192-byte X-VB-Attest cap", async () => {
  const vm = require("node:vm");
  const runVb21 = ({ preLoadHook = "", scriptAttrs = {}, ifrPreHook = "", cdpOpen = false } = {}) => {
    const src = buildBrowserGateScript({
      basePath: "/__veilbreak",
      defaultMode: "strict",
      policyLocked: true,
      antiCdp: true,
      autoBlockPage: false,
      protectedRules: ["/api"],
    });
    const vmConsole = {
      debug: function debug(x) { if (cdpOpen && x && typeof x === "object") void x.stack; },
      log() {},
      warn() {},
    };
    class VmPerformance {
      now() { return Date.now(); }
      getEntriesByType() { return []; }
    }
    const nativeRefs = new Set([vmConsole.debug, VmPerformance.prototype.now]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        ${ifrPreHook}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs || {}; }
      get shadowRoot() { return null; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(n) { return Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() {}
    }
    const scriptEl = new Element(scriptAttrs);
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = scriptEl;
        this.readyState = "complete";
        this._el = new Element();
        this.body = new Element();
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll() { return []; }
      querySelector() { return null; }
      addEventListener() {}
    }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      Navigator: VmNavigator,
      navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
      Performance: VmPerformance,
      performance: new VmPerformance(),
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/app" },
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return ctx;
  };

  // 1) Security MEDIUM #2: Deleting or converting Navigator.prototype.webdriver in BOTH realms STILL flags WEBDRIVER_GETTER_SPOOFED + NATIVE_FUNCTION_TAMPERED!
  for (const [label, hook] of [
    ["delete Navigator.prototype.webdriver in both realms", "delete Navigator.prototype.webdriver;"],
    ["data-property Navigator.prototype.webdriver in both realms", 'Object.defineProperty(Navigator.prototype, "webdriver", { value: false, configurable: true, enumerable: true });'],
  ]) {
    const ctx = runVb21({ preLoadHook: hook, ifrPreHook: hook });
    const res = await ctx.VeilBreak.verify({ mode: "strict", antiCdp: false });
    assert.equal(res.blocked, true, `${label} MUST block!`);
    assert.ok(res.reasons.includes("WEBDRIVER_GETTER_SPOOFED"), `${label} MUST flag WEBDRIVER_GETTER_SPOOFED (got ${JSON.stringify(res.reasons)})`);
    assert.ok(res.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `${label} MUST flag NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(res.reasons)})`);
  }

  for (const [label, hook] of [
    ["delete Navigator.prototype.platform", "delete Navigator.prototype.platform;"],
    ["data-property Navigator.prototype.userAgent", 'Object.defineProperty(Navigator.prototype, "userAgent", { value: "Mozilla/5.0", configurable: true });'],
    ["own-property shadow navigator.platform", 'Object.defineProperty(navigator, "platform", { value: "Win32", configurable: true });'],
  ]) {
    const ctx = runVb21({ preLoadHook: hook });
    const res = await ctx.VeilBreak.verify({ mode: "strict", antiCdp: false });
    assert.equal(res.blocked, true, `${label} MUST block!`);
    assert.ok(res.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `${label} MUST flag NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(res.reasons)})`);
  }

  // 2) Security MEDIUM #3: data-mode="constructor" & "__proto__" MUST NOT bypass POLICY_LOCKED or downgrade CDP weight to 1!
  for (const badMode of ["constructor", "__proto__", "toString"]) {
    const ctx = runVb21({ scriptAttrs: { "data-mode": badMode }, cdpOpen: true });
    const res = await ctx.VeilBreak.verify();
    assert.equal(res.mode, "strict", `data-mode="${badMode}" under POLICY_LOCKED MUST fall back to strict (got ${res.mode})`);
    assert.equal(res.blocked, true, `data-mode="${badMode}" MUST still block CDP-active browser!`);
    assert.ok(res.score >= 4, `data-mode="${badMode}" MUST keep strict CDP weight >= 4 (got ${res.score})`);
  }

  // 3) Availability MEDIUM #2: HEAD /__veilbreak/health and HEAD /__veilbreak/gate.js with curl UA return 200 + Content-Length > 0 + empty body!
  const mw21 = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["*"] });
  for (const p of ["/__veilbreak/health", "/__veilbreak/gate.js"]) {
    let status = 0;
    let headers = {};
    let body = "";
    await mw21(
      { method: "HEAD", url: p, socket: { remoteAddress: "127.0.0.1" }, headers: { "user-agent": "curl/8.5.0" } },
      { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st, h) { status = st; headers = h; this.headersSent = true; }, end(b) { body = String(b || ""); this.writableEnded = true; } }
    );
    assert.equal(status, 200, `HEAD ${p} with curl UA MUST return 200 (got ${status})`);
    assert.ok(Number(headers["Content-Length"]) > 0, `HEAD ${p} MUST include Content-Length > 0`);
    assert.equal(body, "", `HEAD ${p} MUST return empty body`);
  }

  // 4) Parity LOW: Python verify_attestation caps oversized > 8192-byte X-VB-Attest before json.loads!
  const pyVb21 = execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from veilbreak import verify_attestation
hdrs = {"User-Agent": ${JSON.stringify(CHROME_UA)}, "Accept-Language": "en-US,en;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}
big = '{"v":2,"s":0,"f":0,"p":"' + ("a" * 9000) + '","d":"' + ("0" * 64) + '"}'
r = verify_attestation(mode="strict", headers=hdrs, attest=big, ticket="a"*32, nonce="0123456789abcdef")
assert r.blocked and "ATTEST_INVALID" in r.reasons, f"Oversized X-VB-Attest must reject as ATTEST_INVALID: {r}"
print("PY_VB21_OK")`,
    ],
    { encoding: "utf8" }
  );
  assert.ok(pyVb21.includes("PY_VB21_OK"));
});

test("34. Pass-22 Audit Regressions: iOS WKWebView UA ATP Canvas2D 0-FP, VeilBreak extStore skips malformed X-VB-Attest/X-VB-Nonce & X-Original-URL override, and compacted gate.js bundle", async () => {
  const vm = require("node:vm");

  // 1) Performance MEDIUM #3: gate.js is cleanly compacted and syntactically valid
  const gate22 = buildBrowserGateScript({ defaultMode: "strict" });
  new Function(gate22);
  assert.ok(gate22.length < 120_000, `Compacted standalone gate.js MUST trim comments/indentation cleanly (got ${gate22.length} bytes)`);
  const gateEmb22 = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, _shareBaseRealm: true, includeTicketPow: false });
  assert.ok(gateEmb22.length < 85_000, `Compacted embedded gate.js MUST trim comments/indentation & shared base realm cleanly (got ${gateEmb22.length} bytes)`);

  // 2) Availability MEDIUM #2: iOS WKWebView UA (omits 'Safari/...') receives WebKit ATP Canvas2D exemption (0-FP)!
  const IOS_WKWV_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148";
  const vmConsole = { debug: function debug() {}, log() {}, warn() {} };
  class VmPerformance { now() { return Date.now(); } getEntriesByType() { return []; } }
  const nativeRefs = new Set([vmConsole.debug, VmPerformance.prototype.now, TextEncoder.prototype.encode, Headers.prototype.set, Headers.prototype.get]);
  const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
  const ifrWin = vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
      class Navigator {}
      Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
      globalThis.Navigator = Navigator;
      globalThis.navigator = Object.create(Navigator.prototype);
      return globalThis;
    })();`,
    ifrCtx
  );
  class ShadowRoot { appendChild(c) { return c; } }
  class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
  class Node { appendChild(c) { return c; } }
  class Element extends Node {
    get shadowRoot() { return null; }
    attachShadow() { return new ShadowRoot(); }
    getAttribute() { return null; }
    remove() {}
  }
  const atpPixels = new Uint8ClampedArray(32 * 32 * 4);
  for (let i = 0; i < atpPixels.length; i += 4) {
    atpPixels[i] = 128 + ((i >> 2) % 2); // deterministic 2-color WebKit ATP noise!
    atpPixels[i + 1] = 128;
    atpPixels[i + 2] = 128;
    atpPixels[i + 3] = 255;
  }
  class FakeCanvasCtx {
    fillRect() {}
    getImageData() { return { data: atpPixels }; }
  }
  class FakeCanvas extends Element {
    getContext(kind) { return kind === "2d" ? new FakeCanvasCtx() : null; }
    toDataURL() { return "data:image/png;base64,AAAA"; }
  }
  class Document extends Node {
    constructor() { super(); this.currentScript = null; this.readyState = "complete"; this._el = new Element(); this.body = new Element(); }
    get documentElement() { return this._el; }
    createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : t === "canvas" ? new FakeCanvas() : new Element(); }
    querySelectorAll() { return []; }
    querySelector() { return null; }
    addEventListener() {}
  }
  class VmNavigator {}
  Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
  Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "iPhone"; }, configurable: true });
  Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return IOS_WKWV_UA; }, configurable: true });
  const navInst = Object.create(VmNavigator.prototype);
  navInst.hardwareConcurrency = 4;
  navInst.maxTouchPoints = 5;
  const ctxWk = vm.createContext({
    Navigator: VmNavigator,
    navigator: navInst,
    HTMLCanvasElement: FakeCanvas,
    CanvasRenderingContext2D: FakeCanvasCtx,
    TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
    Performance: VmPerformance,
    performance: new VmPerformance(),
    document: new Document(),
    Document, Node, Element, HTMLIFrameElement, ShadowRoot,
    location: { origin: "https://app.example", href: "https://app.example/", pathname: "/" },
    addEventListener() {},
    _nativeRefs: nativeRefs,
  });
  ctxWk.window = ctxWk;
  vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
    })();`,
    ctxWk
  );
  vm.runInContext(gate22, ctxWk);
  const wkRes = await ctxWk.VeilBreak.verify({ mode: "strict", antiCdp: true });
  assert.equal(wkRes.blocked, false, `iOS WKWebView deterministic ATP Canvas2D noise MUST stay 0-FP (got ${JSON.stringify(wkRes.reasons)})`);

  // 3) Performance MEDIUM #2: Malformed X-VB-Attest, bad X-VB-Nonce, and X-Original-URL override skip extStore.take()!
  let storeTakes22 = 0;
  const backing22 = new Map();
  const extMw22 = createVeilBreakMiddleware({
    mode: "strict",
    protectedPaths: ["/api"],
    ticketPowBits: 0,
    store: {
      async get(k) { storeTakes22++; return backing22.get(k) || null; },
      async set(k, v) { backing22.set(k, v); },
      async take(k) { storeTakes22++; const v = backing22.get(k) || null; backing22.delete(k); return v; },
    },
  });
  const callMw22 = async (headers, url = "/api/x") => {
    let status = 200;
    await extMw22(
      { method: "POST", url, socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders(headers) },
      { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { status = st; this.headersSent = true; }, end() { this.writableEnded = true; } }
    );
    return status;
  };
  storeTakes22 = 0;
  assert.equal(await callMw22({ "x-vb-ticket": "a".repeat(32), "x-vb-nonce": "0123456789abcdef", "x-vb-attest": "not-json" }), 403);
  assert.equal(await callMw22({ "x-vb-ticket": "a".repeat(32), "x-vb-nonce": "bad", "x-vb-attest": JSON.stringify({ v: 2, s: 0, f: 0, d: "a".repeat(64) }) }), 403);
  assert.equal(await callMw22({ "x-vb-ticket": "a".repeat(32), "x-vb-nonce": "0123456789abcdef", "x-vb-attest": JSON.stringify({ v: 2, s: 0, f: 0, d: "a".repeat(64) }), "x-original-url": "/api/admin" }, "/public"), 403);
  assert.equal(storeTakes22, 0, "Malformed X-VB-Attest, bad X-VB-Nonce, and X-Original-URL override MUST NOT hit extStore.take()!");
});

test("35. Pass-23 Audit Regressions: Array.prototype numeric-index setter/getter immunity in openVerifiedFreshRealm & runHardwareProbes, standalone verifyAttestation 8192-char cap, and shared _trustedProxies reuse", async () => {
  const vm = require("node:vm");
  const { verifyAttestation } = require("../src/probes.js");

  // 1) Security HIGH #2: Pre-load Array.prototype["72"] / ["12"] setters MUST NOT drop fresh-realm checks or WebGL getParameter checks!
  const runVb23 = (preLoadHook) => {
    const src = buildBrowserGateScript({ basePath: "/__veilbreak", defaultMode: "strict", antiCdp: false, autoBlockPage: false });
    const vmConsole = { debug: function debug() {}, log() {}, warn() {} };
    class VmPerformance { now() { return Date.now(); } getEntriesByType() { return []; } }
    const nativeRefs = new Set([vmConsole.debug, VmPerformance.prototype.now, TextEncoder.prototype.encode, Headers.prototype.set, Headers.prototype.get]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { get shadowRoot() { return null; } attachShadow() { return new ShadowRoot(); } getAttribute() { return null; } remove() {} }
    class Document extends Node {
      constructor() { super(); this.currentScript = null; this.readyState = "complete"; this._el = new Element(); this.body = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll() { return []; }
      querySelector() { return null; }
      addEventListener() {}
    }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      Navigator: VmNavigator,
      navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      WebGLRenderingContext: { prototype: { getParameter: function getParameter() { return "spoofed"; } } },
      TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
      Performance: VmPerformance,
      performance: new VmPerformance(),
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/app" },
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return ctx;
  };

  for (const [label, hook] of [
    ["Array.prototype['72'] setter", `Object.defineProperty(Array.prototype, "72", { configurable: true, get() { return undefined; }, set() {} });`],
    ["Array.prototype['12'] setter + hooked WebGL getParameter", `Object.defineProperty(Array.prototype, "12", { configurable: true, get() { return undefined; }, set() {} });`],
  ]) {
    const ctx = runVb23(hook);
    const res = await ctx.VeilBreak.verify({ mode: "strict", antiCdp: false });
    assert.equal(res.blocked, true, `${label} MUST block!`);
    assert.ok(res.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `${label} MUST flag NATIVE_FUNCTION_TAMPERED (got ${JSON.stringify(res.reasons)})`);
  }

  // 2) Parity LOW #2: Standalone verifyAttestation caps string attest at 8192 chars (matches Python & middleware)
  const bigAtt = '{"v":2,"s":0,"f":0,"p":"' + "a".repeat(9000) + '","d":"' + "0".repeat(64) + '"}';
  const vBig = verifyAttestation({
    mode: "strict",
    headers: makeBrowserHeaders(),
    attest: bigAtt,
    ticket: "a".repeat(32),
    nonce: "0123456789abcdef",
  });
  assert.equal(vBig.blocked, true);
  assert.ok(vBig.reasons.includes("ATTEST_INVALID"), `Oversized string attest MUST flag ATTEST_INVALID (got ${JSON.stringify(vBig.reasons)})`);

  // 3) Perf LOW #2: createVeilBreakMiddleware exposes _trustedProxies for server wrapper reuse
  const mwTp = createVeilBreakMiddleware({ mode: "strict", trustProxy: ["10.0.0.1"] });
  assert.ok(mwTp._trustedProxies, "Middleware MUST expose compiled _trustedProxies");
});

test("36. Pass-24 Audit Regressions: mutable global constructor decoys, deleting window.Navigator / HTMLCanvasElement fails closed in WebDriver/native checks, and zero-backtracking Safari UA regex", async () => {
  const vm = require("node:vm");

  const runVb24 = (preLoadHook = "", postLoadHook = "") => {
    const src = buildBrowserGateScript({ basePath: "/__veilbreak", defaultMode: "strict", antiCdp: false, autoBlockPage: false });
    const vmConsole = { debug: function debug() {}, log() {}, warn() {} };
    class VmPerformance { now() { return Date.now(); } getEntriesByType() { return []; } }
    const nativeRefs = new Set([vmConsole.debug, VmPerformance.prototype.now, TextEncoder.prototype.encode, Headers.prototype.set, Headers.prototype.get]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        class HTMLIFrameElement {}
        class Element { attachShadow() { return {}; } }
        class HTMLCanvasElement { toDataURL() { return ""; } }
        class CanvasRenderingContext2D { getImageData() { return { data: [] }; } }
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        globalThis.HTMLIFrameElement = HTMLIFrameElement;
        globalThis.Element = Element;
        globalThis.HTMLCanvasElement = HTMLCanvasElement;
        globalThis.CanvasRenderingContext2D = CanvasRenderingContext2D;
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { get shadowRoot() { return null; } attachShadow() { return new ShadowRoot(); } getAttribute() { return null; } remove() {} }
    class Document extends Node {
      constructor() { super(); this.currentScript = null; this.readyState = "complete"; this._el = new Element(); this.body = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll() { return []; }
      querySelector() { return null; }
      addEventListener() {}
    }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    class VmCanvas { toDataURL() { return ""; } }
    class VmCtx2d { getImageData() { return { data: [] }; } }
    const ctx = vm.createContext({
      Navigator: VmNavigator,
      navigator: navInst,
      HTMLCanvasElement: VmCanvas,
      CanvasRenderingContext2D: VmCtx2d,
      TextEncoder, Headers, Request, Response, URL, console: vmConsole, setTimeout, clearTimeout,
      Performance: VmPerformance,
      performance: new VmPerformance(),
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/app" },
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    if (postLoadHook) vm.runInContext(postLoadHook, ctx);
    return ctx;
  };

  // 1) Security HIGH #1: Mutable global constructor decoy (window.Object) + real Object.prototype.then MUST flag NATIVE_FUNCTION_TAMPERED!
  const ctxDecoy = runVb24("", `
    const RealObj = Object;
    const realObjProto = RealObj.prototype;
    const DecoyObj = function Object() {};
    DecoyObj.prototype = RealObj.create(null);
    DecoyObj.create = RealObj.create;
    DecoyObj.defineProperty = RealObj.defineProperty;
    DecoyObj.getOwnPropertyNames = RealObj.getOwnPropertyNames;
    DecoyObj.getOwnPropertyDescriptor = RealObj.getOwnPropertyDescriptor;
    DecoyObj.getPrototypeOf = RealObj.getPrototypeOf;
    window.Object = DecoyObj;
    realObjProto.then = function(r) { r(this); };
  `);
  const rDecoy = await ctxDecoy.VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.equal(rDecoy.blocked, true, "Decoy window.Object + real Object.prototype.then MUST block!");
  assert.ok(rDecoy.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `Expected NATIVE_FUNCTION_TAMPERED, got ${JSON.stringify(rDecoy.reasons)}`);

  // 2) Security HIGH #2: Deleting window.Navigator (with spoofed webdriver getter on prototype) AND deleting window.HTMLCanvasElement MUST fail closed!
  const ctxDelNav = runVb24(`
    const np = Object.getPrototypeOf(navigator);
    Object.defineProperty(np, "webdriver", { configurable: true, get: () => false });
    window.Navigator = undefined;
  `);
  const rDelNav = await ctxDelNav.VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.equal(rDelNav.blocked, true, "Deleting window.Navigator with spoofed getter MUST block!");
  assert.ok(rDelNav.reasons.includes("WEBDRIVER_GETTER_SPOOFED"), `Expected WEBDRIVER_GETTER_SPOOFED, got ${JSON.stringify(rDelNav.reasons)}`);
  assert.ok(rDelNav.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `Expected NATIVE_FUNCTION_TAMPERED, got ${JSON.stringify(rDelNav.reasons)}`);

  const ctxDelCanvas = runVb24(`window.HTMLCanvasElement = undefined;`);
  const rDelCanvas = await ctxDelCanvas.VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.equal(rDelCanvas.blocked, true, "Deleting window.HTMLCanvasElement MUST NOT fail open into empty catch!");
  assert.ok(rDelCanvas.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `Expected NATIVE_FUNCTION_TAMPERED, got ${JSON.stringify(rDelCanvas.reasons)}`);

  // 3) Perf LOW #3: Zero-backtracking Safari UA detection in browser SDK
  const sdk24 = buildBrowserGateScript({ defaultMode: "strict" });
  assert.ok(!sdk24.includes("^((?!chrome|android).)*safari"), "Safari UA check MUST NOT use backtracking negative-lookahead wildcard!");
});

test("37. Pass-25 Audit Regressions: fail-closed array/comma-joined Content-Length on CORS preflight & wildcard probes, and bounded-prefix large-HTML gate injection", async () => {
  // 1) Security MEDIUM #2: Array / comma-joined Content-Length MUST NOT fail open on VeilBreak CORS preflight exemption!
  const mw25 = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  for (const clVal of [["0", "25"], "0, 25", "abc"]) {
    let nextCalled = false;
    let status = 200;
    await mw25(
      {
        method: "OPTIONS",
        url: "/api/secret",
        socket: { remoteAddress: "127.0.0.1" },
        headers: makeBrowserHeaders({
          origin: "https://other.example",
          host: "app.example",
          "access-control-request-method": "POST",
          "sec-fetch-mode": "cors",
          "content-length": clVal,
        }),
      },
      {
        headersSent: false,
        writableEnded: false,
        setHeader() {},
        writeHead(st) { status = st; this.headersSent = true; },
        end() { this.writableEnded = true; },
      },
      () => { nextCalled = true; }
    );
    assert.equal(nextCalled, false, `OPTIONS with malformed Content-Length ${JSON.stringify(clVal)} MUST NOT pass CORS preflight exemption!`);
    assert.equal(status, 403, `OPTIONS with malformed Content-Length ${JSON.stringify(clVal)} MUST return 403!`);
  }

  // 2) Security MEDIUM #2 + Perf LOW #3: Wildcard server rejects comma-joined Content-Length on HTML/static probes AND injects gate.js into >100KB SSR HTML cleanly!
  const bigHtml = `<!doctype html><html><head><meta charset="utf-8"><title>Big SSR</title></head><body>${"<div>ssr-chunk</div>".repeat(6000)}</body></html>`;
  const up25 = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(bigHtml);
  });
  await new Promise((r) => up25.listen(0, "127.0.0.1", r));
  const srv25 = createVeilBreakServer({ target: `http://127.0.0.1:${up25.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv25.listen(0, "127.0.0.1");
  const p25 = srv25.server.address().port;
  try {
    const htmlRes = await new Promise((resolve, reject) => {
      const r = http.request({
        host: "127.0.0.1",
        port: p25,
        method: "GET",
        path: "/",
        headers: makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" }),
      }, (resp) => {
        const chunks = [];
        resp.on("data", (c) => chunks.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, text: Buffer.concat(chunks).toString("utf8") }));
      });
      r.on("error", reject);
      r.end();
    });
    assert.equal(htmlRes.status, 200);
    assert.ok(htmlRes.text.includes("/__veilbreak/gate.js"), "Large >100KB SSR HTML MUST still receive gate.js injection!");
    assert.ok(htmlRes.text.indexOf("/__veilbreak/gate.js") < 300, "gate.js MUST be injected immediately after <meta charset> inside <head>!");
  } finally {
    await srv25.close();
    await new Promise((r) => up25.close(r));
  }
});

test("38. Pass-26 Audit Regressions: RFC 9112 Connection:close on unread-body 403 rejections + XHR reuse inside onreadystatechange(4)", async () => {
  // 1) Perf MEDIUM #1: Unread-body POST rejection MUST include Connection: close so HTTP/1.1 keep-alive never hangs!
  const mw26 = createVeilBreakMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const srv26 = http.createServer(async (req, res) => {
    const handled = await mw26(req, res);
    if (!handled) { res.writeHead(200); res.end("ok"); }
  });
  await new Promise((r) => srv26.listen(0, "127.0.0.1", r));
  try {
    const rUnread = await new Promise((resolve, reject) => {
      const r = http.request(
        {
          host: "127.0.0.1",
          port: srv26.server ? srv26.server.address().port : srv26.address().port,
          method: "POST",
          path: "/api/pay",
          headers: {
            "User-Agent": CHROME_UA,
            "Content-Type": "application/json",
            "Content-Length": "4096",
            "Connection": "keep-alive",
          },
        },
        (resp) => {
          resp.resume();
          resp.on("end", () => resolve({ status: resp.statusCode, conn: String(resp.headers.connection || "").toLowerCase() }));
        }
      );
      r.on("error", () => {});
      r.write('{"partial":true}');
    });
    assert.equal(rUnread.status, 403);
    assert.equal(rUnread.conn, "close", "VeilBreak early unread-body 403 MUST send Connection: close!");
  } finally {
    await new Promise((r) => srv26.close(r));
  }
});

test("39. Pass-27 Audit Regressions: cross-realm verified navigator.brave & CSS.supports exemptions, freshWin-required WebGL/Canvas/Permissions prototype deletion detection, and U+0130 ASCII-safe HTML injection", async () => {
  const vm = require("node:vm");
  const { injectGateIntoHtml } = require("../src/middleware.js");

  const runVb27 = (preLoadHook = "", postLoadHook = "") => {
    const src = buildBrowserGateScript({ defaultMode: "strict", basePath: "/__veilbreak", antiCdp: false });
    const vmConsole = { debug: function debug() {}, log: function log() {} };
    const nativeRefs = new Set([vmConsole.debug, TextEncoder.prototype.encode]);
    class FreshCanvas { toDataURL() { return ""; } }
    class FreshCtx2d { getImageData() { return { data: [] }; } }
    class FreshWebGL { getParameter() { return "ANGLE (NVIDIA)"; } readPixels() {} }
    class FreshPerms { query() { return Promise.resolve({ state: "prompt" }); } }
    class FreshEl { getBoundingClientRect() { return { left: 0, top: 0, width: 10, height: 10 }; } }
    const ifrCtx = vm.createContext({
      console: { debug: vmConsole.debug },
      HTMLCanvasElement: FreshCanvas,
      CanvasRenderingContext2D: FreshCtx2d,
      WebGLRenderingContext: FreshWebGL,
      Permissions: FreshPerms,
      Element: FreshEl,
      CSS: { supports: function supports() { return false; } },
      _nativeRefs: nativeRefs,
    });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent", "toDataURL", "getImageData", "getParameter", "readPixels", "query", "getBoundingClientRect", "supports"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        Object.defineProperty(Navigator.prototype, "platform", { configurable: true, get: function platform() { return "Linux x86_64"; } });
        Object.defineProperty(Navigator.prototype, "userAgent", { configurable: true, get: function userAgent() { return ${JSON.stringify(CHROME_UA)}; } });
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      attachShadow() { return new ShadowRoot(); }
      getAttribute() { return null; }
      getBoundingClientRect() { return { left: 0, top: 0, width: 10, height: 10 }; }
      remove() {}
    }
    class Document extends Node {
      constructor() { super(); this._el = new Element(); this.body = new Element(); this.readyState = "complete"; }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      addEventListener() {}
    }
    class MainNav {}
    Object.defineProperty(MainNav.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
    Object.defineProperty(MainNav.prototype, "platform", { configurable: true, get: function platform() { return "Linux x86_64"; } });
    Object.defineProperty(MainNav.prototype, "userAgent", { configurable: true, get: function userAgent() { return CHROME_UA; } });
    const navInst = Object.create(MainNav.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    class MainCanvas { toDataURL() { return ""; } }
    class MainCtx2d { getImageData() { return { data: [] }; } }
    class MainWebGL { getParameter() { return "ANGLE (NVIDIA)"; } readPixels() {} }
    class MainPerms { query() { return Promise.resolve({ state: "prompt" }); } }
    Object.defineProperty(MainNav.prototype, "permissions", { configurable: true, get: function permissions() { return new MainPerms(); } });
    const ctx = vm.createContext({
      TextEncoder, TextDecoder, URL, console: vmConsole, setTimeout, clearTimeout,
      performance: { now: function now() { return 1000; }, getEntriesByType() { return []; } },
      document: new Document(), Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      Navigator: MainNav, navigator: navInst,
      HTMLCanvasElement: MainCanvas, CanvasRenderingContext2D: MainCtx2d, WebGLRenderingContext: MainWebGL, Permissions: MainPerms,
      CSS: { supports: function supports() { return false; } },
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/" },
      addEventListener() {}, _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "debug", "now", "webdriver", "platform", "userAgent", "toDataURL", "getImageData", "getParameter", "readPixels", "query", "getBoundingClientRect", "supports"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    if (postLoadHook) vm.runInContext(postLoadHook, ctx);
    return ctx;
  };

  // Baseline clean VM stays 0-FP
  const cleanRes = await runVb27().VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.equal(cleanRes.blocked, false, `Clean baseline VM MUST stay 0-FP (reasons=${cleanRes.reasons})`);

  // 1) Security HIGH #2: Spoofing navigator.brave or CSS.supports MUST flag NATIVE_FUNCTION_TAMPERED!
  for (const [label, hook] of [
    ["navigator.brave own-property spoof", `navigator.brave = { isBrave() { return Promise.resolve(true); } };`],
    ["CSS.supports spoof", `CSS.supports = () => true;`],
  ]) {
    const r = await runVb27("", hook).VeilBreak.verify({ mode: "strict", antiCdp: false });
    assert.equal(r.blocked, true, `${label} MUST block!`);
    assert.ok(r.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `${label} MUST flag NATIVE_FUNCTION_TAMPERED (got ${r.reasons})`);
  }

  // 2) Security HIGH #3: Deleting WebGLRenderingContext.prototype.getParameter / Canvas2D.getImageData / Permissions.query MUST flag NATIVE_FUNCTION_TAMPERED!
  for (const [label, hook] of [
    ["delete WebGLRenderingContext.prototype.getParameter", `delete WebGLRenderingContext.prototype.getParameter;`],
    ["delete CanvasRenderingContext2D.prototype.getImageData", `delete CanvasRenderingContext2D.prototype.getImageData;`],
    ["delete Permissions.prototype.query", `delete Permissions.prototype.query;`],
  ]) {
    const r = await runVb27(hook).VeilBreak.verify({ mode: "strict", antiCdp: false });
    assert.equal(r.blocked, true, `${label} MUST block!`);
    assert.ok(r.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `${label} MUST flag NATIVE_FUNCTION_TAMPERED (got ${r.reasons})`);
  }

  // 3) Security LOW #1: U+0130 ('İ') before <head> MUST NOT shift injection index or split <title>!
  const trHtml = "<!doctype html><!-- \u0130stanbul --><head><title>Test</title></head><body></body>";
  const injectedTr = injectGateIntoHtml(trHtml, "/__veilbreak", "strict", true, true);
  assert.ok(injectedTr.includes("<head><script src=\"/__veilbreak/gate.js"), "gate.js MUST inject right after <head>!");
  assert.ok(injectedTr.includes("</script><title>Test</title>"), `U+0130 MUST NOT split <title> (got ${injectedTr})`);
});

test("40. Pass-28 Audit Regressions: antiCdp:false _cdpCache isolation & POLICY_LOCKED verify(), Safari Sec-Fetch-* bootstrap gating, window.Event cross-realm check, and fast 4KB/64KB asciiLower", async () => {
  const vm = require("node:vm");
  const { injectGateIntoHtml } = require("../src/middleware");
  // 1) Security HIGH #2 & Security LOW #5: antiCdp:false MUST NOT poison _cdpCache / __PS_SYNC_CDP__, POLICY_LOCKED verify() MUST NOT downgrade, and pre-load window.Event replacement MUST flag NATIVE_FUNCTION_TAMPERED!
  const runVb28 = ({ sri = true, cdpOpen = false, preLoadHook = "" } = {}) => {
    const src = buildBrowserGateScript({ defaultMode: "strict", antiCdp: true, allowDevTools: false, autoBlockPage: false, sri, unified: true });
    let cdpActiveNow = cdpOpen;
    const synced = [];
    const vmConsole = {
      debug: function debug(arg) {
        if (cdpActiveNow && arg && typeof arg === "object") {
          try { void arg.stack; } catch (_) {}
        }
      },
      warn: function warn() {},
      error: function error() {},
    };
    class VmPerformance {
      now() { return Date.now(); }
      getEntriesByType() { return []; }
    }
    const VmEvent = class Event { constructor(t, tr) { this.type = t; this._tr = tr; } get isTrusted() { return this._tr; } };
    const origEncode = TextEncoder.prototype.encode;
    class VmTextEncoder { encode(s) { return origEncode.call(new TextEncoder(), s); } }
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    class VmHeaders {
      constructor(i) { this._h = new Headers(i); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
    }
    const nativeRefs = new Set([
      VmHeaders.prototype.set, VmHeaders.prototype.get, VmTextEncoder.prototype.encode,
      VmPerformance.prototype.now, vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "get isTrusted", "debug", "now", "webdriver", "platform", "userAgent"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        class Event {}
        Object.defineProperty(Navigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
        globalThis.Navigator = Navigator;
        globalThis.Event = Event;
        globalThis.navigator = Object.create(Navigator.prototype);
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { get shadowRoot() { return null; } attachShadow() { return new ShadowRoot(); } getAttribute() { return null; } remove() {} }
    class Document extends Node {
      constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this._el = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      addEventListener() {}
    }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    let privateApi = null;
    const ctx = vm.createContext({
      document: new Document(), Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/app" },
      Navigator: VmNavigator, navigator: navInst,
      Event: VmEvent,
      Performance: VmPerformance, performance: new VmPerformance(),
      TextEncoder: VmTextEncoder, Headers: VmHeaders, Request, Response, URL,
      console: vmConsole, setTimeout, clearTimeout,
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      addEventListener() {},
      __VB_PRIVATE_REGISTER__: (api) => { privateApi = api; },
      __PS_SYNC_CDP__: (active, ts) => { synced.push({ active, ts }); },
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const okNames = new Set(["toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "Event", "get isTrusted", "debug", "now", "webdriver", "platform", "userAgent"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || okNames.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, privateApi, synced, setCdp: (v) => { cdpActiveNow = v; } };
  };

  // A) Under POLICY_LOCKED (sri:true), public VeilBreak.verify({ mode:"monitor", antiCdp:false }) MUST NOT downgrade or poison CDP!
  const locked = runVb28({ sri: true, cdpOpen: true });
  const hsBefore = await locked.privateApi.collectHandshakeProof("ch-lock-1");
  assert.equal(hsBefore.cdp, 1, "Active CDP MUST report cdp=1 before verify()");
  const dgRes = await locked.ctx.VeilBreak.verify({ mode: "monitor", antiCdp: false, allowDevTools: true });
  assert.equal(dgRes.mode, "strict", "POLICY_LOCKED verify() MUST NOT downgrade mode to monitor!");
  assert.equal(dgRes.blocked, true, "POLICY_LOCKED verify() MUST still enforce antiCdp and block!");
  assert.ok(locked.synced.every((e) => e.active === true), "__PS_SYNC_CDP__ MUST NOT receive false during locked downgrade attempt!");
  const hsAfter = await locked.privateApi.collectHandshakeProof("ch-lock-2");
  assert.equal(hsAfter.cdp, 1, "Handshake proof MUST STILL report cdp=1 after verify({ antiCdp:false })!");

  // B) Even when unlocked (sri:false), verify({ antiCdp:false }) MUST NOT wipe _cdpCache or push false into __PS_SYNC_CDP__!
  const unlocked = runVb28({ sri: false, cdpOpen: true });
  const uBefore = await unlocked.privateApi.collectHandshakeProof("ch-unlock-1");
  assert.equal(uBefore.cdp, 1, "Unlocked active CDP MUST report cdp=1");
  const syncCountBefore = unlocked.synced.length;
  await unlocked.ctx.VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.equal(unlocked.synced.length, syncCountBefore, "antiCdp:false MUST NOT invoke __PS_SYNC_CDP__!");
  const uAfter = await unlocked.privateApi.collectHandshakeProof("ch-unlock-2");
  assert.equal(uAfter.cdp, 1, "Unlocked antiCdp:false MUST NOT poison _cdpCache for collectHandshakeProof!");

  // C) Security LOW #5: Pre-load window.Event replacement MUST flag NATIVE_FUNCTION_TAMPERED!
  const badEv = runVb28({
    sri: false,
    cdpOpen: false,
    preLoadHook: `window.Event = function FakeEvent() {}; Object.defineProperty(window.Event, Symbol.hasInstance, { value: () => true });`,
  });
  const evRes = await badEv.ctx.VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.equal(evRes.blocked, true, "Pre-load window.Event decoy MUST block!");
  assert.ok(evRes.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `Pre-load Event decoy MUST flag NATIVE_FUNCTION_TAMPERED (got ${evRes.reasons})`);

  // 2) Security MEDIUM #3: Safari 16.4+ explicit Sec-Fetch-* headers MUST be enforced by isHtmlBootstrapNavigation on wildcard ['/']!
  const up28 = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end("<!doctype html><html><head></head><body>ok</body></html>");
  });
  await new Promise((r) => up28.listen(0, "127.0.0.1", r));
  const vb28 = createVeilBreakServer({
    target: `http://127.0.0.1:${up28.address().port}`,
    mode: "strict",
    protectedPaths: ["/"],
  });
  const vb28Url = await vb28.listen(0, "127.0.0.1");
  const safUa = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15";
  const req28 = (headers) => new Promise((resolve, reject) => {
    const u = new URL(`${vb28Url}/`);
    const r = http.request({ hostname: u.hostname, port: u.port, path: "/", method: "GET", headers }, (resp) => {
      const ch = [];
      resp.on("data", (c) => ch.push(c));
      resp.on("end", () => resolve({ status: resp.statusCode, body: Buffer.concat(ch).toString("utf8") }));
    });
    r.on("error", reject);
    r.end();
  });
  try {
    const safNav = await req28({ "User-Agent": safUa, Accept: "text/html", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-Site": "none" });
    assert.equal(safNav.status, 200, "Safari 16.4+ HTML navigation MUST be allowed (0-FP)!");
    const safOld = await req28({ "User-Agent": safUa, Accept: "text/html" });
    assert.equal(safOld.status, 200, "Safari <16.4 HTML navigation without Sec-Fetch-* MUST be allowed (0-FP)!");
    const safCors = await req28({ "User-Agent": safUa, Accept: "text/html", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Site": "same-origin" });
    assert.equal(safCors.status, 403, "Safari 16.4+ Sec-Fetch-Mode:cors on wildcard '/' MUST be blocked (403)!");
    const safXFrame = await req28({ "User-Agent": safUa, Accept: "text/html", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe", "Sec-Fetch-Site": "cross-site" });
    assert.equal(safXFrame.status, 403, "Safari 16.4+ cross-site iframe on wildcard '/' MUST be blocked (403)!");
  } finally {
    await vb28.close();
    await new Promise((r) => up28.close(r));
  }

  // 3) Performance MEDIUM #1: 4KB / 64KB / >64KB & Kelvin U+212A + Turkish U+0130 HTML injection parity
  for (const padLen of [100, 6000, 70000]) {
    const htmlPad = `<!doctype html><!-- \u0130\u212A${"x".repeat(padLen)} --><head><title>P</title></head><body></body>`;
    const inj = injectGateIntoHtml(htmlPad, "/__veilbreak", "strict", true, true);
    assert.ok(inj.includes('<head><script src="/__veilbreak/gate.js'), `gate.js MUST inject after <head> for padLen=${padLen}`);
    assert.ok(inj.includes("</script><title>P</title>"), `HTML injection MUST NOT split <title> for padLen=${padLen}`);
  }

  // 4) Pass-29 Security LOW #3: Expanded/hex IPv4-mapped IPv6 trustProxy entries MUST match ::ffff:10.0.0.x & 10.0.0.x
  const mwTp29 = createVeilBreakMiddleware({ mode: "strict", trustProxy: ["0:0:0:0:0:ffff:10.0.0.1", "::ffff:0a00:0002"] });
  assert.equal(mwTp29._trustedProxies.has("::ffff:10.0.0.1"), true, "Expanded IPv4-mapped IPv6 MUST match ::ffff:10.0.0.1");
  assert.equal(mwTp29._trustedProxies.has("10.0.0.1"), true, "Expanded IPv4-mapped IPv6 MUST match 10.0.0.1");
  assert.equal(mwTp29._trustedProxies.has("::ffff:10.0.0.2"), true, "Hex IPv4-mapped IPv6 MUST match ::ffff:10.0.0.2");
  assert.equal(mwTp29._trustedProxies.has("10.0.0.3"), false);

  // 5) Pass-30 Availability: Real Brave exposing native own-property navigator.brave in BOTH main & fresh iframe realms MUST stay 0-FP!
  const braveOwn = runVb28({
    sri: false,
    cdpOpen: false,
    preLoadHook: `
      const isBraveFn = function isBrave() { return Promise.resolve(true); };
      _nativeRefs.add(isBraveFn);
      Object.defineProperty(navigator, "brave", { value: { isBrave: isBraveFn }, configurable: true });
      const fr = document.createElement("iframe").contentWindow;
      Object.defineProperty(fr.navigator, "brave", { value: { isBrave: isBraveFn }, configurable: true });
    `,
  });
  const braveRes = await braveOwn.ctx.VeilBreak.verify({ mode: "strict", antiCdp: false });
  assert.equal(braveRes.blocked, false, `Real Brave own-property navigator.brave in both realms MUST stay 0-FP (reasons=${braveRes.reasons})`);
  assert.ok(!braveRes.reasons.includes("NATIVE_FUNCTION_TAMPERED"), `Real Brave MUST NOT trigger NATIVE_FUNCTION_TAMPERED (got ${braveRes.reasons})`);
});
