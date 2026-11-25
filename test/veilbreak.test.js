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
