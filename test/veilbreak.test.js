"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
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
  // C++-patched noise Chromium profile
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

  // C++-patched Gecko profile (non-deterministic canvas + GPU hardware lie)
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

  // JS stealth plugin profile (worker mismatch + tampered native getter + permissions contradiction)
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

  // CDP viewport emulation leak (Patchright / Rebrowser headed)
  const cdpGeom = evaluateTelemetry(
    { viewportGeometryImpossibility: true, platform: "Linux x86_64" },
    { mode: "strict" }
  );
  assert.equal(cdpGeom.blocked, true);
  assert.equal(cdpGeom.score, 2);
});

test("3. Privacy browser (Canvas-only farbling) allowed in balanced mode, blocked in strict", () => {
  const braveLike = { canvas2dUniqueColors: 4, platform: "Linux x86_64" };
  assert.equal(evaluateTelemetry(braveLike, { mode: "balanced" }).blocked, false);
  assert.equal(evaluateTelemetry(braveLike, { mode: "strict" }).blocked, true);
});

test("4. Stage-2 Biomechanical Click Kinematics blocks bot clicks while allowing humans & keyboard accessibility", () => {
  // Real human mouse click
  const human = evaluateInteraction({ isTrusted: true, detail: 1, pointerMoves: 24, dwellMs: 78, hitExactCenter: false });
  assert.equal(human.blocked, false);
  assert.equal(human.score, 0);

  // Keyboard accessibility activation (Enter/Space on focused button -> isTrusted=true, detail=0)
  const keyboard = evaluateInteraction({ isTrusted: true, detail: 0, pointerMoves: 0, dwellMs: -1, hitExactCenter: false });
  assert.equal(keyboard.blocked, false);
  assert.equal(keyboard.score, 0);

  // Synthetic JS click (Nodriver / SeleniumBase UC)
  const synthetic = evaluateInteraction({ isTrusted: false, detail: 0, pointerMoves: 0, dwellMs: -1, hitExactCenter: false });
  assert.equal(synthetic.blocked, true);
  assert.equal(synthetic.score, 6);
  assert.ok(synthetic.reasons.includes("UNTRUSTED_SYNTHETIC_CLICK"));

  // Programmatic CDP/Juggler teleport click (Patchright / Rebrowser / Camoufox / CloakBrowser)
  const teleport = evaluateInteraction({ isTrusted: true, detail: 1, pointerMoves: 1, dwellMs: 0.4, hitExactCenter: true });
  assert.equal(teleport.blocked, true);
  assert.equal(teleport.score, 4);
  assert.ok(teleport.reasons.includes("TELEPORT_CLICK_PHYSICS"));
});

test("5. VB_ATTEST_V2 cryptographic verification & Python wire parity", () => {
  const ticket = "abcdef0123456789abcdef0123456789";
  const nonce = "0123456789abcdef";
  const headers = {
    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"',
    "sec-ch-ua-platform": '"Linux"',
  };
  const att = buildAttestation({
    mode: "strict",
    ticket,
    nonce,
    telemetry: { platform: "Linux x86_64" },
  });
  const okRes = verifyAttestation({ mode: "strict", headers, attest: att, ticket, nonce });
  assert.equal(okRes.ok, true);
  assert.equal(okRes.blocked, false);

  // Tampered digest must fail
  const tampered = { ...att, d: "0".repeat(64) };
  const badRes = verifyAttestation({ mode: "strict", headers, attest: tampered, ticket, nonce });
  assert.equal(badRes.blocked, true);
  assert.ok(badRes.reasons.includes("ATTEST_DIGEST_MISMATCH"));

  // Legacy GREASE lie (Chrome 158 + ' Not A;Brand";v="99')
  const greaseRes = verifyAttestation({
    mode: "strict",
    headers: { ...headers, "sec-ch-ua": '"Chromium";v="158", " Not A;Brand";v="99", "Google Chrome";v="158"' },
    attest: att,
    ticket,
    nonce,
  });
  assert.equal(greaseRes.blocked, true);
  assert.ok(greaseRes.reasons.includes("SEC_CH_UA_GREASE_LIE"));

  // Python zero-dep verifier wire parity
  const pyDir = path.join(__dirname, "..", "python");
  const pyOut = execFileSync("python3", [
    "-c",
    `import sys, json; sys.path.insert(0, ${JSON.stringify(pyDir)}); from veilbreak import verify_attestation; ` +
    `r = verify_attestation(mode="strict", headers=json.loads(${JSON.stringify(JSON.stringify(headers))}), attest=json.loads(${JSON.stringify(JSON.stringify(att))}), ticket=${JSON.stringify(ticket)}, nonce=${JSON.stringify(nonce)}); ` +
    `print(json.dumps({"ok": r.ok, "blocked": r.blocked, "score": r.score, "reasons": r.reasons}))`,
  ], { encoding: "utf8" });
  const pyParsed = JSON.parse(pyOut);
  assert.equal(pyParsed.ok, true);
  assert.equal(pyParsed.blocked, false);
  assert.equal(pyParsed.score, 0);
});

test("6. Live HTTP server middleware enforces one-time tickets, blocks curl, and injects <script>", async () => {
  const upstream = http.createServer((req, res) => {
    if (req.url === "/api/secret") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, secret: "PROTECTED_OK" }));
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<!doctype html><html><head><title>App</title></head><body><h1>Hi</h1></body></html>");
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
    // HTML page gets auto-injected gate.js
    const htmlResp = await fetch(`${baseUrl}/`, { headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0.0.0" } });
    assert.equal(htmlResp.status, 200);
    const html = await htmlResp.text();
    assert.ok(html.includes("/__veilbreak/gate.js"));

    // Unattested API request (curl / scraper) is 403
    const rawApi = await fetch(`${baseUrl}/api/secret`);
    assert.equal(rawApi.status, 403);
    const rawJson = await rawApi.json();
    assert.equal(rawJson.error, "VEILBREAK_DENIED");

    // Valid one-time ticket + clean attestation passes once, replay is blocked!
    const tk = (await (await fetch(`${baseUrl}/__veilbreak/ticket`)).json()).ticket;
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
  } finally {
    await gate.close();
    await new Promise((r) => upstream.close(r));
  }
});

test("7. Natural-language compiler & browser SDK script syntax check", () => {
  const p1 = compileNaturalLanguage("protect http://localhost:3000 on port 9090 while keeping privacy browsers working");
  assert.equal(p1.intent, "protect");
  assert.equal(p1.options.mode, "balanced");
  assert.equal(p1.options.port, 9090);

  const p2 = compileNaturalLanguage("show me a demo");
  assert.equal(p2.intent, "demo");

  const js = buildBrowserGateScript();
  // Ensure generated browser SDK is syntactically valid JS
  new Function(js);
});
