"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const {
  evaluateTelemetry,
  buildAttestation,
  verifyAttestation,
  createCloakGateServer,
  compileNaturalLanguage,
} = require("../src/index.js");

const CHROME_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36";

test("1. Live CloakBrowser 146 physics profile (11/11 and Linux 8/11) is denied in strict & balanced; clean Chrome passes (0/11)", () => {
  const cloakWin = {
    canvas2dUniqueColors: 5,
    webglClearUniqueColors: 5,
    silentAudioNonZeroSamples: 512,
    domRectSubpixelDrift: true,
    osFontLie: true,
    d3d11ExtMismatch: true,
    platform: "Win32",
  };
  const rStrict = evaluateTelemetry(cloakWin, { mode: "strict" });
  assert.equal(rStrict.blocked, true);
  assert.equal(rStrict.score, 11);

  const rBalanced = evaluateTelemetry(cloakWin, { mode: "balanced" });
  assert.equal(rBalanced.blocked, true);
  assert.equal(rBalanced.score, 11);

  // Even with --fingerprint-platform=linux (osFontLie=false, d3d11=false) -> still 8/11 -> denied!
  const cloakLinux = { ...cloakWin, osFontLie: false, d3d11ExtMismatch: false, platform: "Linux x86_64" };
  const rLinux = evaluateTelemetry(cloakLinux, { mode: "balanced" });
  assert.equal(rLinux.blocked, true);
  assert.equal(rLinux.score, 8);

  // Brave Shields Aggressive (Canvas-only farbling +2) passes balanced (>=4) while clean Chrome scores 0/11
  const brave = { canvas2dUniqueColors: 3, webglClearUniqueColors: 1, silentAudioNonZeroSamples: 0, domRectSubpixelDrift: false, osFontLie: false, platform: "Linux x86_64" };
  assert.equal(evaluateTelemetry(brave, { mode: "balanced" }).blocked, false);
  assert.equal(evaluateTelemetry(brave, { mode: "strict" }).blocked, true);

  const clean = { canvas2dUniqueColors: 1, webglClearUniqueColors: 1, silentAudioNonZeroSamples: 0, domRectSubpixelDrift: false, osFontLie: false, d3d11ExtMismatch: false, platform: "Linux x86_64" };
  assert.equal(evaluateTelemetry(clean, { mode: "strict" }).blocked, false);
  assert.equal(evaluateTelemetry(clean, { mode: "strict" }).score, 0);
});

test("2. Server attestation rejects missing attest, forged digest, HeadlessChrome UA, and OS header lies", () => {
  const cleanAtt = buildAttestation({
    mode: "strict",
    ticket: "tk-1",
    nonce: "n-1",
    telemetry: { platform: "Linux x86_64" },
  });
  const ok = verifyAttestation({
    mode: "strict",
    headers: { "user-agent": CHROME_UA, "sec-ch-ua-platform": '"Linux"' },
    attest: cleanAtt,
    ticket: "tk-1",
    nonce: "n-1",
  });
  assert.equal(ok.blocked, false);
  assert.equal(ok.score, 0);

  // Missing attest -> blocked
  const miss = verifyAttestation({ mode: "strict", headers: { "user-agent": CHROME_UA }, attest: null, ticket: "tk-1", nonce: "n-1" });
  assert.equal(miss.blocked, true);
  assert.ok(miss.reasons.includes("CLOAK_ATTEST_REQUIRED"));

  // Forged digest -> blocked
  const forged = verifyAttestation({
    mode: "strict",
    headers: { "user-agent": CHROME_UA },
    attest: { ...cleanAtt, d: "0".repeat(64) },
    ticket: "tk-1",
    nonce: "n-1",
  });
  assert.equal(forged.blocked, true);
  assert.ok(forged.reasons.includes("CLOAK_ATTEST_DIGEST_MISMATCH"));

  // HeadlessChrome UA -> blocked
  const hl = verifyAttestation({
    mode: "strict",
    headers: { "user-agent": "Mozilla/5.0 HeadlessChrome/158.0" },
    attest: cleanAtt,
    ticket: "tk-1",
    nonce: "n-1",
  });
  assert.equal(hl.blocked, true);
  assert.ok(hl.reasons.includes("AUTOMATION_UA_DENIED"));

  // OS header lie -> blocked
  const osLie = verifyAttestation({
    mode: "strict",
    headers: { "user-agent": CHROME_UA, "sec-ch-ua-platform": '"Windows"' },
    attest: cleanAtt,
    ticket: "tk-1",
    nonce: "n-1",
  });
  assert.equal(osLie.blocked, true);
  assert.ok(osLie.reasons.includes("OS_HEADER_CONTRADICTION"));
});

test("3. Standalone CloakGate server injects gate.js, enforces single-use ticket + attest on /api, and serves playground", async () => {
  const backend = http.createServer((req, res) => {
    if (req.url === "/api/data") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, secret: "PROTECTED_OK" }));
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<!doctype html><html><head><title>Test</title></head><body>Hi</body></html>");
  });
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));

  const shield = createCloakGateServer({
    target: `http://127.0.0.1:${backend.address().port}`,
    mode: "strict",
    protectedPaths: ["/api"],
  });
  const baseUrl = await shield.listen(0, "127.0.0.1");
  try {
    const html = await (await fetch(`${baseUrl}/`, { headers: { "User-Agent": CHROME_UA } })).text();
    assert.ok(html.includes("/__cloakgate/gate.js"));

    const pg = await (await fetch(`${baseUrl}/__cloakgate/playground`, { headers: { "User-Agent": CHROME_UA } })).text();
    assert.ok(pg.includes("<cloak-gate"));

    // Unauthenticated /api call -> 403
    const denied = await fetch(`${baseUrl}/api/data`, { headers: { "User-Agent": CHROME_UA } });
    assert.equal(denied.status, 403);

    // Valid single-use ticket + clean attestation -> 200 OK
    const { ticket } = await (await fetch(`${baseUrl}/__cloakgate/ticket`, { headers: { "User-Agent": CHROME_UA } })).json();
    const att = buildAttestation({ mode: "strict", ticket, nonce: "n99", telemetry: { platform: "Linux x86_64" } });
    const ok = await fetch(`${baseUrl}/api/data`, {
      headers: {
        "User-Agent": CHROME_UA,
        "Sec-CH-UA-Platform": '"Linux"',
        "X-CG-Ticket": ticket,
        "X-CG-Nonce": "n99",
        "X-CG-Attest": JSON.stringify({ s: att.s, f: att.f, p: att.p, d: att.d }),
      },
    });
    assert.equal(ok.status, 200);

    // Replaying same ticket -> 403!
    const rep = await fetch(`${baseUrl}/api/data`, {
      headers: {
        "User-Agent": CHROME_UA,
        "X-CG-Ticket": ticket,
        "X-CG-Nonce": "n99",
        "X-CG-Attest": JSON.stringify({ s: att.s, f: att.f, p: att.p, d: att.d }),
      },
    });
    assert.equal(rep.status, 403);
  } finally {
    await shield.close();
    await new Promise((r) => backend.close(r));
  }
});

test("4. Plain-English Natural-Language CLI compiler + Python stdlib verifier parity", () => {
  const p1 = compileNaturalLanguage("block cloakbrowser on http://localhost:3000 on port 8091");
  assert.equal(p1.options.mode, "strict");
  assert.equal(p1.options.port, 8091);

  const p2 = compileNaturalLanguage("block cloakbrowser on http://localhost:3000 while keeping brave working");
  assert.equal(p2.options.mode, "balanced");

  const p3 = compileNaturalLanguage("watch for cloakbrowser without blocking on http://localhost:3000");
  assert.equal(p3.options.mode, "monitor");

  const pyOut = execFileSync(
    "python3",
    [
      "-c",
      `import hashlib, sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from cloakgate import verify_cloak_attestation
d_ok = hashlib.sha256(b"CG_ATTEST_V1|t1|n1|0|0|Linux x86_64").hexdigest()
v_ok = verify_cloak_attestation(mode="strict", headers={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) Chrome/158.0","Sec-CH-UA-Platform":'"Linux"'}, attest={"s":0,"f":0,"p":"Linux x86_64","d":d_ok}, ticket="t1", nonce="n1")
assert v_ok.ok and not v_ok.blocked
d_cb = hashlib.sha256(b"CG_ATTEST_V1|t2|n2|11|63|Win32").hexdigest()
v_cb = verify_cloak_attestation(mode="strict", headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0) Chrome/146.0"}, attest={"s":11,"f":63,"p":"Win32","d":d_cb}, ticket="t2", nonce="n2")
assert v_cb.blocked and v_cb.score == 11
print("PY_CG_OK")`,
    ],
    { encoding: "utf8" }
  );
  assert.equal(pyOut.trim(), "PY_CG_OK");
});
