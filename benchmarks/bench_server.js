#!/usr/bin/env node
"use strict";

/**
 * Live VeilBreak Benchmark Target Server.
 * Wraps an upstream app with createVeilBreakServer({ mode: "strict", autoBlockPage: false })
 * so browsers report Stage-1 passive invariants, <veil-break> Shadow DOM verdict,
 * Stage-2 click kinematics, and genuine server-side /api/secret HTTP enforcement (200 vs 403).
 */
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createVeilBreakServer, thresholdForMode } = require("../src/index.js");

const PORT = Number(process.env.VB_BENCH_PORT || 18995);
const OUT_DIR = process.env.VB_BENCH_OUT || path.join(os.tmpdir(), "veilbreak_bench_runs");
const MODE = process.env.VB_BENCH_MODE || "strict";
const MAX_TICKETS_PER_MIN = Number(process.env.VB_BENCH_MAX_TICKETS_PER_MIN || 1000);
fs.mkdirSync(OUT_DIR, { recursive: true });

function safeLabel(raw) {
  return String(raw || "unknown").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64) || "unknown";
}

function writeJsonAtomic(filePath, data) {
  const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, typeof data === "string" || Buffer.isBuffer(data) ? data : JSON.stringify(data));
  fs.renameSync(tmp, filePath);
}

async function main() {
  const upstream = http.createServer((req, res) => {
    const u = new URL(req.url, "http://127.0.0.1");

    if (u.pathname === "/api/secret") {
      const body = JSON.stringify({ ok: true, secret: "VERIFIED_GENUINE_BROWSER_DATA" });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
      res.end(body);
      return;
    }

    if (u.pathname === "/bench-report" && req.method === "POST") {
      const label = safeLabel(u.searchParams.get("label"));
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        writeJsonAtomic(path.join(OUT_DIR, `${label}.json`), Buffer.concat(chunks));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"ok":true}');
      });
      return;
    }

    const label = safeLabel(u.searchParams.get("label"));
    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VeilBreak Live Benchmark</title>
</head>
<body style="margin:0;padding:40px;font-family:system-ui;background:#0d1117;color:#e6edf3;">
  <veil-break id="vb-wc" mode="${MODE}"><div id="wc-payload">PROTECTED_COMPONENT</div></veil-break>
  <button id="vb-btn" style="position:fixed;left:260px;top:200px;width:200px;height:60px;font-size:18px;">Verify Action</button>
  <pre id="state">booting...</pre>
  <script>
  (async () => {
    const label = ${JSON.stringify(label)};
    const t0 = performance.now();
    const s1 = await window.VeilBreak.verify({ mode: ${JSON.stringify(MODE)} });
    const probeMs = Number((performance.now() - t0).toFixed(2));

    await new Promise((r) => setTimeout(r, 150));
    const wc = document.getElementById("vb-wc");
    const wcStatus = wc ? (wc.dataset.veilbreakStatus || "unknown") : "missing";

    let apiPassive = { status: 0, ok: false, error: null };
    const tApi0 = performance.now();
    try {
      const r = await fetch("/api/secret");
      apiPassive = { status: r.status, ok: r.ok, body: await r.json() };
    } catch (e) {
      apiPassive = { status: 0, ok: false, error: String(e.message || e) };
    }
    const apiFetchPowMs = Number((performance.now() - tApi0).toFixed(2));

    const report = {
      label,
      mode: ${JSON.stringify(MODE)},
      probeMs,
      apiFetchPowMs,
      stage1: {
        blocked: s1.blocked || !apiPassive.ok,
        score: s1.score,
        threshold: s1.threshold,
        reasons: s1.reasons,
        wcStatus,
        apiPassiveStatus: apiPassive.status,
        apiPassiveOk: apiPassive.ok,
      },
      stage2: null,
    };

    const post = () => fetch("/bench-report?label=" + encodeURIComponent(label), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report),
    });
    await post();
    document.getElementById("state").textContent = "STAGE1_DONE";

    document.getElementById("vb-btn").addEventListener("click", async (ev) => {
      const k = window.VeilBreak.evaluateClick(ev, ev.currentTarget);
      let apiActive = { status: 0, ok: false, error: null };
      try {
        const r = await fetch("/api/secret");
        apiActive = { status: r.status, ok: r.ok, body: await r.json() };
      } catch (e) {
        apiActive = { status: 0, ok: false, error: String(e.message || e) };
      }
      report.stage2 = {
        clickBlocked: k.blocked,
        clickScore: k.score,
        clickReasons: k.reasons,
        clickDetails: k.details,
        combinedBlocked: s1.blocked || k.blocked || !apiActive.ok,
        apiActiveStatus: apiActive.status,
        apiActiveOk: apiActive.ok,
      };
      await post();
      document.getElementById("state").textContent = "STAGE2_DONE";
    });
  })();
  </script>
</body>
</html>`;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(html) });
    res.end(html);
  });

  await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
  const upPort = upstream.address().port;

  let lastDetect = null;
  const gate = createVeilBreakServer({
    target: `http://127.0.0.1:${upPort}`,
    mode: MODE,
    protectedPaths: ["/api"],
    maxTicketsPerMinPerIp: MAX_TICKETS_PER_MIN,
    autoBlockPage: false,
    onDetect: (ev) => {
      lastDetect = ev;
    },
  });

  const origEmit = gate.server.listeners("request")[0];
  gate.server.removeAllListeners("request");
  gate.server.on("request", (req, res) => {
    const u = new URL(req.url || "/", "http://127.0.0.1");
    const lbl = u.searchParams.get("label");
    if (lbl && u.pathname === "/") {
      const origEnd = res.end.bind(res);
      res.end = (...args) => {
        if (res.statusCode === 403) {
          const safe = safeLabel(lbl);
          let parsed = null;
          try {
            if (args[0]) parsed = JSON.parse(Buffer.isBuffer(args[0]) ? args[0].toString("utf8") : String(args[0]));
          } catch {}
          const reasons = (parsed && parsed.reasons) || (lastDetect && lastDetect.reasons) || ["HTTP_403_DENIED"];
          const score = (parsed && parsed.score) ?? (lastDetect && lastDetect.score) ?? 6;
          const threshold = (parsed && parsed.threshold) ?? thresholdForMode(MODE);
          writeJsonAtomic(path.join(OUT_DIR, `${safe}.json`), {
            label: safe,
            mode: MODE,
            probeMs: 0.0,
            stage1: {
              blocked: true,
              score,
              threshold,
              reasons: reasons.map((r) => `${r} (HTTP 403 on page load)`),
              wcStatus: "blocked_http_403",
              apiPassiveStatus: 403,
              apiPassiveOk: false,
            },
            stage2: null,
          });
        }
        return origEnd(...args);
      };
    }
    return origEmit(req, res);
  });

  const url = await gate.listen(PORT, "127.0.0.1");
  console.log(`VB_BENCH_READY ${url}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
