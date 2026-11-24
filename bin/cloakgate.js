#!/usr/bin/env node
"use strict";

const http = require("node:http");
const { createCloakGateServer, compileNaturalLanguage } = require("../src/index.js");

function printHelp() {
  console.log(`CloakGate v1.0.0 — Detect & Block CloakBrowser and Anti-Detect Browsers

Beginner Natural-Language Mode (Plain English):
  cloakgate ask "block cloakbrowser on http://localhost:3000 on port 8080"
  cloakgate ask "block cloakbrowser on http://localhost:3000 while keeping brave working"
  cloakgate explain "watch for cloakbrowser without blocking on http://localhost:3000"

Commands:
  cloakgate protect --target <url> [--port 8080] [--mode strict|balanced|monitor] [--paths /api]
  cloakgate demo [--port 8089] [--mode strict|balanced]
  cloakgate snippet [--mode strict|balanced]
  cloakgate ask "<plain English>" [--dry-run] [--json]
  cloakgate explain "<plain English>" [--json]
`);
}

function printSnippets(mode = "strict") {
  console.log(`<!-- 1. One-line HTML drop-in (blocks CloakBrowser across the entire page) -->
<script src="/__cloakgate/gate.js" data-mode="${mode}" data-block-page="true"></script>

<!-- 2. Protect any specific Web Component / section with <cloak-gate> -->
<script src="/__cloakgate/gate.js" data-mode="${mode}" data-block-page="false"></script>
<cloak-gate mode="${mode}">
  <my-pricing-widget></my-pricing-widget>
</cloak-gate>

// 3. Express / Node.js server middleware (zero dependencies)
const { createCloakGateMiddleware } = require("cloakgate");
app.use(createCloakGateMiddleware({ mode: "${mode}", protectedPaths: ["/api"] }));
`);
}

function parseFlags(args) {
  const opts = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--target" && args[i + 1]) opts.target = args[++i];
    else if (a === "--port" && args[i + 1]) opts.port = Number(args[++i]);
    else if (a === "--host" && args[i + 1]) opts.host = args[++i];
    else if (a === "--mode" && args[i + 1]) opts.mode = args[++i];
    else if (a === "--paths" && args[i + 1]) opts.protectedPaths = args[++i].split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--dry-run") opts.dryRun = true;
    else if (a === "--json") opts.json = true;
  }
  return opts;
}

async function runDemo(port = 8089, mode = "strict") {
  const backend = http.createServer((req, res) => {
    if (req.url === "/api/secret") {
      const payload = JSON.stringify({ ok: true, secret: "REAL_BROWSER_ONLY_API_DATA" });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) });
      res.end(payload);
      return;
    }
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>CloakGate Protected App</title></head>
<body style="background:#0b0f19;color:#e2e8f0;font-family:system-ui;padding:32px;">
  <h1>CloakGate Protected Page (${mode})</h1>
  <p id="page-secret">REAL_BROWSER_CONTENT_MOUNTED</p>
  <cloak-gate id="wc-demo" mode="${mode}"><div id="wc-inner">WC_SECRET_VISIBLE</div></cloak-gate>
  <p><a href="/__cloakgate/playground" style="color:#38bdf8;">Open Live 6-Invariant Diagnostic Playground →</a></p>
</body></html>`;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(html) });
    res.end(html);
  });
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));
  const bPort = backend.address().port;

  const shield = createCloakGateServer({
    target: `http://127.0.0.1:${bPort}`,
    mode,
    protectedPaths: ["/api"],
    autoBlockPage: true,
    onDetect: (ev) => {
      console.log(`[cloakgate] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.join(",")}`);
    },
  });
  const url = await shield.listen(port, "127.0.0.1");
  console.log(`[cloakgate] Demo active at ${url} (mode=${mode})`);
  console.log(`[cloakgate] Diagnostic playground: ${url}/__cloakgate/playground`);
}

async function main() {
  const [, , cmd, ...rest] = process.argv;
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    return;
  }

  if (cmd === "snippet") {
    const f = parseFlags(rest);
    printSnippets(f.mode || "strict");
    return;
  }

  if (cmd === "ask" || cmd === "do" || cmd === "explain") {
    const forceDry = cmd === "explain";
    const flags = parseFlags(rest);
    const words = rest.filter((w) => !["--dry-run", "--json"].includes(w));
    const plan = compileNaturalLanguage(words.join(" "));
    const dryRun = forceDry || Boolean(flags.dryRun);
    if (flags.json) {
      console.log(JSON.stringify({ ok: true, dryRun, ...plan }, null, 2));
      if (dryRun) return;
    } else {
      console.log("[cloakgate natural language]");
      console.log(`  You asked: "${plan.input}"`);
      console.log(`  Goal:      ${plan.goal}`);
      console.log(`  Command:   ${plan.command}`);
      console.log("  Why:");
      for (const r of plan.reasons) console.log(`    - ${r}`);
      if (dryRun) {
        console.log('  Mode:      DRY-RUN (run with "cloakgate ask ..." to execute)');
        return;
      }
    }
    if (plan.intent === "snippet") {
      printSnippets(plan.options.mode);
      return;
    }
    if (plan.intent === "demo") {
      await runDemo(plan.options.port, plan.options.mode);
      return;
    }
    const shield = createCloakGateServer({
      ...plan.options,
      onDetect: (ev) => console.log(`[cloakgate] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.path} score=${ev.score}`),
    });
    const url = await shield.listen(plan.options.port, "127.0.0.1");
    console.log(`[cloakgate] Shield listening at ${url} -> ${plan.options.target} (mode=${plan.options.mode})`);
    return;
  }

  if (cmd === "demo") {
    const f = parseFlags(rest);
    await runDemo(f.port || 8089, f.mode || "strict");
    return;
  }

  if (cmd === "protect") {
    const f = parseFlags(rest);
    if (!f.target) {
      console.error("Missing --target <url> (example: cloakgate protect --target http://127.0.0.1:3000 --port 8080)");
      process.exit(1);
    }
    const shield = createCloakGateServer({
      target: f.target,
      mode: f.mode || "strict",
      protectedPaths: f.protectedPaths || ["/api"],
    });
    const url = await shield.listen(f.port || 8080, f.host || "127.0.0.1");
    console.log(`[cloakgate] Shield active at ${url} -> ${f.target} (mode=${shield.mode})`);
    return;
  }

  console.error(`Unknown command: ${cmd}`);
  printHelp();
  process.exit(1);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
