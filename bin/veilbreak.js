#!/usr/bin/env node
"use strict";

const http = require("node:http");
const { createVeilBreakServer, compileNaturalLanguage, normalizeMode } = require("../src/index.js");

function printHelp() {
  console.log(`VeilBreak v2.0.0 — Universal Anti-Stealth & Browser Integrity Gate

Natural-Language Mode:
  node bin/veilbreak.js ask "block stealth browsers on http://localhost:3000 on port 8080"
  node bin/veilbreak.js ask "protect http://localhost:3000 while keeping privacy browsers working"
  node bin/veilbreak.js explain "watch for anti-detect browsers without blocking on http://localhost:3000"

Commands:
  node bin/veilbreak.js protect --target <url> [--port 8080] [--host 127.0.0.1]
                        [--mode strict|balanced|monitor|off] [--paths /api]
                        [--no-playground] [--no-debug-headers]
  node bin/veilbreak.js demo [--port 8089] [--host 127.0.0.1] [--mode strict|balanced|monitor]
  node bin/veilbreak.js snippet [--mode strict|balanced|monitor]
  node bin/veilbreak.js ask "<natural language>" [--dry-run] [--json]
  node bin/veilbreak.js explain "<natural language>" [--json]
`);
}

function printSnippets(rawMode = "strict") {
  const mode = normalizeMode(rawMode);
  console.log(`<!-- 1. One-line HTML drop-in (blocks stealth & automated browsers across the page) -->
<script src="/__veilbreak/gate.js" data-mode="${mode}" data-block-page="true"></script>

<!-- 2. Protect any specific Web Component / section with <veil-break> -->
<script src="/__veilbreak/gate.js" data-mode="${mode}" data-block-page="false"></script>
<veil-break mode="${mode}">
  <my-pricing-widget></my-pricing-widget>
</veil-break>

// 3. Express / Node.js server middleware (from cloned repo — remember to include <script src="/__veilbreak/gate.js"> in your HTML!)
const { createVeilBreakMiddleware } = require("./src/index.js");
app.use(createVeilBreakMiddleware({ mode: "${mode}", protectedPaths: ["/api"] }));
`);
}

function parsePortStrict(raw) {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new Error(`Invalid --port value '${raw}': expected integer 0-65535`);
  }
  return n;
}

function parseFlags(args, { allowPositional = false } = {}) {
  const opts = { positionals: [] };
  const valueFlags = new Set(["--target", "--port", "--host", "--mode", "--paths"]);
  const boolFlags = new Set(["--dry-run", "--json", "--no-playground", "--no-debug-headers", "--no-inject"]);

  for (let i = 0; i < args.length; i++) {
    let a = args[i];
    let inlineVal = null;
    if (a.startsWith("--") && a.includes("=")) {
      const eq = a.indexOf("=");
      inlineVal = a.slice(eq + 1);
      a = a.slice(0, eq);
    }

    if (boolFlags.has(a)) {
      if (a === "--dry-run") opts.dryRun = true;
      else if (a === "--json") opts.json = true;
      else if (a === "--no-playground") opts.enablePlayground = false;
      else if (a === "--no-debug-headers") opts.exposeDebugHeaders = false;
      else if (a === "--no-inject") opts.injectGate = false;
      continue;
    }

    if (valueFlags.has(a)) {
      const val = inlineVal !== null ? inlineVal : args[++i];
      if (val === undefined || (inlineVal === null && val.startsWith("--"))) {
        throw new Error(`Flag '${a}' requires a value`);
      }
      if (a === "--target") opts.target = val;
      else if (a === "--port") opts.port = parsePortStrict(val);
      else if (a === "--host") opts.host = val;
      else if (a === "--mode") opts.mode = normalizeMode(val);
      else if (a === "--paths") opts.protectedPaths = val.split(",").map((s) => s.trim()).filter(Boolean);
      continue;
    }

    if (a.startsWith("-")) {
      throw new Error(`Unknown flag '${a}'. Run with --help to see supported flags.`);
    }
    if (!allowPositional) {
      throw new Error(`Unexpected argument '${a}'. Run with --help for usage.`);
    }
    opts.positionals.push(a);
  }
  return opts;
}

function attachGracefulShutdown(closers) {
  let closing = false;
  const shutdown = () => {
    if (closing) return;
    closing = true;
    Promise.all(closers.map((fn) => Promise.resolve().then(fn).catch(() => {}))).finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function runDemo(port = 8089, mode = "strict", host = "127.0.0.1", quietStdout = false) {
  const backend = http.createServer((req, res) => {
    if (req.url === "/api/secret") {
      const payload = JSON.stringify({ ok: true, secret: "REAL_BROWSER_ONLY_API_DATA" });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) });
      res.end(payload);
      return;
    }
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>VeilBreak Protected App</title></head>
<body style="background:#0b0f19;color:#e2e8f0;font-family:system-ui;padding:32px;">
  <h1>VeilBreak Protected Page (${mode})</h1>
  <p id="page-secret">REAL_BROWSER_CONTENT_MOUNTED</p>
  <veil-break id="wc-demo" mode="${mode}"><div id="wc-inner">WC_SECRET_VISIBLE</div></veil-break>
  <p><a href="/__veilbreak/playground" style="color:#38bdf8;">Open Live 14-Invariant Diagnostic Playground →</a></p>
</body></html>`;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(html) });
    res.end(html);
  });
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));
  const bPort = backend.address().port;

  const shield = createVeilBreakServer({
    target: `http://127.0.0.1:${bPort}`,
    mode,
    protectedPaths: ["/api"],
    autoBlockPage: true,
    onDetect: (ev) => {
      console.error(`[veilbreak] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.join(",")}`);
    },
  });
  const url = await shield.listen(port, host);
  attachGracefulShutdown([() => shield.close(), () => new Promise((r) => backend.close(r))]);
  if (!quietStdout) {
    console.log(`[veilbreak] Demo active at ${url} (mode=${mode})`);
    console.log(`[veilbreak] Diagnostic playground: ${url}/__veilbreak/playground`);
  }
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
    const flags = parseFlags(rest, { allowPositional: true });
    const plan = compileNaturalLanguage(flags.positionals.join(" "));
    const dryRun = forceDry || Boolean(flags.dryRun);
    if (flags.json) {
      console.log(JSON.stringify({ ok: true, dryRun, ...plan }, null, 2));
      if (dryRun) return;
    } else {
      console.log("[veilbreak natural language]");
      console.log(`  You asked: "${plan.input}"`);
      console.log(`  Goal:      ${plan.goal}`);
      console.log(`  Command:   ${plan.command}`);
      console.log("  Why:");
      for (const r of plan.reasons) console.log(`    - ${r}`);
      if (dryRun) {
        console.log('  Mode:      DRY-RUN (run with "node bin/veilbreak.js ask ..." to execute)');
        return;
      }
    }
    if (plan.intent === "snippet") {
      printSnippets(flags.mode || plan.options.mode);
      return;
    }
    if (plan.intent === "demo") {
      await runDemo(flags.port ?? plan.options.port, flags.mode || plan.options.mode, flags.host || "127.0.0.1", Boolean(flags.json));
      return;
    }
    const shield = createVeilBreakServer({
      ...plan.options,
      mode: flags.mode || plan.options.mode,
      enablePlayground: flags.enablePlayground,
      exposeDebugHeaders: flags.exposeDebugHeaders,
      injectGate: flags.injectGate,
      onDetect: (ev) => console.error(`[veilbreak] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.join(",")}`),
    });
    const url = await shield.listen(flags.port ?? plan.options.port, flags.host || "127.0.0.1");
    attachGracefulShutdown([() => shield.close()]);
    if (!flags.json) {
      console.log(`[veilbreak] Gate listening at ${url} -> ${plan.options.target} (mode=${shield.mode})`);
    }
    return;
  }

  if (cmd === "demo") {
    const f = parseFlags(rest);
    await runDemo(f.port ?? 8089, f.mode || "strict", f.host || "127.0.0.1");
    return;
  }

  if (cmd === "protect") {
    const f = parseFlags(rest);
    if (!f.target) {
      console.error("Missing --target <url> (example: node bin/veilbreak.js protect --target http://127.0.0.1:3000 --port 8080)");
      process.exit(1);
    }
    const shield = createVeilBreakServer({
      target: f.target,
      mode: f.mode || "strict",
      protectedPaths: f.protectedPaths || ["/api"],
      enablePlayground: f.enablePlayground,
      exposeDebugHeaders: f.exposeDebugHeaders,
      injectGate: f.injectGate,
      onDetect: (ev) => {
        console.error(`[veilbreak] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.join(",")}`);
      },
    });
    const url = await shield.listen(f.port ?? 8080, f.host || "127.0.0.1");
    attachGracefulShutdown([() => shield.close()]);
    console.log(`[veilbreak] Gate active at ${url} -> ${f.target} (mode=${shield.mode})`);
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
