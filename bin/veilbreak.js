#!/usr/bin/env node
"use strict";

const http = require("node:http");
const { createVeilBreakServer, compileNaturalLanguage, normalizeMode } = require("../src/index.js");

const pkgVersion = (() => {
  try {
    return require("../package.json").version || "2.1.0";
  } catch {
    return "2.1.0";
  }
})();

function printHelp() {
  console.log(`VeilBreak v${pkgVersion} — Universal Anti-Stealth & Browser Integrity Gate

Natural-Language Mode:
  node bin/veilbreak.js ask "block stealth browsers on http://localhost:3000 on port 8080"
  node bin/veilbreak.js ask "protect http://localhost:3000 while keeping privacy browsers working"
  node bin/veilbreak.js explain "watch for anti-detect browsers without blocking on http://localhost:3000"

Commands:
  node bin/veilbreak.js protect --target <url> [--port 8080] [--host 127.0.0.1]
                        [--mode strict|balanced|monitor|observe|off] [--paths /api]
                        [--trust-proxy 127.0.0.1,10.0.0.0/8] [--pow-bits 12]
                        [--no-playground] [--no-debug-headers] [--no-inject] [--no-anti-cdp]
  node bin/veilbreak.js demo [--port 8089] [--host 127.0.0.1] [--mode strict|balanced|monitor|observe|off]
  node bin/veilbreak.js snippet [--mode strict|balanced|monitor|observe|off]
  node bin/veilbreak.js ask|do "<natural language>" [--dry-run] [--json]
  node bin/veilbreak.js explain "<natural language>" [--json]
`);
}

function buildSnippetsText(rawMode = "strict") {
  const mode = normalizeMode(rawMode);
  return `<!-- 1. One-line HTML drop-in (blocks stealth & automated browsers across the page) -->
<script src="/__veilbreak/gate.js" data-mode="${mode}" data-block-page="true"></script>

<!-- 2. Protect any specific Web Component / section with <veil-break> -->
<script src="/__veilbreak/gate.js" data-mode="${mode}" data-block-page="false"></script>
<veil-break mode="${mode}">
  <my-pricing-widget></my-pricing-widget>
</veil-break>

// 3. Express / Node.js server middleware (remember to include <script src="/__veilbreak/gate.js"> in your HTML!)
const { createVeilBreakMiddleware } = require("veilbreak");
app.use(createVeilBreakMiddleware({ mode: "${mode}", protectedPaths: ["/api"] }));
`;
}

function parsePortStrict(raw) {
  const s = String(raw ?? "").trim();
  if (!/^\d{1,5}$/.test(s)) {
    throw new Error(`Invalid --port value '${raw}': expected decimal integer 0-65535`);
  }
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new Error(`Invalid --port value '${raw}': expected integer 0-65535`);
  }
  return n;
}

function parseNonNegIntFlag(flag, raw, maxVal = 22) {
  const s = String(raw ?? "").trim();
  if (!/^\d+$/.test(s)) {
    throw new Error(`Invalid ${flag} value '${raw}': expected an integer 0-${maxVal}`);
  }
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0 || n > maxVal) {
    throw new Error(`Invalid ${flag} value '${raw}': expected an integer 0-${maxVal}`);
  }
  return n;
}

function parseFlags(args, { allowPositional = false, allowedFlags = null } = {}) {
  const opts = { positionals: [] };
  const valueFlags = new Set(["--target", "--port", "--host", "--mode", "--paths", "--trust-proxy", "--pow-bits"]);
  const boolFlags = new Set(["--dry-run", "--json", "--no-playground", "--no-debug-headers", "--no-inject", "--no-anti-cdp"]);
  let endOfFlags = false;

  for (let i = 0; i < args.length; i++) {
    let a = args[i];
    if (!endOfFlags && a === "--") {
      endOfFlags = true;
      continue;
    }
    if (!endOfFlags && (a === "--help" || a === "-h")) {
      opts.help = true;
      return opts;
    }
    if (endOfFlags) {
      if (!allowPositional) throw new Error(`Unexpected argument '${a}'. Run with --help for usage.`);
      opts.positionals.push(a);
      continue;
    }

    let inlineVal = null;
    if (a.startsWith("--") && a.includes("=")) {
      const eq = a.indexOf("=");
      inlineVal = a.slice(eq + 1);
      a = a.slice(0, eq);
    }

    if (boolFlags.has(a)) {
      if (allowedFlags && !allowedFlags.has(a)) {
        throw new Error(`Flag '${a}' is not supported for this command. Run with --help for usage.`);
      }
      if (inlineVal !== null) {
        throw new Error(`Flag '${a}' does not accept a value`);
      }
      if (a === "--dry-run") opts.dryRun = true;
      else if (a === "--json") opts.json = true;
      else if (a === "--no-playground") opts.enablePlayground = false;
      else if (a === "--no-debug-headers") opts.exposeDebugHeaders = false;
      else if (a === "--no-inject") opts.injectGate = false;
      else if (a === "--no-anti-cdp") opts.antiCdp = false;
      continue;
    }

    if (valueFlags.has(a)) {
      if (allowedFlags && !allowedFlags.has(a)) {
        throw new Error(`Flag '${a}' is not supported for this command. Run with --help for usage.`);
      }
      const val = inlineVal !== null ? inlineVal : args[++i];
      if (val === undefined || (inlineVal === null && val.startsWith("--"))) {
        throw new Error(`Flag '${a}' requires a value`);
      }
      if (a === "--target") {
        if (!val.trim()) throw new Error("Flag '--target' cannot be empty");
        opts.target = val.trim();
      } else if (a === "--port") {
        opts.port = parsePortStrict(val);
      } else if (a === "--host") {
        if (!val.trim()) throw new Error("Flag '--host' cannot be empty");
        opts.host = val.trim();
      } else if (a === "--mode") {
        opts.mode = normalizeMode(val);
      } else if (a === "--paths") {
        const list = val.split(",").map((s) => s.trim()).filter(Boolean);
        if (list.length === 0) throw new Error("Flag '--paths' must include at least one route prefix");
        opts.protectedPaths = list;
      } else if (a === "--trust-proxy") {
        const list = val.split(",").map((s) => s.trim()).filter(Boolean);
        if (list.length === 0) throw new Error("Flag '--trust-proxy' cannot be empty");
        opts.trustProxy = list;
      } else if (a === "--pow-bits") {
        opts.ticketPowBits = parseNonNegIntFlag("--pow-bits", val, 22);
      }
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
    if (closing) process.exit(130);
    closing = true;
    const deadline = setTimeout(() => process.exit(0), 3000);
    if (typeof deadline.unref === "function") deadline.unref();
    Promise.all(closers.map((fn) => Promise.resolve().then(fn).catch(() => {}))).finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function runDemo(port = 8089, mode = "strict", host = "127.0.0.1", quietStdout = false) {
  const safeMode = normalizeMode(mode);
  const backend = http.createServer((req, res) => {
    const pathname = String(req.url || "/").split("?")[0];
    if (pathname === "/api/secret") {
      const payload = JSON.stringify({ ok: true, secret: "REAL_BROWSER_ONLY_API_DATA" });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) });
      res.end(payload);
      return;
    }
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>VeilBreak Protected App</title></head>
<body style="background:#0b0f19;color:#e2e8f0;font-family:system-ui;padding:32px;">
  <h1>VeilBreak Protected Page (${safeMode})</h1>
  <p id="page-secret">REAL_BROWSER_CONTENT_MOUNTED</p>
  <veil-break id="wc-demo" mode="${safeMode}"><div id="wc-inner">WC_SECRET_VISIBLE</div></veil-break>
  <p><a href="/__veilbreak/playground" style="color:#38bdf8;">Open Live 14-Invariant Diagnostic Playground →</a></p>
</body></html>`;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(html) });
    res.end(html);
  });
  await new Promise((resolve, reject) => {
    backend.once("error", reject);
    backend.listen(0, "127.0.0.1", () => {
      backend.removeListener("error", reject);
      resolve();
    });
  });
  const bPort = backend.address().port;
  const closeBackend = () =>
    new Promise((r) => {
      if (typeof backend.closeAllConnections === "function") backend.closeAllConnections();
      backend.close(r);
    });

  let shield;
  let url;
  try {
    shield = createVeilBreakServer({
      target: `http://127.0.0.1:${bPort}`,
      mode: safeMode,
      protectedPaths: ["/api"],
      autoBlockPage: true,
      onDetect: (ev) => {
        console.error(
          `[veilbreak] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.join(",")}`
        );
      },
    });
    url = await shield.listen(port, host);
  } catch (err) {
    await closeBackend();
    throw err;
  }
  attachGracefulShutdown([() => shield.close(), closeBackend]);
  if (!quietStdout) {
    console.log(`[veilbreak] Demo active at ${url} (mode=${safeMode})`);
    console.log(`[veilbreak] Diagnostic playground: ${url}/__veilbreak/playground`);
  }
}

const PROTECT_FLAGS = new Set([
  "--target",
  "--port",
  "--host",
  "--mode",
  "--paths",
  "--trust-proxy",
  "--pow-bits",
  "--no-playground",
  "--no-debug-headers",
  "--no-inject",
  "--no-anti-cdp",
]);
const DEMO_FLAGS = new Set(["--port", "--host", "--mode"]);
const SNIPPET_FLAGS = new Set(["--mode"]);
const ASK_FLAGS = new Set([...PROTECT_FLAGS, "--dry-run", "--json"]);
const EXPLAIN_FLAGS = new Set(["--json", "--port", "--mode", "--target", "--paths", "--trust-proxy"]);

async function main() {
  const [, , cmd, ...rest] = process.argv;
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    return;
  }

  if (cmd === "snippet") {
    const f = parseFlags(rest, { allowedFlags: SNIPPET_FLAGS });
    if (f.help) {
      printHelp();
      return;
    }
    console.log(buildSnippetsText(f.mode || "strict"));
    return;
  }

  if (cmd === "ask" || cmd === "do" || cmd === "explain") {
    const forceDry = cmd === "explain";
    const flags = parseFlags(rest, {
      allowPositional: true,
      allowedFlags: forceDry ? EXPLAIN_FLAGS : ASK_FLAGS,
    });
    if (flags.help) {
      printHelp();
      return;
    }
    const plan = compileNaturalLanguage(flags.positionals.join(" "));
    if (flags.port !== undefined && plan.intent !== "snippet") plan.options.port = flags.port;
    if (flags.mode !== undefined) plan.options.mode = flags.mode;
    if (flags.target !== undefined && plan.intent === "protect") plan.options.target = flags.target;
    if (flags.protectedPaths !== undefined && plan.intent === "protect") plan.options.protectedPaths = flags.protectedPaths;
    if (flags.trustProxy !== undefined && plan.intent === "protect") plan.options.trustProxy = flags.trustProxy;

    const dryRun = forceDry || Boolean(flags.dryRun);
    if (flags.json) {
      const payload = { ok: true, dryRun, ...plan };
      if (!dryRun && plan.intent === "snippet") {
        payload.snippet = buildSnippetsText(plan.options.mode);
      }
      console.log(JSON.stringify(payload, null, 2));
      if (dryRun || plan.intent === "snippet") return;
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
      console.log(buildSnippetsText(plan.options.mode));
      return;
    }
    if (plan.intent === "demo") {
      await runDemo(plan.options.port, plan.options.mode, flags.host || "127.0.0.1", Boolean(flags.json));
      return;
    }
    const shield = createVeilBreakServer({
      ...plan.options,
      ticketPowBits: flags.ticketPowBits,
      enablePlayground: flags.enablePlayground,
      exposeDebugHeaders: flags.exposeDebugHeaders,
      injectGate: flags.injectGate,
      antiCdp: flags.antiCdp,
      onDetect: (ev) =>
        console.error(
          `[veilbreak] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.join(",")}`
        ),
    });
    const url = await shield.listen(plan.options.port, flags.host || "127.0.0.1");
    attachGracefulShutdown([() => shield.close()]);
    if (!flags.json) {
      console.log(`[veilbreak] Gate listening at ${url} -> ${plan.options.target} (mode=${shield.mode})`);
    }
    return;
  }

  if (cmd === "demo") {
    const f = parseFlags(rest, { allowedFlags: DEMO_FLAGS });
    if (f.help) {
      printHelp();
      return;
    }
    await runDemo(f.port ?? 8089, f.mode || "strict", f.host || "127.0.0.1");
    return;
  }

  if (cmd === "protect") {
    const f = parseFlags(rest, { allowedFlags: PROTECT_FLAGS });
    if (f.help) {
      printHelp();
      return;
    }
    if (!f.target) {
      console.error("Missing --target <url> (example: node bin/veilbreak.js protect --target http://127.0.0.1:3000 --port 8080)");
      process.exit(1);
    }
    const shield = createVeilBreakServer({
      target: f.target,
      mode: f.mode || "strict",
      protectedPaths: f.protectedPaths || ["/api"],
      trustProxy: f.trustProxy,
      ticketPowBits: f.ticketPowBits,
      enablePlayground: f.enablePlayground,
      exposeDebugHeaders: f.exposeDebugHeaders,
      injectGate: f.injectGate,
      antiCdp: f.antiCdp,
      onDetect: (ev) => {
        console.error(
          `[veilbreak] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.join(",")}`
        );
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
