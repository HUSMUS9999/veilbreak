"use strict";

function shellQuote(arg) {
  const s = String(arg);
  if (/^[a-zA-Z0-9_./:@=,-]+$/.test(s)) return s;
  return `'${s.replace(/'/g, "'\\''")}'`;
}

function parsePort(val, fallback) {
  const n = Number(val);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return fallback;
  return n;
}

function detectMode(low) {
  const negatedMonitor = /\b(?:don'?t|do not|not)\s+(?:just\s+)?(?:monitor|watch|observe)\b/.test(low);
  const explicitMonitor =
    !negatedMonitor &&
    /\b(without blocking|monitor only|log only|watch only|observe only|monitor mode)\b/.test(low);
  const plainMonitor =
    !negatedMonitor &&
    !/\b(block|deny|stop|prevent|strict)\b/.test(low) &&
    /\b(monitor|watch|observe|audit)\b/.test(low);
  if (explicitMonitor || plainMonitor) return "monitor";
  if (/\b(brave|librewolf|privacy browsers?|balanced|gentle|relaxed)\b/.test(low)) return "balanced";
  if (/\b(disable|turn off|mode off)\b/.test(low)) return "off";
  return "strict";
}

function compileNaturalLanguage(sentence) {
  const input = String(sentence || "").trim();
  if (!input) {
    throw new Error('Describe what you want in natural language, e.g.:\n  node bin/veilbreak.js ask "block stealth browsers on http://localhost:3000 on port 8080"');
  }
  const low = input.toLowerCase();
  const explicitPortMatch = input.match(/\bport[\s=]+(\d{1,5})\b/i);
  const mode = detectMode(low);

  if (/\b(snippet|code|html|embed|react|web component)\b/.test(low) && !/https?:\/\//.test(low)) {
    return {
      input,
      intent: "snippet",
      goal: `Print ready-to-paste HTML, <veil-break> Web Component, and Express integration snippets (${mode})`,
      options: { mode },
      command: `node bin/veilbreak.js snippet --mode ${mode}`,
      reasons: ["Gives a 1-line copy-paste script tag, <veil-break> Shadow DOM wrapper, and server middleware"],
    };
  }

  if (/\b(demo|playground|diagnostic|test my browser|try it)\b/.test(low) && !/https?:\/\//.test(low)) {
    const demoPort = explicitPortMatch ? parsePort(explicitPortMatch[1], 8089) : 8089;
    return {
      input,
      intent: "demo",
      goal: `Launch live VeilBreak 14-invariant diagnostic playground & <veil-break> demo (${mode})`,
      options: { port: demoPort, mode },
      command: `node bin/veilbreak.js demo --port ${demoPort} --mode ${mode}`,
      reasons: ["Open in standard Chrome/Firefox vs any stealth or automation browser to inspect all 14 invariants + click kinematics live"],
    };
  }

  const urlMatch = input.match(/https?:\/\/[^\s"'`)};|&<>]+/i);
  let target = "http://127.0.0.1:3000";
  if (urlMatch) {
    const candidate = urlMatch[0].replace(/[.,;!?)]+$/, "");
    let parsed;
    try {
      parsed = new URL(candidate);
    } catch {
      throw new Error(`Invalid target URL in prompt: '${candidate}'`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error(`Unsupported URL scheme '${parsed.protocol}': expected http:// or https://`);
    }
    target = parsed.toString().replace(/\/$/, "");
  }

  let listenPort = 8080;
  if (explicitPortMatch) {
    const p = parsePort(explicitPortMatch[1], null);
    if (!p) throw new Error(`Invalid port number '${explicitPortMatch[1]}' (expected 1-65535)`);
    listenPort = p;
  }

  const reasons = [];
  if (mode === "monitor") {
    reasons.push("--mode monitor: scores browser visits via X-VeilBreak-Score without blocking users");
  } else if (mode === "balanced") {
    reasons.push("--mode balanced (score >= 4): requires multiple corroborating physics failures or high-confidence automation proof; allows single-invariant canvas farbling");
  } else if (mode === "off") {
    reasons.push("--mode off: disables blocking for local development");
  } else {
    reasons.push("--mode strict (score >= 2 + mandatory one-time ticket + automation UA denial): maximum stealth & automation blocking");
  }

  // Strip target URLs first, and require whitespace/boundary before `/` so "Brave/LibreWolf" or "Chrome/Firefox" never matches!
  const withoutUrls = input.replace(/https?:\/\/[^\s"'`)]+/gi, " ");
  const pathMatches = [...withoutUrls.matchAll(/(?:^|[\s,'"`])(\/[a-z0-9._~/-]+)/gi)]
    .map((m) => m[1].replace(/[.,;!?)]+$/, ""))
    .filter((p) => p !== "/" && !p.startsWith("//"));
  const protectedPaths = pathMatches.length > 0 ? [...new Set(pathMatches)] : ["/api"];
  reasons.push(`Auto-injects /__veilbreak/gate.js into HTML pages and verifies one-time tickets + VB_ATTEST_V2 on ${protectedPaths.join(", ")}`);

  return {
    input,
    intent: "protect",
    goal: `Protect ${target} against stealth & automated browsers on http://127.0.0.1:${listenPort} (${mode})`,
    options: { target, port: listenPort, mode, protectedPaths },
    command: `node bin/veilbreak.js protect --target ${shellQuote(target)} --port ${listenPort} --mode ${mode} --paths ${shellQuote(protectedPaths.join(","))}`,
    reasons,
  };
}

module.exports = { compileNaturalLanguage };
