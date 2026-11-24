"use strict";

function compileNaturalLanguage(sentence) {
  const input = String(sentence || "").trim();
  if (!input) {
    throw new Error('Describe what you want in natural language, e.g.:\n  veilbreak ask "block stealth browsers on http://localhost:3000 on port 8080"');
  }
  const low = input.toLowerCase();

  if (/\b(snippet|code|html|embed|react|web component)\b/.test(low) && !/https?:\/\//.test(low)) {
    const mode = /\b(brave|privacy|balanced)\b/.test(low) ? "balanced" : "strict";
    return {
      input,
      intent: "snippet",
      goal: `Print ready-to-paste HTML, <veil-break> Web Component, and Express integration snippets (${mode})`,
      options: { mode },
      command: `veilbreak snippet --mode ${mode}`,
      reasons: ["Gives a 1-line copy-paste script tag, <veil-break> Shadow DOM wrapper, and server middleware"],
    };
  }

  if (/\b(demo|playground|diagnostic|test my browser|try it)\b/.test(low) && !/https?:\/\//.test(low)) {
    const mode = /\b(brave|privacy|balanced)\b/.test(low) ? "balanced" : "strict";
    return {
      input,
      intent: "demo",
      goal: `Launch live VeilBreak 14-invariant diagnostic playground & <veil-break> demo (${mode})`,
      options: { port: 8089, mode },
      command: `veilbreak demo --port 8089 --mode ${mode}`,
      reasons: ["Open in standard Chrome/Firefox vs any stealth or automation browser to inspect all 14 invariants + click kinematics live"],
    };
  }

  const urlMatch = input.match(/https?:\/\/[^\s"'`]+/i);
  const target = urlMatch ? urlMatch[0].replace(/[.,;!?]+$/, "") : "http://127.0.0.1:3000";
  const explicitPort = input.match(/\bport\s+(\d{2,5})\b/i);
  const listenPort = explicitPort ? Number(explicitPort[1]) : 8080;

  let mode = "strict";
  const reasons = [];
  if (/\b(monitor|watch|log only|without blocking|observe|audit)\b/.test(low)) {
    mode = "monitor";
    reasons.push("--mode monitor: scores browser visits via X-VeilBreak-Score without blocking users");
  } else if (/\b(brave|librewolf|privacy browsers?|balanced|gentle)\b/.test(low)) {
    mode = "balanced";
    reasons.push("--mode balanced (score >= 4): blocks multi-invariant stealth & automated browsers while allowing canvas-only privacy browsers");
  } else {
    mode = "strict";
    reasons.push("--mode strict (score >= 2 + mandatory one-time ticket SHA-256 attest + automation UA denial): maximum stealth & automation blocking");
  }

  const pathMatches = [...input.matchAll(/(\/[a-z0-9_/-]+)/gi)]
    .map((m) => m[1])
    .filter((p) => !urlMatch || !urlMatch[0].endsWith(p))
    .filter((p) => p !== "/" && !p.startsWith("//"));
  const protectedPaths = pathMatches.length > 0 ? [...new Set(pathMatches)] : ["/api"];
  reasons.push(`Auto-injects /__veilbreak/gate.js into HTML pages and verifies VB_ATTEST_V2 SHA-256 attestation on ${protectedPaths.join(", ")}`);

  return {
    input,
    intent: "protect",
    goal: `Protect ${target} against stealth & automated browsers on http://127.0.0.1:${listenPort} (${mode})`,
    options: { target, port: listenPort, mode, protectedPaths },
    command: `veilbreak protect --target ${target} --port ${listenPort} --mode ${mode} --paths ${protectedPaths.join(",")}`,
    reasons,
  };
}

module.exports = { compileNaturalLanguage };
