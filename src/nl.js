"use strict";

function compileNaturalLanguage(sentence) {
  const input = String(sentence || "").trim();
  if (!input) {
    throw new Error('Describe what you want in plain English, e.g.:\n  cloakgate ask "block cloakbrowser on http://localhost:3000 on port 8080"');
  }
  const low = input.toLowerCase();

  if (/\b(snippet|code|html|embed|react|web component)\b/.test(low) && !/https?:\/\//.test(low)) {
    const mode = /\b(brave|privacy|balanced)\b/.test(low) ? "balanced" : "strict";
    return {
      input,
      intent: "snippet",
      goal: `Print ready-to-paste HTML, <cloak-gate> Web Component, and Express integration snippets (${mode})`,
      options: { mode },
      command: `cloakgate snippet --mode ${mode}`,
      reasons: ["Gives beginners a 1-line copy-paste script tag and <cloak-gate> wrapper"],
    };
  }

  if (/\b(demo|playground|diagnostic|test my browser|try it)\b/.test(low) && !/https?:\/\//.test(low)) {
    const mode = /\b(brave|privacy|balanced)\b/.test(low) ? "balanced" : "strict";
    return {
      input,
      intent: "demo",
      goal: `Launch live CloakGate diagnostic playground & <cloak-gate> Web Component demo (${mode})`,
      options: { port: 8089, mode },
      command: `cloakgate demo --port 8089 --mode ${mode}`,
      reasons: ["Open in normal Chrome (0/11 CLEAN) vs CloakBrowser (11/11 DENIED) to see all 6 hardware invariants live"],
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
    reasons.push("--mode monitor: scores CloakBrowser visits via X-CloakGate-Score without blocking users");
  } else if (/\b(brave|librewolf|privacy browser|balanced|gentle)\b/.test(low)) {
    mode = "balanced";
    reasons.push("--mode balanced (score >= 4): blocks CloakBrowser (11/11 or 8/11) while allowing Canvas-only privacy browsers like Brave");
  } else {
    mode = "strict";
    reasons.push("--mode strict (score >= 2 + mandatory ticket-bound SHA-256 attest + headless UA denial): maximum CloakBrowser blocking");
  }

  const pathMatches = [...input.matchAll(/(\/[a-z0-9_/-]+)/gi)]
    .map((m) => m[1])
    .filter((p) => !urlMatch || !urlMatch[0].endsWith(p))
    .filter((p) => p !== "/" && !p.startsWith("//"));
  const protectedPaths = pathMatches.length > 0 ? [...new Set(pathMatches)] : ["/api"];
  reasons.push(`Auto-injects /__cloakgate/gate.js into HTML pages and verifies SHA-256 hardware attestation on ${protectedPaths.join(", ")}`);

  return {
    input,
    intent: "protect",
    goal: `Block CloakBrowser in front of ${target} on http://127.0.0.1:${listenPort} (${mode})`,
    options: { target, port: listenPort, mode, protectedPaths },
    command: `cloakgate protect --target ${target} --port ${listenPort} --mode ${mode} --paths ${protectedPaths.join(",")}`,
    reasons,
  };
}

module.exports = { compileNaturalLanguage };
