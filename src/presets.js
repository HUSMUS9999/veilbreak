"use strict";

const VALID_MODES = new Set(["off", "monitor", "observe", "balanced", "strict", "paranoid"]);

const SECURITY_PRESETS = Object.freeze({
  off: Object.freeze({
    mode: "off",
    threshold: Number.POSITIVE_INFINITY,
    ticketPowBits: 0,
    bindIp: false,
    requireFetchMetadata: false,
    blockAiCrawlers: false,
    antiCdp: false,
    allowDevTools: true,
    cdpRuntimeWeight: 0,
    autoBlockPage: false,
    sri: false,
  }),
  monitor: Object.freeze({
    mode: "monitor",
    threshold: Number.POSITIVE_INFINITY,
    ticketPowBits: 0,
    bindIp: false,
    requireFetchMetadata: false,
    blockAiCrawlers: true,
    antiCdp: true,
    allowDevTools: true,
    cdpRuntimeWeight: 1,
    autoBlockPage: false,
    sri: true,
  }),
  balanced: Object.freeze({
    mode: "balanced",
    threshold: 4,
    ticketPowBits: 10,
    bindIp: false,
    requireFetchMetadata: false,
    blockAiCrawlers: true,
    antiCdp: true,
    allowDevTools: true,
    cdpRuntimeWeight: 1,
    autoBlockPage: false,
    sri: true,
  }),
  strict: Object.freeze({
    mode: "strict",
    threshold: 2,
    ticketPowBits: 12,
    bindIp: true,
    requireFetchMetadata: true,
    blockAiCrawlers: true,
    antiCdp: true,
    allowDevTools: false,
    cdpRuntimeWeight: 4,
    autoBlockPage: true,
    sri: true,
  }),
  paranoid: Object.freeze({
    mode: "paranoid",
    threshold: 2,
    ticketPowBits: 14,
    bindIp: true,
    requireFetchMetadata: true,
    blockAiCrawlers: true,
    antiCdp: true,
    allowDevTools: false,
    cdpRuntimeWeight: 6,
    autoBlockPage: true,
    sri: true,
  }),
});

function normalizeMode(mode = "strict") {
  const m = String(mode ?? "strict").trim().toLowerCase();
  if (!VALID_MODES.has(m)) {
    throw new Error(
      `Invalid VeilBreak mode '${mode}': expected 'off', 'monitor', 'observe', 'balanced', 'strict', or 'paranoid'`
    );
  }
  return m === "observe" ? "monitor" : m;
}

function resolvePreset(mode = "strict", overrides = {}) {
  const norm = normalizeMode(mode);
  const base = SECURITY_PRESETS[norm];
  const antiCdp = overrides.antiCdp !== undefined ? Boolean(overrides.antiCdp) : base.antiCdp;
  const allowDevTools =
    overrides.allowDevTools !== undefined ? Boolean(overrides.allowDevTools) : base.allowDevTools;
  let cdpRuntimeWeight = base.cdpRuntimeWeight;
  if (!antiCdp || norm === "off") {
    cdpRuntimeWeight = 0;
  } else if (allowDevTools && (norm === "strict" || norm === "paranoid")) {
    cdpRuntimeWeight = 1;
  } else if (!allowDevTools && norm === "balanced") {
    cdpRuntimeWeight = 4;
  }
  return {
    ...base,
    antiCdp,
    allowDevTools,
    cdpRuntimeWeight,
    bindIp: overrides.bindIp !== undefined ? Boolean(overrides.bindIp) : base.bindIp,
    requireFetchMetadata:
      overrides.requireFetchMetadata !== undefined
        ? Boolean(overrides.requireFetchMetadata)
        : base.requireFetchMetadata,
    blockAiCrawlers:
      overrides.blockAiCrawlers !== undefined ? Boolean(overrides.blockAiCrawlers) : base.blockAiCrawlers,
    autoBlockPage:
      overrides.autoBlockPage !== undefined ? Boolean(overrides.autoBlockPage) : base.autoBlockPage,
    sri: overrides.sri !== undefined ? Boolean(overrides.sri) : base.sri,
  };
}

module.exports = {
  VALID_MODES,
  SECURITY_PRESETS,
  normalizeMode,
  resolvePreset,
};
