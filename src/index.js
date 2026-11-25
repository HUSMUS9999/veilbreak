"use strict";

const {
  FLAG,
  decodeFlags,
  normalizeMode,
  thresholdForMode,
  evaluateTelemetry,
  evaluateInteraction,
  buildAttestation,
  verifyAttestation,
  isAutomationOrCliUa,
  verifyPowSolution,
  solvePowChallenge,
  normalizePathname,
  stripSchemeAndAuthority,
  expandPathCandidates,
  isProtectedPath,
  sha256Hex,
} = require("./probes.js");
const { buildBrowserGateScript, buildPlaygroundHtml } = require("./browser-sdk.js");
const { createVeilBreakMiddleware, createVeilBreakServer } = require("./middleware.js");
const { compileNaturalLanguage } = require("./nl.js");

module.exports = {
  FLAG,
  decodeFlags,
  normalizeMode,
  normalizePathname,
  stripSchemeAndAuthority,
  expandPathCandidates,
  isProtectedPath,
  isAutomationOrCliUa,
  verifyPowSolution,
  solvePowChallenge,
  thresholdForMode,
  evaluateTelemetry,
  evaluateInteraction,
  buildAttestation,
  verifyAttestation,
  buildBrowserGateScript,
  buildPlaygroundHtml,
  createVeilBreakMiddleware,
  createVeilBreakServer,
  compileNaturalLanguage,
  sha256Hex,
};
