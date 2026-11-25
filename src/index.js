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
  sha256Hex,
} = require("./probes.js");
const { buildBrowserGateScript, buildPlaygroundHtml } = require("./browser-sdk.js");
const { createVeilBreakMiddleware, createVeilBreakServer, normalizePathname } = require("./middleware.js");
const { compileNaturalLanguage } = require("./nl.js");

module.exports = {
  FLAG,
  decodeFlags,
  normalizeMode,
  normalizePathname,
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
