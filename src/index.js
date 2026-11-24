"use strict";

const {
  FLAG,
  normalizeMode,
  thresholdForMode,
  evaluateTelemetry,
  evaluateInteraction,
  buildAttestation,
  verifyAttestation,
  sha256Hex,
} = require("./probes.js");
const { buildBrowserGateScript, buildPlaygroundHtml } = require("./browser-sdk.js");
const { createVeilBreakMiddleware, createVeilBreakServer } = require("./middleware.js");
const { compileNaturalLanguage } = require("./nl.js");

module.exports = {
  FLAG,
  normalizeMode,
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
