import type { NormalizedVeilBreakMode, VeilBreakMode, VeilBreakPreset } from "./presets.js";
export type { NormalizedVeilBreakMode, VeilBreakMode, VeilBreakPreset } from "./presets.js";

export interface VeilBreakFlags {
  readonly CANVAS2D_NOISE: number;
  readonly WEBGL_CLEAR_NOISE: number;
  readonly SILENT_AUDIO_NOISE: number;
  readonly DOMRECT_POISONING: number;
  readonly OS_CORE_FONT_LIE: number;
  readonly WEBGL_HARDWARE_LIE: number;
  readonly WEBDRIVER_FLAG: number;
  readonly CDP_RUNTIME_ENABLE: number;
  readonly AUTOMATION_GLOBAL: number;
  readonly WEBDRIVER_GETTER_SPOOF: number;
  readonly NATIVE_FN_TAMPERED: number;
  readonly WORKER_CONTRADICTION: number;
  readonly VIEWPORT_IMPOSSIBILITY: number;
  readonly ENGINE_COHERENCE_LIE: number;
  readonly SYNTHETIC_INTERACTION: number;
  readonly CDP_SOFT_RENDERER: number;
}

export const PROXY_LEAK_HEADERS: readonly string[];
export const FLAG: Readonly<VeilBreakFlags>;

export interface VeilBreakInteraction {
  isTrusted?: boolean;
  detail?: number;
  pointerType?: string;
  pointerMoves?: number;
  zeroMoveCount?: number;
  dwellMs?: number;
  hitExactCenter?: boolean;
}

export interface VeilBreakTelemetry {
  webdriver?: boolean;
  freshIframeWebdriver?: boolean;
  automationGlobalArtifact?: boolean;
  cdpRuntimeEnable?: boolean;
  softwareWebglHeadless?: boolean;
  webdriverGetterSpoofed?: boolean;
  nativeFunctionTampered?: boolean;
  workerRealmContradiction?: boolean;
  canvas2dUniqueColors?: number;
  canvas2dRepeatDiff?: number;
  offscreenCanvasUniqueColors?: number;
  webglClearUniqueColors?: number;
  webglHardwareLie?: boolean;
  webglRenderer?: string;
  silentAudioNonZeroSamples?: number;
  domRectSubpixelDrift?: boolean;
  domRectDelta?: number;
  osFontLie?: boolean;
  viewportGeometryImpossibility?: boolean;
  engineCoherenceLie?: boolean;
  platform?: string;
  interaction?: VeilBreakInteraction;
}

export interface VeilBreakVerdict {
  ok: boolean;
  blocked: boolean;
  score: number;
  threshold: number;
  mode: NormalizedVeilBreakMode;
  reasons: string[];
  flags?: number;
  platform?: string;
  cdpActive?: boolean;
}

export interface VeilBreakAttestation {
  v: 2;
  s: number;
  f: number;
  p: string;
  d: string;
  w?: string;
  m?: string;
  u?: string;
  r?: string[];
  blocked?: boolean;
}

export interface VeilBreakHandshakeProof {
  v: 3;
  ch: string;
  s: number;
  f: number;
  p: string;
  cdp: 0 | 1;
  wr: string;
  wk: 0 | 1;
  ms: number;
  d: string;
}

export function decodeFlags(flags: number): string[];
export { normalizeMode, resolvePreset } from "./presets.js";
export function thresholdForMode(mode?: VeilBreakMode | (string & {})): number;
export function sha256Hex(input: Buffer | ArrayBufferView | string): string;
export function isAutomationOrCliUa(headers?: Record<string, string | string[] | undefined>): boolean;
export function isAiCrawlerRequest(headers?: Record<string, string | string[] | undefined>): boolean;
export function verifyPowSolution(ticket: string, challenge: string, powNonce: string, difficulty: number): boolean;
export function solvePowChallenge(ticket: string, challenge: string, difficulty: number): string;
export function normalizePathname(rawUrl: string): string;
export function stripSchemeAndAuthority(rawUrl: string): string;
export function expandPathCandidates(rawUrl: string): string[];
export function normalizeProtectedPaths(protectedPaths?: Array<string | RegExp>): Array<string | RegExp>;
export function isProtectedPath(rawUrl: string, protectedPaths?: Array<string | RegExp>, preNormalized?: boolean): boolean;
export function evaluateTelemetry(
  telemetry?: VeilBreakTelemetry,
  opts?: { mode?: VeilBreakMode; antiCdp?: boolean; allowDevTools?: boolean }
): VeilBreakVerdict;
export function evaluateInteraction(interaction?: VeilBreakInteraction, opts?: { mode?: VeilBreakMode }): VeilBreakVerdict;
export function buildAttestation(opts?: {
  mode?: VeilBreakMode;
  ticket?: string;
  nonce?: string;
  telemetry?: VeilBreakTelemetry;
  antiCdp?: boolean;
  allowDevTools?: boolean;
  challenge?: string;
  difficulty?: number;
  powNonce?: string | null;
  method?: string;
  path?: string;
}): VeilBreakAttestation | null;
export function verifyAttestation(opts?: {
  mode?: VeilBreakMode;
  headers?: Record<string, string | string[] | undefined>;
  attest?: VeilBreakAttestation | string | null;
  ticket?: string;
  nonce?: string;
  expectedChallenge?: string;
  expectedDifficulty?: number;
  expectedMethod?: string;
  expectedPath?: string;
  requireFetchMetadata?: boolean;
  blockAiCrawlers?: boolean;
  antiCdp?: boolean;
  allowDevTools?: boolean;
}): VeilBreakVerdict;
export function buildHandshakeProof(opts?: {
  mode?: VeilBreakMode;
  challenge?: string;
  telemetry?: VeilBreakTelemetry;
  antiCdp?: boolean;
  allowDevTools?: boolean;
  workerOk?: boolean;
  probeMs?: number;
}): VeilBreakHandshakeProof | null;
export function verifyHandshakeProof(opts?: {
  mode?: VeilBreakMode;
  headers?: Record<string, string | string[] | undefined>;
  proof?: VeilBreakHandshakeProof | unknown;
  expectedChallenge?: string;
  requireFetchMetadata?: boolean;
  blockAiCrawlers?: boolean;
  antiCdp?: boolean;
  allowDevTools?: boolean;
  skipHeaderChecks?: boolean;
}): VeilBreakVerdict;
