import type * as http from "node:http";

export type VeilBreakMode = "off" | "monitor" | "observe" | "balanced" | "strict";
export type NormalizedVeilBreakMode = "off" | "monitor" | "balanced" | "strict";

export const FLAG: Readonly<Record<string, number>>;

export interface VeilBreakVerdict {
  ok: boolean;
  blocked: boolean;
  score: number;
  threshold: number;
  mode: NormalizedVeilBreakMode;
  reasons: string[];
  flags?: number;
  platform?: string;
}

export interface VeilBreakAttestation {
  v: 2;
  s: number;
  f: number;
  p: string;
  d: string;
  r?: string[];
  blocked?: boolean;
}

export interface VeilBreakMiddlewareOptions {
  mode?: VeilBreakMode;
  basePath?: string;
  protectedPaths?: Array<string | RegExp>;
  ticketTtlMs?: number;
  maxTickets?: number;
  maxTicketsPerMinPerIp?: number;
  autoBlockPage?: boolean;
  enablePlayground?: boolean;
  exposeDebugHeaders?: boolean;
  trustProxy?: string | string[];
  onDetect?: (event: VeilBreakVerdict & { path: string; method: string }) => void;
}

export interface VeilBreakServerOptions extends VeilBreakMiddlewareOptions {
  target?: string;
  injectGate?: boolean;
  maxHtmlBytes?: number;
  upstreamTimeoutMs?: number;
}

export interface VeilBreakMiddleware {
  (req: http.IncomingMessage, res: http.ServerResponse, next?: (err?: unknown) => void): Promise<boolean>;
  mode: NormalizedVeilBreakMode;
}

export interface VeilBreakServer {
  server: http.Server;
  mode: NormalizedVeilBreakMode;
  listen(port?: number, host?: string): Promise<string>;
  close(): Promise<void>;
}

export function decodeFlags(flags: number): string[];
export function normalizeMode(mode?: string): NormalizedVeilBreakMode;
export function normalizePathname(rawUrl: string): string;
export function thresholdForMode(mode?: string): number;
export function sha256Hex(input: Buffer | string): string;
export function evaluateTelemetry(telemetry?: Record<string, unknown>, opts?: { mode?: VeilBreakMode; antiCdp?: boolean }): VeilBreakVerdict;
export function evaluateInteraction(interaction?: Record<string, unknown>, opts?: { mode?: VeilBreakMode }): VeilBreakVerdict;
export function buildAttestation(opts?: { mode?: VeilBreakMode; ticket?: string; nonce?: string; telemetry?: Record<string, unknown>; antiCdp?: boolean }): VeilBreakAttestation | null;
export function verifyAttestation(opts?: { mode?: VeilBreakMode; headers?: Record<string, string | string[] | undefined>; attest?: VeilBreakAttestation | string | null; ticket?: string; nonce?: string }): VeilBreakVerdict;
export function buildBrowserGateScript(opts?: { basePath?: string; defaultMode?: VeilBreakMode; protectedRules?: Array<string | { regex: string; flags: string }>; autoBlockPage?: boolean }): string;
export function buildPlaygroundHtml(opts?: { basePath?: string; mode?: VeilBreakMode }): string;
export function createVeilBreakMiddleware(options?: VeilBreakMiddlewareOptions): VeilBreakMiddleware;
export function createVeilBreakServer(options?: VeilBreakServerOptions): VeilBreakServer;
export function compileNaturalLanguage(prompt: string): { intent: string; options: Record<string, unknown>; summary: string };
