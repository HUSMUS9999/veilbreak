import type * as http from "node:http";
import type { NormalizedVeilBreakMode, VeilBreakMode, VeilBreakPreset, VeilBreakHandshakeProof, VeilBreakVerdict } from "./probes.js";

export interface VeilBreakRequest extends http.IncomingMessage {
  originalUrl?: string;
  ip?: string;
  veilBreak?: VeilBreakVerdict;
}

export interface VeilBreakMiddlewareOptions {
  mode?: VeilBreakMode;
  basePath?: string;
  protectedPaths?: Array<string | RegExp>;
  ticketTtlMs?: number;
  maxTickets?: number;
  maxTicketsPerMinPerIp?: number;
  ticketPowBits?: number;
  bindIp?: boolean;
  requireFetchMetadata?: boolean;
  blockAiCrawlers?: boolean;
  antiCdp?: boolean;
  allowDevTools?: boolean;
  autoBlockPage?: boolean;
  sri?: boolean;
  unified?: boolean;
  includeTicketPow?: boolean;
  userGestureWindowMs?: number;
  enablePlayground?: boolean;
  exposeDebugHeaders?: boolean;
  trustProxy?: string | string[];
  store?: {
    get(key: string): unknown | Promise<unknown>;
    set(key: string, value: unknown, ttlMs?: number): unknown | Promise<unknown>;
  } & (
    | { take(key: string): unknown | Promise<unknown>; delete?(key: string): unknown | Promise<unknown>; del?(key: string): unknown | Promise<unknown> }
    | { delete(key: string): unknown | Promise<unknown>; take?(key: string): unknown | Promise<unknown>; del?(key: string): unknown | Promise<unknown> }
    | { del(key: string): unknown | Promise<unknown>; take?(key: string): unknown | Promise<unknown>; delete?(key: string): unknown | Promise<unknown> }
  );
  onDetect?: (event: VeilBreakVerdict & { path: string; method: string }) => void;
}

export interface VeilBreakServerOptions extends VeilBreakMiddlewareOptions {
  target?: string;
  injectGate?: boolean;
  sriOnPublicCache?: boolean;
  maxHtmlBytes?: number;
  upstreamTimeoutMs?: number;
}

export interface VeilBreakMiddleware {
  (req: VeilBreakRequest, res: http.ServerResponse, next?: (err?: unknown) => void): Promise<boolean>;
  mode: NormalizedVeilBreakMode;
  basePath: string;
  gateSri: string;
  gateVersion: string;
  gateJs: string;
  preset: VeilBreakPreset;
  verifyHandshakeProof(opts?: {
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
}

export interface VeilBreakServer {
  server: http.Server;
  mode: NormalizedVeilBreakMode;
  listen(port?: number, host?: string): Promise<string>;
  close(): Promise<void>;
}

export function createVeilBreakMiddleware(options?: VeilBreakMiddlewareOptions): VeilBreakMiddleware;
export function createVeilBreakServer(options?: VeilBreakServerOptions): VeilBreakServer;
export function injectGateIntoHtml(
  html: string,
  basePath: string,
  mode: string,
  autoBlockPage?: boolean,
  antiCdp?: boolean,
  opts?: { sri?: string; version?: string; unified?: boolean; allowDevTools?: boolean; bridgeToken?: string }
): string;
export { normalizePathname } from "./probes.js";
