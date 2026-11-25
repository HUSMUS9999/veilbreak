import type * as http from "node:http";
import type { NormalizedVeilBreakMode, VeilBreakMode, VeilBreakVerdict } from "./probes.js";

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
  antiCdp?: boolean;
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
  (req: VeilBreakRequest, res: http.ServerResponse, next?: (err?: unknown) => void): Promise<boolean>;
  mode: NormalizedVeilBreakMode;
}

export interface VeilBreakServer {
  server: http.Server;
  mode: NormalizedVeilBreakMode;
  listen(port?: number, host?: string): Promise<string>;
  close(): Promise<void>;
}

export function createVeilBreakMiddleware(options?: VeilBreakMiddlewareOptions): VeilBreakMiddleware;
export function createVeilBreakServer(options?: VeilBreakServerOptions): VeilBreakServer;
export { normalizePathname } from "./probes.js";
