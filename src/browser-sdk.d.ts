import type { VeilBreakMode } from "./probes.js";

export interface BuildBrowserGateOptions {
  basePath?: string;
  defaultMode?: VeilBreakMode;
  protectedPaths?: Array<string | RegExp | { regex: string; flags: string }>;
  protectedRules?: Array<string | RegExp | { regex: string; flags: string }> | null;
  autoBlockPage?: boolean;
  antiCdp?: boolean;
  allowDevTools?: boolean;
  unified?: boolean;
  embedded?: boolean;
  includeTicketPow?: boolean;
  sri?: boolean;
  userGestureWindowMs?: number;
  allowBlockPageOverridePath?: string;
}

export interface BuildPlaygroundOptions {
  basePath?: string;
  mode?: VeilBreakMode;
  antiCdp?: boolean;
}

export function buildBrowserGateScript(options?: BuildBrowserGateOptions): string;
export function buildPlaygroundHtml(options?: BuildPlaygroundOptions): string;
