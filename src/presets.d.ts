export type VeilBreakMode = "off" | "monitor" | "observe" | "balanced" | "strict" | "paranoid";
export type NormalizedVeilBreakMode = "off" | "monitor" | "balanced" | "strict" | "paranoid";

export interface VeilBreakPreset {
  readonly mode: NormalizedVeilBreakMode;
  readonly threshold: number;
  readonly ticketPowBits: number;
  readonly bindIp: boolean;
  readonly requireFetchMetadata: boolean;
  readonly blockAiCrawlers: boolean;
  readonly antiCdp: boolean;
  readonly allowDevTools: boolean;
  readonly cdpRuntimeWeight: number;
  readonly autoBlockPage: boolean;
  readonly sri: boolean;
}

export const VALID_MODES: ReadonlySet<VeilBreakMode>;
export const SECURITY_PRESETS: Readonly<Record<NormalizedVeilBreakMode, Readonly<VeilBreakPreset>>>;
export function normalizeMode(mode?: VeilBreakMode | (string & {})): NormalizedVeilBreakMode;
export function resolvePreset(
  mode?: VeilBreakMode | (string & {}),
  overrides?: Partial<Omit<VeilBreakPreset, "mode" | "threshold" | "ticketPowBits" | "cdpRuntimeWeight">>
): VeilBreakPreset;
