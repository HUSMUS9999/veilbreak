import type { NormalizedVeilBreakMode } from "./probes.js";

export type VeilBreakNaturalLanguagePlan =
  | {
      input: string;
      intent: "snippet";
      goal: string;
      options: { mode: NormalizedVeilBreakMode };
      command: string;
      reasons: string[];
    }
  | {
      input: string;
      intent: "demo";
      goal: string;
      options: { port: number; mode: NormalizedVeilBreakMode };
      command: string;
      reasons: string[];
    }
  | {
      input: string;
      intent: "protect";
      goal: string;
      options: {
        target: string;
        port: number;
        mode: NormalizedVeilBreakMode;
        protectedPaths: string[];
        trustProxy: string;
      };
      command: string;
      reasons: string[];
    };

export function compileNaturalLanguage(prompt: string): VeilBreakNaturalLanguagePlan;
