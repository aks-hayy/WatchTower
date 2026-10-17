export type SigmaCoverageState = "no-coverage" | "partial" | "complete";

export function describeSigmaCoverage(
  coverageStatus: string | undefined,
  complete: boolean | undefined,
  activeRules?: number,
): { label: string; state: SigmaCoverageState; message: string } {
  if (coverageStatus === "no_compatible_rules" || activeRules === 0) {
    return {
      label: "NO RULE COVERAGE",
      state: "no-coverage",
      message: "No compatible Sigma rules were evaluated. This is not a clean result.",
    };
  }
  if (complete === false) {
    return {
      label: "PARTIAL HUNT",
      state: "partial",
      message: "Results may be incomplete because an evaluation limit was reached.",
    };
  }
  return {
    label: "HUNT COMPLETE",
    state: "complete",
    message: "The available compatible rules completed evaluation for this scope.",
  };
}
