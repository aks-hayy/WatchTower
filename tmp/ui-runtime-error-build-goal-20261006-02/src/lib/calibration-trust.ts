export type CalibrationTrustBasis =
  | "bootstrap_corpus"
  | "field_evidence"
  | "corpus"
  | "uncalibrated"
  | "unknown";

export function calibrationTrustPresentation(
  basis: CalibrationTrustBasis | undefined,
  level: string,
): { label: string; detail: string } {
  if (basis === "bootstrap_corpus") {
    return {
      label: "Bootstrap corpus",
      detail: "Release bootstrap corpus passed; this is not 30 host-days of field evidence.",
    };
  }
  if (basis === "field_evidence") return { label: "Field evidence", detail: "" };
  if (basis === "corpus") return { label: "Corpus validated", detail: "" };
  if (basis === "uncalibrated") return { label: "Uncalibrated", detail: "" };
  if (level === "FIELD_CALIBRATED") {
    return { label: "Evidence basis unknown", detail: "Attestation basis is missing or invalid." };
  }
  return { label: level.replaceAll("_", " ").toLowerCase(), detail: "" };
}
