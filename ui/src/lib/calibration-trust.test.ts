import assert from "node:assert/strict";
import test from "node:test";
import { calibrationTrustPresentation } from "./calibration-trust";

test("bootstrap qualification is never labeled as field evidence", () => {
  const result = calibrationTrustPresentation("bootstrap_corpus", "FIELD_CALIBRATED");
  assert.equal(result.label, "Bootstrap corpus");
  assert.match(result.detail, /not 30 host-days of field evidence/i);
});

test("actual field evidence retains its distinct label", () => {
  assert.equal(
    calibrationTrustPresentation("field_evidence", "FIELD_CALIBRATED").label,
    "Field evidence",
  );
});

test("unknown attestation basis is not described as trusted field data", () => {
  assert.equal(
    calibrationTrustPresentation("unknown", "FIELD_CALIBRATED").label,
    "Evidence basis unknown",
  );
});
