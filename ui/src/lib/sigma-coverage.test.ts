import assert from "node:assert/strict";
import test from "node:test";
import { describeSigmaCoverage } from "./sigma-coverage";

test("never describes a zero-compatible-rule hunt as successful coverage", () => {
  assert.deepEqual(describeSigmaCoverage("no_compatible_rules", true), {
    label: "NO RULE COVERAGE",
    state: "no-coverage",
    message: "No compatible Sigma rules were evaluated. This is not a clean result.",
  });
});

test("keeps query truncation separate from missing rule coverage", () => {
  assert.equal(describeSigmaCoverage("covered", false).state, "partial");
  assert.equal(describeSigmaCoverage("covered", true).state, "complete");
});

test("fails closed when a compatible-rule count is absent but no rules are active", () => {
  assert.equal(describeSigmaCoverage(undefined, true, 0).state, "no-coverage");
});
