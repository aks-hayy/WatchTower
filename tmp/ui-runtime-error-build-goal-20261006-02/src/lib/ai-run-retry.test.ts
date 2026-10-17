import assert from "node:assert/strict";
import test from "node:test";

test("offers retry only for an interrupted run with a read-only origin", async () => {
  const retryModule = await import("./ai-run-retry").catch(() => null);
  assert.ok(retryModule, "interrupted-run retry eligibility is implemented");

  const run = {
    status: "INTERRUPTED",
    mode: "investigate",
    policy: { read_only: true },
  };
  assert.equal(retryModule.canRetryInterruptedAIRun(run, true), true);
  assert.equal(retryModule.canRetryInterruptedAIRun(run, false), false);
  assert.equal(
    retryModule.canRetryInterruptedAIRun(
      { ...run, mode: "action", policy: { read_only: false } },
      true,
    ),
    false,
  );
  assert.equal(retryModule.canRetryInterruptedAIRun({ ...run, status: "FAILED" }, true), false);
});
