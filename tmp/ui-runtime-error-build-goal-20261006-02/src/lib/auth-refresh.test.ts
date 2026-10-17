import assert from "node:assert/strict";
import test from "node:test";
import { applyAuthStatusRefresh } from "./auth-refresh";

test("a successful status refresh clears stale connection errors", () => {
  const next = applyAuthStatusRefresh(
    { status: null, connectionError: "Failed to fetch" },
    { ok: true, status: { state: "setup_required" } },
  );

  assert.equal(next.status?.state, "setup_required");
  assert.equal(next.connectionError, "");
});

test("a failed status refresh preserves the last known status", () => {
  const previous = { state: "locked" };
  const next = applyAuthStatusRefresh(
    { status: previous, connectionError: "" },
    { ok: false, cause: new Error("Failed to fetch") },
  );

  assert.equal(next.status, previous);
  assert.equal(next.connectionError, "Failed to fetch");
});
