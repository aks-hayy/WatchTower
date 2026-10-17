import assert from "node:assert/strict";
import test from "node:test";
import { describeUiRuntimeError } from "./ui-runtime-error";

test("explains that a missing lazy route bundle requires restarting the UI", () => {
  const presentation = describeUiRuntimeError(
    new Error(
      "Failed to fetch dynamically imported module: http://127.0.0.1:43000/assets/capture-old.js",
    ),
  );

  assert.equal(presentation.kind, "stale_ui_bundle");
  assert.equal(presentation.title, "Restart WatchTower UI");
  assert.match(presentation.message, /restart the WatchTower UI/i);
  assert.match(presentation.message, /reload this page/i);
  assert.match(presentation.actionLabel, /reload after restart/i);
  assert.equal(presentation.showTechnicalDetails, false);
});

test("recognizes browser variants of lazy-module loading failures", () => {
  for (const message of [
    "Importing a module script failed.",
    "error loading dynamically imported module",
    "ChunkLoadError: Loading chunk 17 failed",
  ]) {
    assert.equal(describeUiRuntimeError(new Error(message)).kind, "stale_ui_bundle", message);
  }
});

test("keeps actionable generic recovery for unrelated route errors", () => {
  const presentation = describeUiRuntimeError(new Error("The request timed out"));

  assert.equal(presentation.kind, "request_error");
  assert.equal(presentation.title, "Something went wrong");
  assert.equal(presentation.actionLabel, "Try again");
  assert.equal(presentation.showTechnicalDetails, true);
});
