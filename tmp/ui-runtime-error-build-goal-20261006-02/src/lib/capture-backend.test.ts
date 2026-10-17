import assert from "node:assert/strict";
import test from "node:test";

import { captureStartBackend, selectCaptureBackend } from "./capture-backend.ts";

test("idle network devices prefer supported rust and fall back to a supported backend", () => {
  assert.equal(
    selectCaptureBackend({
      source_type: "network",
      backends: ["python", "rust"],
      capturing: false,
    }),
    "rust",
  );
  assert.equal(
    selectCaptureBackend({
      source_type: "network",
      backends: ["python"],
      capturing: false,
    }),
    "python",
  );
  assert.equal(
    selectCaptureBackend({ source_type: "network", backends: [], capturing: false }),
    null,
  );
});

test("bluetooth defaults to python and an active engine always wins", () => {
  assert.equal(
    selectCaptureBackend({
      source_type: "bluetooth",
      backends: ["python"],
      capturing: false,
    }),
    "python",
  );
  assert.equal(
    selectCaptureBackend({
      source_type: "network",
      backends: ["python", "rust"],
      capturing: true,
      engine: { backend: "python" },
    }),
    "python",
  );
});

test("untouched capture and settings choices omit backend while explicit choices remain explicit", () => {
  const network = {
    source_type: "network",
    backends: ["python", "rust"],
    capturing: false,
  };
  const bluetooth = {
    source_type: "bluetooth",
    backends: ["python"],
    capturing: false,
  };

  assert.equal(captureStartBackend(network), undefined);
  assert.equal(captureStartBackend(bluetooth), undefined);
  assert.equal(captureStartBackend(network, "python"), "python");
  assert.equal(captureStartBackend(network, "rust"), "rust");
  assert.equal(captureStartBackend(bluetooth, "rust"), null);
});
