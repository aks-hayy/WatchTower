import assert from "node:assert/strict";
import test from "node:test";
import { captureControlDisabled } from "./capture-control.ts";

test("an explicit capture start remains available while the local daemon is offline", () => {
  assert.equal(
    captureControlDisabled({
      busy: false,
      capturing: false,
      interfaceUp: true,
      backendAvailable: true,
    }),
    false,
  );
});

test("active capture can always be stopped even if its interface is now down", () => {
  assert.equal(
    captureControlDisabled({
      busy: false,
      capturing: true,
      interfaceUp: false,
      backendAvailable: false,
    }),
    false,
  );
});

test("capture start still requires an idle, usable interface and an available backend", () => {
  assert.equal(
    captureControlDisabled({
      busy: false,
      capturing: false,
      interfaceUp: false,
      backendAvailable: true,
    }),
    true,
  );
  assert.equal(
    captureControlDisabled({
      busy: false,
      capturing: false,
      interfaceUp: true,
      backendAvailable: false,
    }),
    true,
  );
});
