import assert from "node:assert/strict";
import test from "node:test";
import { pluginStatusPresentation } from "./plugin-coverage";

test("shows a disabled compatibility detector as replaced, not ready", () => {
  const presentation = pluginStatusPresentation(
    { enabled: false, valid: true },
    {
      state: "disabled_by_policy",
      reason: "This compatibility plugin is disabled and replaced by watchtower.stateful.host.",
      next_action:
        "Use active replacement watchtower.stateful.host; do not enable this legacy plugin.",
    },
  );

  assert.equal(presentation.label, "Disabled by policy");
  assert.match(presentation.detail || "", /replaced by watchtower\.stateful\.host/);
  assert.match(presentation.nextAction || "", /do not enable/i);
  assert.notEqual(presentation.label, "Ready");
});

test("preserves a valid-but-enabled plugin as ready", () => {
  assert.deepEqual(pluginStatusPresentation({ enabled: true, valid: true }, { state: "ready" }), {
    label: "Ready",
    detail: "",
    nextAction: "",
  });
});
