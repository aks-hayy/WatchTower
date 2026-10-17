import assert from "node:assert/strict";
import test from "node:test";
import { providerProbeSummary, toolSupportLabel } from "./provider-capability";

test("tool support distinguishes supported, unsupported, and untested models", () => {
  assert.equal(toolSupportLabel(true), "Yes");
  assert.equal(toolSupportLabel(false), "No");
  assert.equal(toolSupportLabel(null), "Not tested");
  assert.equal(toolSupportLabel(undefined), "Not tested");
});

test("provider probe summary distinguishes chat readiness from tool readiness", () => {
  const summary = providerProbeSummary("ollama", {
    model: "qwen2.5-coder:latest",
    available: true,
    model_catalog_available: true,
    selected_model_available: false,
    agentic_ready: false,
    capability: {
      chat_ready: true,
      detail: "model responded without a native tool call",
    },
  });
  assert.match(summary, /model catalog available/);
  assert.match(summary, /selected model is not installed/);
  assert.match(summary, /qwen2\.5-coder:latest/);
  assert.match(summary, /chat ready/);
  assert.match(summary, /agentic tools not ready/);
  assert.match(summary, /model responded without a native tool call/);
});

test("unavailable Ollama status includes a concrete recovery step", () => {
  const summary = providerProbeSummary("ollama", {
    available: false,
    detail: "connection refused",
  });

  assert.equal(
    summary,
    "Ollama is unavailable: connection refused. Start Ollama, then test again.",
  );
});

test("missing Ollama model status directs users to model settings", () => {
  const summary = providerProbeSummary("ollama", {
    available: false,
    detail: "configured model 'llama3.2' is not installed",
  });

  assert.equal(
    summary,
    "Ollama is unavailable: configured model 'llama3.2' is not installed. Choose or install a model in Settings, then test again.",
  );
});

test("unconfigured hosted providers direct credential setup to Settings", () => {
  const summary = providerProbeSummary("OpenAI", {
    available: false,
    detail: "not configured",
    requires_credential: true,
    credential_configured: false,
  });

  assert.equal(
    summary,
    "OpenAI credentials are not configured. Add them in Settings, then test again.",
  );
});
