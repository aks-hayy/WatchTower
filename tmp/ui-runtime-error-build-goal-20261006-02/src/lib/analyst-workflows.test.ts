import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPriorityInvestigationPrompt,
  activeConversationIdFromSearch,
  isRawProviderNarration,
  latestRunIdForConversation,
  parseInvestigationResult,
  persistedRunIdsForConversation,
  selectHighestPriorityEndpoint,
} from "./analyst-workflows";

test("selects the highest-priority endpoint deterministically", () => {
  const selected = selectHighestPriorityEndpoint([
    { ip: "10.0.0.20", priority_score: 42 },
    { ip: "10.0.0.30", priority_score: 91 },
    { ip: "", priority_score: 100 },
    { ip: "10.0.0.40", priority_score: Number.NaN },
  ]);

  assert.equal(selected?.ip, "10.0.0.30");
  assert.equal(selected?.priority_score, 91);
});

test("builds an explicit investigation prompt for the selected endpoint", () => {
  const prompt = buildPriorityInvestigationPrompt({ ip: "10.0.0.30", priority_score: 91 });

  assert.match(prompt, /first use the investigate tool/i);
  assert.match(prompt, /10\.0\.0\.30/);
  assert.match(prompt, /evidence, alerts, flows, confidence, and next actions/i);
  assert.doesNotMatch(prompt, /json response/i);
});

test("returns no endpoint when the current scope has no usable candidates", () => {
  assert.equal(selectHighestPriorityEndpoint([{ ip: "", priority_score: 50 }]), null);
  assert.equal(selectHighestPriorityEndpoint([]), null);
});

test("restores only a non-empty conversation id from route search", () => {
  assert.equal(activeConversationIdFromSearch("conversation-123"), "conversation-123");
  assert.equal(activeConversationIdFromSearch("  conversation-123  "), "conversation-123");
  assert.equal(activeConversationIdFromSearch("  "), undefined);
  assert.equal(activeConversationIdFromSearch(undefined), undefined);
  assert.equal(activeConversationIdFromSearch(123), undefined);
});

test("turns an investigation tool result into an operator summary", () => {
  const summary = parseInvestigationResult([
    {
      tool_name: "investigate",
      result_json: JSON.stringify({
        data: {
          target: "10.0.0.30",
          verdict: "ELEVATED",
          risk_score: 72,
          confidence: 0.8,
          summary: "2 flows and 1 alert support an elevated assessment.",
          findings: ["Periodic beaconing observed"],
          next_actions: ["Review the alert evidence"],
          asset_profile: { role: "External service endpoint" },
          lookup: { activity: { flow_count: 2, alert_count: 1, artifact_count: 0 } },
          correlations: [{ evidence_ref: "alert:1->flow:2" }],
        },
      }),
    },
  ]);

  assert.deepEqual(summary, {
    ip: "10.0.0.30",
    verdict: "ELEVATED",
    risk_score: 72,
    confidence: 0.8,
    role_confidence: null,
    summary: "2 flows and 1 alert support an elevated assessment.",
    role: "External service endpoint",
    flow_count: 2,
    alert_count: 1,
    carved_file_count: 0,
    correlation_count: 1,
    findings: ["Periodic beaconing observed"],
    next_actions: ["Review the alert evidence"],
  });
});

test("keeps investigation confidence separate from endpoint role confidence", () => {
  const summary = parseInvestigationResult([
    {
      tool_name: "investigate",
      result_json: JSON.stringify({
        data: {
          target: "10.0.0.30",
          confidence: 0.43,
          asset_profile: { role: "Client / Workstation", role_confidence: 0.62 },
        },
      }),
    },
  ]);

  assert.equal(summary?.confidence, 0.43);
  assert.equal(summary?.role_confidence, 0.62);
});

test("finds the latest persisted run when reopening a conversation", () => {
  assert.equal(
    latestRunIdForConversation([{ run_id: "run-old" }, { run_id: null }, { run_id: "run-new" }]),
    "run-new",
  );
  assert.equal(latestRunIdForConversation([{ run_id: null }]), null);
});

test("loads each persisted run once for multi-turn conversations", () => {
  assert.deepEqual(
    persistedRunIdsForConversation([
      { run_id: "run-investigation" },
      { run_id: "run-general" },
      { run_id: "run-investigation" },
      { run_id: null },
    ]),
    ["run-investigation", "run-general"],
  );
});

test("recognizes provider narration that should not be shown as the analyst answer", () => {
  assert.equal(
    isRawProviderNarration("This output appears to be a cybersecurity investigation."),
    true,
  );
  assert.equal(isRawProviderNarration("This is a JSON response from an endpoint."), true);
  assert.equal(isRawProviderNarration("This is an API response in JSON format."), true);
  assert.equal(
    isRawProviderNarration("The endpoint is elevated because of repeated flows."),
    false,
  );
});
