import assert from "node:assert/strict";
import test from "node:test";
import { summarizeEffectiveScope } from "./ai-scope";

test("summarizes the scope actually attached to an AI run", () => {
  assert.equal(
    summarizeEffectiveScope({
      source: "pcap:test",
      interface: "Wi-Fi",
      session_id: "session-1",
      node_id: "sensor-1",
      target_ips: ["198.51.100.4", "203.0.113.8"],
    }),
    "source pcap:test · interface Wi-Fi · session session-1 · sensor sensor-1 · 2 targets",
  );
});

test("makes unscoped general chat explicit", () => {
  assert.equal(summarizeEffectiveScope(null), "General conversation (no capture scope)");
});
