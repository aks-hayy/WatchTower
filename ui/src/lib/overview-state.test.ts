import assert from "node:assert/strict";
import test from "node:test";
import { resolveOverviewEvidenceState, resolveOverviewPosture } from "./overview-state";

const emptyData = () => ({
  health: { capture_state: "idle" as "idle" | "starting" | "active" },
  stats: { total_packets: 0, total_flows: 0, active_hosts: 0 },
  interfaces: [{ capturing: false }],
  timeline: [] as Array<{ packets_per_sec: number; bytes_per_sec: number; flows: number }>,
  protocols: [] as unknown[],
  ports: [] as unknown[],
  alerts: [] as unknown[],
  entities: [] as unknown[],
  topology: { nodes: [] as unknown[], edges: [] as unknown[] },
});

test("does not call an empty dashboard nominal when no capture evidence exists", () => {
  const state = resolveOverviewEvidenceState(emptyData());
  assert.equal(state, "no-data");
  assert.equal(resolveOverviewPosture(state, 0, 0).level, "NO DATA");
});

test("does not label observed traffic nominal when no endpoints have been scored", () => {
  assert.equal(resolveOverviewPosture("history", 0, 0).level, "UNASSESSED");
});

test("keeps risk posture based on entity priority when scored endpoints exist", () => {
  assert.equal(resolveOverviewPosture("history", 1, 85).level, "ELEVATED");
});

test("distinguishes an active capture that has not produced observations", () => {
  const data = emptyData();
  data.health.capture_state = "active";
  data.interfaces[0].capturing = true;

  assert.equal(resolveOverviewEvidenceState(data), "collecting");
});

test("distinguishes capture startup before the first observations", () => {
  const data = emptyData();
  data.health.capture_state = "starting";

  assert.equal(resolveOverviewEvidenceState(data), "starting");
});

test("preserves the stored-history state when capture is stopped but evidence remains", () => {
  const data = emptyData();
  data.stats.total_packets = 12;
  data.stats.total_flows = 2;

  assert.equal(resolveOverviewEvidenceState(data), "history");
});

test("does not hide available evidence just because capture is active", () => {
  const data = emptyData();
  data.health.capture_state = "active";
  data.interfaces[0].capturing = true;
  data.alerts.push({});

  assert.equal(resolveOverviewEvidenceState(data), "monitoring");
});
