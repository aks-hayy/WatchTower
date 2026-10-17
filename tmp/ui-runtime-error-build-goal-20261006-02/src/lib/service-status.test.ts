import assert from "node:assert/strict";
import test from "node:test";
import { describeServiceStatus, resolveWorkspaceServiceState } from "./service-status";
import type { HealthStatus } from "@/types/watchtower";

const healthy: HealthStatus = {
  status: "ok",
  version: "test",
  database: "ok",
  daemon: "online",
  daemon_healthy: true,
  capture_state: "idle",
};

test("does not report ready before health is known", () => {
  assert.equal(resolveWorkspaceServiceState(null), "checking");
});

test("reports offline and degraded states consistently", () => {
  assert.equal(resolveWorkspaceServiceState({ ...healthy, status: "offline" }), "offline");
  assert.equal(resolveWorkspaceServiceState({ ...healthy, status: "degraded" }), "attention");
  assert.equal(resolveWorkspaceServiceState({ ...healthy, capture_state: "failed" }), "attention");
});

test("distinguishes a reachable controller from its stopped native sensor", () => {
  const status = describeServiceStatus({
    ...healthy,
    status: "offline",
    database: "ok",
    daemon: "offline",
    daemon_healthy: false,
    deployment_role: "native",
    capture_state: "unavailable",
  });

  assert.equal(status.state, "attention");
  assert.equal(status.label, "Sensor stopped");
  assert.equal(
    status.bannerText,
    "CONTROLLER AVAILABLE · SENSOR STOPPED · database ok, daemon offline",
  );
});

test("reports ready only for healthy service state", () => {
  assert.equal(resolveWorkspaceServiceState(healthy), "ready");
});

test("describes controller readiness separately from native capture availability", () => {
  const status = describeServiceStatus({
    ...healthy,
    daemon: "not_applicable",
    daemon_healthy: false,
    capture_state: "unavailable",
    deployment_role: "controller",
    next_action: "Review native sensors to begin live monitoring.",
  });

  assert.equal(status.state, "ready");
  assert.equal(status.label, "Controller ready");
  assert.equal(status.sourceLabel, "Controller");
  assert.equal(status.nativeDaemonApplicable, false);
  assert.equal(status.nextAction, "Review native sensors to begin live monitoring.");
});
