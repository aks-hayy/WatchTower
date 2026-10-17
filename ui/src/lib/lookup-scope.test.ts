import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { LookupIntelPanel } from "../components/LookupIntelPanel";
import type { IpLookup } from "../types/watchtower";

function lookup(scope_limitations?: string[]): IpLookup {
  return {
    ip: "10.0.0.4",
    source: "live",
    generated_at: 1,
    scope: "private",
    subnet: "10.0.0.0/24",
    ip_version: 4,
    is_private: true,
    is_global: false,
    summary: "Passive profile",
    identity: {},
    enrichment: { scope: "private", ip_version: 4, observed_name_count: 0, source: "none" },
    asset_profile: {},
    activity: {
      flow_count: 0,
      alert_count: 0,
      artifact_count: 0,
      total_packets: 0,
      total_bytes: 0,
      outbound_bytes: 0,
      inbound_bytes: 0,
      protocols: [],
    },
    services: [],
    peers: { internal: [], external: [] },
    observed_names: [],
    location: { label: "Local network", latitude: 0, longitude: 0 },
    gaps: [],
    next_actions: [],
    scope_limitations,
  };
}

test("IP intelligence renders scope limitations when evidence was excluded", () => {
  const markup = renderToStaticMarkup(
    createElement(LookupIntelPanel, {
      lookup: lookup(["Global identity was excluded.", "Unattributed artifacts were excluded."]),
    }),
  );

  assert.match(markup, /Evidence scope limits/);
  assert.match(markup, /Global identity was excluded\./);
  assert.match(markup, /Unattributed artifacts were excluded\./);
});

test("IP intelligence omits the scope warning when there are no scope limitations", () => {
  const markup = renderToStaticMarkup(createElement(LookupIntelPanel, { lookup: lookup([]) }));

  assert.doesNotMatch(markup, /Evidence scope limits/);
});
