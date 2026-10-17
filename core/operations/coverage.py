"""Capability coverage contract shared by the API, CLI, and UI.

Inventory is useful only when an operator can tell the difference between a
feature that is usable, intentionally disabled, not supported by the current
runtime, or broken. This module keeps that vocabulary in one place.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping


STATES = {
    "ready",
    "disabled_by_policy",
    "unsupported_telemetry",
    "unavailable_dependency",
    "invalid_plugin",
}

# Retired compatibility detectors remain visible in inventory for explanation,
# but their duplicate signals are owned by the unified stateful detector.
REPLACEMENTS = {
    "watchtower.recon": "watchtower.stateful.host",
    "watchtower.behavior.beacon": "watchtower.stateful.host",
    "watchtower.exfiltration": "watchtower.stateful.host",
}


def _capability(capabilities: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = capabilities.get(name) or {}
    return value if isinstance(value, Mapping) else {}


def build_coverage_matrix(
    plugins: Iterable[Mapping[str, Any]],
    capabilities: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a stable, operator-readable matrix for plugin coverage.

    ``required_capability`` is optional so existing plugin manifests remain
    compatible. A disabled detector is never presented as ready, and a
    missing dependency is never disguised as an empty-result hunt.
    """
    capabilities = capabilities or {}
    items: list[dict[str, Any]] = []
    for plugin in plugins:
        name = str(plugin.get("name") or plugin.get("detector_id") or "unknown plugin")
        item_id = str(plugin.get("detector_id") or name)
        plugin_type = str(plugin.get("type") or "plugin")
        enabled = bool(plugin.get("enabled", True))
        valid = bool(plugin.get("valid", True))
        required = str(plugin.get("required_capability") or "")
        replacement = str(plugin.get("replaced_by") or REPLACEMENTS.get(item_id, ""))
        dependency = _capability(capabilities, required) if required else {}

        if not valid:
            state = "invalid_plugin"
            reason = str(plugin.get("last_error") or "The plugin failed its contract validation.")
            next_action = "Review the plugin validation error before using this capability."
        elif not enabled:
            state = "disabled_by_policy"
            if replacement:
                reason = f"This compatibility plugin is disabled and replaced by {replacement}."
                next_action = f"Use active replacement {replacement}; do not enable this legacy plugin."
            else:
                reason = "The plugin is disabled by policy and does not produce findings."
                next_action = "Review its policy and calibration evidence before enabling it."
        elif required and not bool(dependency.get("available")):
            state = "unavailable_dependency"
            reason = str(dependency.get("reason") or f"Required capability {required} is unavailable.")
            next_action = str(dependency.get("next_action") or "Restore the dependency and rerun diagnostics.")
        else:
            state = "ready"
            reason = "Loaded and available for its supported telemetry."
            next_action = ""

        if state not in STATES:
            raise ValueError(f"unknown coverage state: {state}")
        item = {
            "id": item_id,
            "name": name,
            "type": plugin_type,
            "state": state,
            "reason": reason,
            "next_action": next_action,
            "enabled": enabled,
            "valid": valid,
            "supported_link_types": list(plugin.get("supported_link_types") or []),
            "input_kinds": list(plugin.get("input_kinds") or []),
            "detector_id": str(plugin.get("detector_id") or ""),
            "replacement": replacement,
            "calibration_level": str(plugin.get("calibration_level") or "NOT_APPLICABLE"),
            "limitations": [],
        }
        if plugin_type == "detector" and item["calibration_level"] not in {"FIELD_CALIBRATED", "NOT_APPLICABLE"}:
            item["limitations"].append("Detector trust is bounded by its current calibration level.")
        items.append(item)

    items.sort(key=lambda item: (item["type"], item["name"].casefold()))
    counts = Counter(item["state"] for item in items)
    return {
        "schema_version": "coverage.v1",
        "items": items,
        "summary": {state: int(counts.get(state, 0)) for state in sorted(STATES)},
        "limitations": [
            "Coverage describes configured capability availability; it does not prove that a capture contains the required telemetry.",
        ],
    }
