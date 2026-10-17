from core.operations.coverage import build_coverage_matrix


def test_coverage_matrix_distinguishes_disabled_invalid_and_ready_plugins():
    result = build_coverage_matrix([
        {
            "name": "Beaconing Detector",
            "type": "detector",
            "detector_id": "watchtower.behavior.beacon",
            "enabled": False,
            "valid": True,
            "supported_link_types": ["ethernet"],
            "calibration_level": "UNCALIBRATED",
        },
        {
            "name": "Broken Detector",
            "type": "detector",
            "detector_id": "watchtower.broken",
            "enabled": True,
            "valid": False,
            "last_error": "manifest rejected",
            "supported_link_types": ["ethernet"],
        },
        {
            "name": "HTTP Parser",
            "type": "parser",
            "enabled": True,
            "valid": True,
            "supported_link_types": ["ethernet"],
        },
    ])

    by_id = {item["id"]: item for item in result["items"]}
    assert by_id["watchtower.behavior.beacon"]["state"] == "disabled_by_policy"
    assert by_id["watchtower.behavior.beacon"]["next_action"]
    assert by_id["watchtower.broken"]["state"] == "invalid_plugin"
    assert by_id["HTTP Parser"]["state"] == "ready"
    assert result["summary"]["disabled_by_policy"] == 1
    assert result["summary"]["invalid_plugin"] == 1


def test_coverage_matrix_reports_missing_required_capability():
    result = build_coverage_matrix([
        {
            "name": "Rust-only detector",
            "type": "detector",
            "detector_id": "watchtower.rust.only",
            "enabled": True,
            "valid": True,
            "required_capability": "rust_sensor",
            "supported_link_types": ["ethernet"],
        },
    ], {"rust_sensor": {"available": False, "reason": "binary missing", "next_action": "Use Python"}})

    item = result["items"][0]
    assert item["state"] == "unavailable_dependency"
    assert item["reason"] == "binary missing"
    assert item["next_action"] == "Use Python"


def test_disabled_compatibility_detector_points_to_its_active_replacement():
    result = build_coverage_matrix([{
        "name": "Legacy Beaconing Detector",
        "type": "detector",
        "detector_id": "watchtower.behavior.beacon",
        "enabled": False,
        "valid": True,
        "replaced_by": "watchtower.stateful.host",
    }])

    item = result["items"][0]
    assert item["state"] == "disabled_by_policy"
    assert item["replacement"] == "watchtower.stateful.host"
    assert "replaced" in item["reason"].lower()
    assert "watchtower.stateful.host" in item["next_action"]
    assert item["next_action"] == (
        "Use active replacement watchtower.stateful.host; do not enable this legacy plugin."
    )
