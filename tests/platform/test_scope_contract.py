from core.operations.scope import EffectiveScope


def test_effective_scope_normalizes_and_serializes_all_filters():
    scope = EffectiveScope.from_dict({
        "source": "live",
        "interface": "Ethernet",
        "session_id": "session-1",
        "node_id": "node-1",
        "time_start": 10,
        "time_end": 20,
        "target_ips": ["10.0.0.8", "10.0.0.8"],
    })

    assert scope.target_ips == ("10.0.0.8",)
    assert scope.time_start == 10.0
    assert scope.time_end == 20.0
    assert scope.to_dict()["session_id"] == "session-1"


def test_effective_scope_rejects_reverse_time_ranges():
    try:
        EffectiveScope.from_dict({"time_start": 20, "time_end": 10})
    except ValueError as exc:
        assert "time_start" in str(exc)
    else:
        raise AssertionError("reverse time range must be rejected")


def test_effective_scope_rejects_invalid_explicit_targets_instead_of_widening():
    for targets in (["not-an-ip"], ["10.0.0.8", "not-an-ip"]):
        try:
            EffectiveScope.from_dict({"target_ips": targets})
        except ValueError as exc:
            assert "target_ips" in str(exc)
        else:
            raise AssertionError("invalid explicit targets must not become an unscoped query")


def test_effective_scope_rejects_non_finite_time_bounds():
    for time_start in (float("nan"), float("inf"), float("-inf")):
        try:
            EffectiveScope.from_dict({"time_start": time_start})
        except ValueError as exc:
            assert "time_start" in str(exc)
        else:
            raise AssertionError("non-finite time bounds must be rejected")
