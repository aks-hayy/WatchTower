import importlib

from core.forensics.analysis_identity import build_analysis_identity
from core.forensics.plugin_loader import PluginLoader


def _rust_plan():
    return importlib.import_module("core.forensics.rust_plan")


def test_execution_mode_and_plan_digest_do_not_change_semantic_identity():
    rust_plan = _rust_plan()
    loader = PluginLoader()
    aggregate = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
    )
    compatibility = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
        requested_mode="compatibility-v1",
    )
    pcap_digest = "ab" * 32

    aggregate_identity = build_analysis_identity(
        pcap_digest,
        {
            "backend": "rust",
            "plugin_semantic_digest": aggregate.semantic_plugin_digest,
            "rust_analysis_execution_mode": aggregate.execution_mode,
            "execution_plan_digest": aggregate.execution_plan_digest,
        },
    )
    compatibility_identity = build_analysis_identity(
        pcap_digest,
        {
            "execution_plan_digest": compatibility.execution_plan_digest,
            "rust_analysis_execution_mode": compatibility.execution_mode,
            "plugin_semantic_digest": compatibility.semantic_plugin_digest,
            "backend": "rust",
        },
    )

    assert aggregate.execution_mode == "aggregate-v1"
    assert compatibility.execution_mode == "compatibility-v1"
    assert aggregate.semantic_plugin_digest == compatibility.semantic_plugin_digest
    assert aggregate.execution_plan_digest != compatibility.execution_plan_digest
    assert aggregate_identity == compatibility_identity


def test_semantic_plugin_digest_changes_immutable_analysis_identity():
    pcap_digest = "cd" * 32

    first = build_analysis_identity(
        pcap_digest,
        {"backend": "rust", "plugin_semantic_digest": "11" * 32},
    )
    second = build_analysis_identity(
        pcap_digest,
        {"backend": "rust", "plugin_semantic_digest": "22" * 32},
    )

    assert first.case_id == second.case_id
    assert first.configuration_hash != second.configuration_hash
    assert first.analysis_id != second.analysis_id
