import importlib
from dataclasses import replace

import pytest

from core.forensics.base import BaseDetector, BaseParser
from core.forensics.plugin_loader import PluginLoader


def _rust_plan():
    return importlib.import_module("core.forensics.rust_plan")


def _declared_capability(rust_plan, *, prefix=b"WT"):
    return rust_plan.OfflineCapability(
        packet_view="fast-v1",
        selector_programs=(
            rust_plan.SelectorProgram(
                candidate_mode="fast-v1",
                clauses=(
                    rust_plan.SelectorClause(
                        opcode="payload-prefix-in",
                        values=(prefix,),
                    ),
                ),
            ),
        ),
    )


class UnknownParser(BaseParser):
    name = "Unknown Parser"


class UnknownDetector(BaseDetector):
    name = "Unknown Detector"


class DeclaredParser(BaseParser):
    name = "Declared Parser"


class DeclaredDetector(BaseDetector):
    name = "Declared Detector"


def test_all_active_builtins_have_valid_capabilities_and_select_aggregate():
    rust_plan = _rust_plan()
    loader = PluginLoader()
    active = [
        *[parser for parser in loader.get_parsers() if parser.enabled],
        *[detector for detector in loader.get_detectors() if detector.enabled],
    ]

    plan = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
        source_type="network",
        link_type="ethernet",
    )

    assert plan.execution_mode == "aggregate-v1"
    assert plan.incompatibilities == ()
    assert len(plan.plugins) == len(active)
    for plugin in active:
        capability = rust_plan.offline_capability_for(plugin)
        assert capability is not None, plugin.name
        assert rust_plan.validate_offline_capability(capability) == ()

    bluetooth = next(
        entry for entry in plan.plugins if entry.name == "Bluetooth HCI Parser"
    )
    assert bluetooth.supported_capture_sources == ("bluetooth",)
    assert bluetooth.supported_link_types == ("bluetooth-hci",)
    assert not bluetooth.applicable


def test_infrastructure_parser_none_view_matches_its_passive_identity_contract():
    rust_plan = _rust_plan()
    loader = PluginLoader()
    parser = next(
        plugin
        for plugin in loader.get_parsers()
        if plugin.name == "Infrastructure Parser"
    )

    assert rust_plan.offline_capability_for(parser).packet_view == "none"
    assert parser.parse(object()) == {"identities": {}}


def test_os_identity_enrichment_does_not_force_every_packet_into_python():
    rust_plan = _rust_plan()
    loader = PluginLoader()
    detector = next(
        plugin
        for plugin in loader.get_detectors()
        if plugin.name == "OS Fingerprinting Detector"
    )

    capability = rust_plan.offline_capability_for(detector)

    assert capability.packet_view == "none"
    assert capability.selector_programs == ()


def test_ntp_metadata_uses_the_first_flow_candidate_instead_of_every_datagram():
    rust_plan = _rust_plan()
    loader = PluginLoader()
    parser = next(
        plugin for plugin in loader.get_parsers() if plugin.name == "NTP Parser"
    )

    capability = rust_plan.offline_capability_for(parser)

    assert capability.packet_view == "none"
    assert capability.selector_programs == ()


def test_ftp_detector_selects_protocol_evidence_on_nonstandard_ports():
    rust_plan = _rust_plan()
    detector = next(
        plugin
        for plugin in PluginLoader().get_detectors()
        if plugin.name == "Cleartext FTP Credential Detector"
    )

    capability = rust_plan.offline_capability_for(detector)
    clauses = capability.selector_programs[0].clauses

    assert rust_plan.SelectorClause("ip-protocol-in", (6,)) in clauses
    assert not any(clause.opcode == "destination-port-in" for clause in clauses)
    assert rust_plan.SelectorClause(
        "payload-contains-any", (b"USER ", b"PASS ")
    ) in clauses


def test_file_detector_selects_every_required_pe_evidence_segment():
    rust_plan = _rust_plan()
    detector = next(
        plugin
        for plugin in PluginLoader().get_detectors()
        if plugin.name == "File Transfer Detector"
    )

    capability = rust_plan.offline_capability_for(detector)
    literals = {
        literal
        for program in capability.selector_programs
        for clause in program.clauses
        if clause.opcode == "payload-contains-any"
        for literal in clause.values
    }

    assert {b"MZ", b"This program cannot be run in DOS mode"} <= literals


def test_plugin_and_execution_digests_ignore_runtime_inventory_ordering():
    rust_plan = _rust_plan()
    loader = PluginLoader()

    first = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
    )
    reordered = rust_plan.build_rust_analysis_plan(
        list(reversed(loader.get_parsers())),
        list(reversed(loader.get_detectors())),
    )

    assert first.semantic_plugin_digest == reordered.semantic_plugin_digest
    assert first.execution_plan_digest == reordered.execution_plan_digest
    assert first.plugins == reordered.plugins
    assert first.selector_programs == reordered.selector_programs


def test_selector_set_and_clause_order_do_not_change_digests():
    rust_plan = _rust_plan()
    first_parser = DeclaredParser()
    first_parser.offline_capability = rust_plan.OfflineCapability(
        packet_view="fast-v1",
        selector_programs=(
            rust_plan.SelectorProgram(
                candidate_mode="fast-v1",
                clauses=(
                    rust_plan.SelectorClause("ip-protocol-in", (17, 6)),
                    rust_plan.SelectorClause("either-port-in", (443, 80)),
                ),
            ),
            rust_plan.SelectorProgram(
                candidate_mode="fast-v1",
                clauses=(
                    rust_plan.SelectorClause(
                        "payload-prefix-in",
                        (b"POST ", b"GET "),
                    ),
                ),
            ),
        ),
    )
    reordered_parser = DeclaredParser()
    reordered_parser.offline_capability = rust_plan.OfflineCapability(
        packet_view="fast-v1",
        selector_programs=(
            rust_plan.SelectorProgram(
                candidate_mode="fast-v1",
                clauses=(
                    rust_plan.SelectorClause(
                        "payload-prefix-in",
                        (b"GET ", b"POST "),
                    ),
                ),
            ),
            rust_plan.SelectorProgram(
                candidate_mode="fast-v1",
                clauses=(
                    rust_plan.SelectorClause("either-port-in", (80, 443)),
                    rust_plan.SelectorClause("ip-protocol-in", (6, 17)),
                ),
            ),
        ),
    )

    first = rust_plan.build_rust_analysis_plan([first_parser], [])
    reordered = rust_plan.build_rust_analysis_plan([reordered_parser], [])

    assert first.semantic_plugin_digest == reordered.semantic_plugin_digest
    assert first.execution_plan_digest == reordered.execution_plan_digest
    assert first.selector_programs == reordered.selector_programs


def test_semantic_digest_changes_for_capability_api_source_and_manifest_version():
    rust_plan = _rust_plan()
    loader = PluginLoader()
    parser = next(
        plugin for plugin in loader.get_parsers() if plugin.name == "HTTP Parser"
    )
    detector = next(
        plugin
        for plugin in loader.get_detectors()
        if plugin.name == "Application Abuse Detector"
    )
    baseline = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
    )

    parser.api_version += 1
    api_changed = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
    )
    parser.api_version -= 1

    parser.supported_capture_sources = ("network", "import")
    source_changed = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
    )
    del parser.supported_capture_sources

    parser.offline_capability = replace(
        rust_plan.offline_capability_for(parser),
        packet_flow_view="scalar-v1",
    )
    capability_changed = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
    )
    del parser.offline_capability

    detector.manifest = replace(detector.manifest, version="2.1.1")
    manifest_changed = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
    )

    changed = {
        api_changed.semantic_plugin_digest,
        source_changed.semantic_plugin_digest,
        capability_changed.semantic_plugin_digest,
        manifest_changed.semantic_plugin_digest,
    }
    assert baseline.semantic_plugin_digest not in changed
    assert len(changed) == 4


def test_unknown_parser_and_detector_select_compatibility_without_omission():
    rust_plan = _rust_plan()

    plan = rust_plan.build_rust_analysis_plan(
        [UnknownParser()],
        [UnknownDetector()],
    )

    assert plan.execution_mode == "compatibility-v1"
    assert [(entry.plugin_type, entry.name) for entry in plan.plugins] == [
        ("detector", "Unknown Detector"),
        ("parser", "Unknown Parser"),
    ]
    assert all(entry.applicable for entry in plan.plugins)
    assert all(entry.capability is None for entry in plan.plugins)
    assert len(plan.incompatibilities) == 2
    assert "Unknown Detector" in plan.incompatibilities[0]
    assert "Unknown Parser" in plan.incompatibilities[1]


def test_strict_aggregate_rejects_every_unknown_capability_actionably():
    rust_plan = _rust_plan()

    with pytest.raises(rust_plan.AggregateCapabilityError) as caught:
        rust_plan.build_rust_analysis_plan(
            [UnknownParser()],
            [UnknownDetector()],
            strict_aggregate=True,
        )

    assert caught.value.incompatibilities == (
        "detector Unknown Detector: missing aggregate-v1 offline capability declaration",
        "parser Unknown Parser: missing aggregate-v1 offline capability declaration",
    )
    assert "Unknown Detector" in str(caught.value)
    assert "Unknown Parser" in str(caught.value)


def test_malformed_capability_fails_closed_without_crashing_plan_generation():
    rust_plan = _rust_plan()
    parser = DeclaredParser()
    parser.offline_capability = {"contract": "aggregate-v1"}

    plan = rust_plan.build_rust_analysis_plan([parser], [])

    assert plan.execution_mode == "compatibility-v1"
    assert plan.plugins[0].capability is None
    assert plan.plugins[0].capability_state == "invalid"
    assert plan.incompatibilities == (
        "parser Declared Parser: offline capability must be an OfflineCapability declaration",
    )


def test_bluetooth_and_unsupported_link_requests_remain_explicit():
    rust_plan = _rust_plan()
    loader = PluginLoader()

    bluetooth = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
        source_type="bluetooth",
        link_type="bluetooth-hci",
    )
    unsupported_link = rust_plan.build_rust_analysis_plan(
        loader.get_parsers(),
        loader.get_detectors(),
        source_type="network",
        link_type="linux-sll",
    )

    bluetooth_entry = next(
        entry
        for entry in bluetooth.plugins
        if entry.name == "Bluetooth HCI Parser"
    )
    assert bluetooth.execution_mode == "compatibility-v1"
    assert bluetooth_entry.applicable
    assert any(
        "source_type bluetooth is not supported by aggregate-v1"
        in incompatibility
        for incompatibility in bluetooth.incompatibilities
    )
    assert unsupported_link.execution_mode == "compatibility-v1"
    assert any(
        "link_type linux-sll is not supported by aggregate-v1"
        in incompatibility
        for incompatibility in unsupported_link.incompatibilities
    )


def test_runtime_plugin_drift_and_plan_tampering_are_rejected():
    rust_plan = _rust_plan()
    parser = DeclaredParser()
    parser.offline_capability = _declared_capability(rust_plan)
    detector = DeclaredDetector()
    detector.offline_capability = rust_plan.OfflineCapability(
        flow_input="full-flow-v1"
    )
    queued = rust_plan.build_rust_analysis_plan([parser], [detector])

    assert (
        rust_plan.verify_rust_analysis_plan(
            queued,
            [parser],
            [detector],
        )
        == queued
    )

    parser.api_version = 2
    with pytest.raises(
        rust_plan.RustPlanDriftError,
        match="queued plugin inventory changed before replay",
    ):
        rust_plan.verify_rust_analysis_plan(queued, [parser], [detector])
    parser.api_version = 1

    tampered = replace(queued, execution_plan_digest="00" * 32)
    with pytest.raises(
        rust_plan.RustPlanIntegrityError,
        match="execution-plan digest mismatch",
    ):
        rust_plan.verify_rust_analysis_plan(tampered, [parser], [detector])
