import json

from core.calibration.attestations import document_digest
from core.api.service import WatchtowerApiService
from core.operations import calibration_presentation
from core.operations.calibration_presentation import calibration_trust_basis, calibration_trust_label
from core.operations.calibration_presentation import annotate_calibration_verification


def _write_attestation(path, payload):
    payload["digest"] = document_digest(payload)
    path = path.parent / f"{payload['digest']}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return payload["digest"]


def test_bootstrap_attestation_is_not_presented_as_field_evidence(tmp_path):
    path = tmp_path / "bootstrap.json"
    digest = _write_attestation(path, {
        "awarded_level": "FIELD_CALIBRATED",
        "bootstrap_exception": {"exception_id": "builtins-v2.0"},
        "field_evidence": {"relevant_host_days": 0},
    })

    assert calibration_trust_basis("FIELD_CALIBRATED", digest, tmp_path) == "bootstrap_corpus"
    assert calibration_trust_label("FIELD_CALIBRATED", "bootstrap_corpus") == "BOOTSTRAP QUALIFIED"


def test_field_attestation_requires_minimum_host_days(tmp_path):
    path = tmp_path / "field.json"
    digest = _write_attestation(path, {
        "awarded_level": "FIELD_CALIBRATED",
        "bootstrap_exception": None,
        "field_evidence": {"relevant_host_days": 30},
    })

    assert calibration_trust_basis("FIELD_CALIBRATED", digest, tmp_path) == "field_evidence"
    assert calibration_trust_label("FIELD_CALIBRATED", "field_evidence") == "FIELD EVIDENCE"
    assert calibration_trust_basis("CORPUS_VALIDATED") == "corpus"
    assert calibration_trust_label("CORPUS_VALIDATED", "corpus") == "CORPUS VALIDATED"


def test_invalid_or_missing_attestation_never_claims_field_evidence(tmp_path):
    assert calibration_trust_basis("FIELD_CALIBRATED", "a" * 64, tmp_path) == "unknown"
    assert calibration_trust_basis("FIELD_CALIBRATED", "../escape", tmp_path) == "unknown"
    assert calibration_trust_basis("FIELD_CALIBRATED", "a" * 64, tmp_path, "stale") == "unknown"


def test_plugin_trust_summary_uses_verified_evidence_and_discloses_mixed_basis(tmp_path):
    summarize = getattr(calibration_presentation, "calibration_trust_summary", None)
    assert callable(summarize)
    digest = _write_attestation(tmp_path / "bootstrap.json", {
        "awarded_level": "FIELD_CALIBRATED",
        "bootstrap_exception": {"exception_id": "builtins-v2.0"},
        "field_evidence": {"relevant_host_days": 0},
    })
    bootstrap = {
        "calibration_level": "FIELD_CALIBRATED",
        "attestation_digest": digest,
        "stale_reason": "",
    }

    assert summarize([bootstrap], tmp_path) == "BOOTSTRAP QUALIFIED"
    assert summarize([bootstrap, {"calibration_level": "CORPUS_VALIDATED"}], tmp_path) == "MIXED TRUST"
    assert summarize([], tmp_path) == "NOT APPLICABLE"


def test_api_report_summary_exposes_bootstrap_basis():
    summary = WatchtowerApiService._report_summary({
        "awarded_level": "FIELD_CALIBRATED",
        "bootstrap_exception": {"exception_id": "builtins-v2.0"},
    })

    assert summary["trust_basis"] == "bootstrap_corpus"


def test_verification_output_distinguishes_bootstrap_from_field_evidence(tmp_path):
    digest = _write_attestation(tmp_path / "bootstrap.json", {
        "awarded_level": "FIELD_CALIBRATED",
        "bootstrap_exception": {"exception_id": "builtins-v2.0"},
        "field_evidence": {"relevant_host_days": 0},
    })
    profiles = tmp_path / "scoring_profiles.yaml"
    profiles.write_text(
        "detectors:\n  watchtower.application.abuse:\n    findings:\n"
        "      credential.cleartext.generic:\n"
        "        calibration_level: FIELD_CALIBRATED\n"
        f"        attestation_digest: {digest}\n",
        encoding="utf-8",
    )
    result = {"valid": True, "errors": [], "targets": [{
        "detector_id": "watchtower.application.abuse",
        "finding_type": "credential.cleartext.generic",
        "level": "FIELD_CALIBRATED",
        "valid": True,
        "reason": "",
    }]}

    annotated = annotate_calibration_verification(result, profiles, tmp_path)

    assert annotated["targets"][0]["trust_basis"] == "bootstrap_corpus"
    assert annotated["targets"][0]["trust_label"] == "BOOTSTRAP QUALIFIED"
    assert annotated["targets"][0]["attestation_digest"] == digest
