import os
from pathlib import Path
import time
from types import SimpleNamespace

from core.api.pcap_jobs import PcapJobManager
from core.storage.database import WatchtowerDB


class MemoryCredentialStore:
    def __init__(self):
        self.secrets = {}

    def set(self, reference, secret):
        self.secrets[reference] = secret

    def get(self, reference):
        return self.secrets.get(reference)

    def delete(self, reference):
        return self.secrets.pop(reference, None) is not None


class CaseAwareFakeEngine:
    def __init__(self, **_kwargs):
        pass

    def analyze_pcap(self, path, progress_callback, source_name, mode, backend, cancel_event, case_id=None):
        size = os.path.getsize(path)
        progress_callback(size, size)
        return SimpleNamespace(
            status="COMPLETE",
            summary={"total_flows": 1, "analysis_mode": mode, "case_id": case_id},
            bytes_processed=size,
            error=None,
            report_id=None,
        )


def test_pcap_job_creates_hash_bound_case(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    capture = Path(tmp_path) / "case.pcap"
    capture.write_bytes(b"pcap-case-fixture")
    manager = PcapJobManager(
        db=db,
        engine_factory=CaseAwareFakeEngine,
        credential_store=MemoryCredentialStore(),
    )
    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        deadline = time.time() + 3
        job = manager.get(submitted["id"])
        while job["status"] not in {"complete", "failed", "partial"} and time.time() < deadline:
            time.sleep(0.01)
            job = manager.get(submitted["id"])

        assert job["status"] == "complete", job
        assert job["case_id"]
        assert job["analysis_id"].startswith("analysis-")
        assert job["analysis_id"] != job["id"]
        assert len(job["pcap_sha256"]) == 64
        case = db.get_forensic_case(job["case_id"])
        assert case["analysis_id"] == job["analysis_id"]
        assert case["sha256"] == job["pcap_sha256"]
        assert case["state"] == "complete"
        revision = db.get_forensic_analysis_revision(job["analysis_id"])
        assert revision["pcap_sha256"] == job["pcap_sha256"]
        assert revision["state"] == "complete"

        custody = db.get_case_custody(job["case_id"])
        assert [event["event_type"] for event in custody] == ["submitted", "completed"]
        assert custody[0]["digest"] == job["pcap_sha256"]
    finally:
        manager.shutdown()
        db.close()
