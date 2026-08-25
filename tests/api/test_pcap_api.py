import os
from pathlib import Path
from types import SimpleNamespace
import time

from fastapi.testclient import TestClient

from core.api.pcap_jobs import PcapJobManager
from core.api.server import create_app
from core.api.service import WatchtowerApiService
from core.storage.database import WatchtowerDB
from tests.api.test_local_api import FakeDatabase, FakeDaemon, FakeRegistry


class MemoryCredentialStore:
    def __init__(self):
        self.secrets = {}

    def set(self, reference, secret):
        self.secrets[reference] = secret

    def get(self, reference):
        return self.secrets.get(reference)

    def delete(self, reference):
        return self.secrets.pop(reference, None) is not None


class FakeJobs:
    def __init__(self):
        self.submitted = []

    def submit(self, path, filename, mode, backend):
        self.submitted.append((filename, mode, backend, os.path.getsize(path)))
        os.remove(path)
        return {"id": "job-1", "filename": filename, "status": "queued", "source": "pcap:job-1:test.pcap"}

    def list(self, limit=50):
        return [{"id": "job-1", "status": "running"}]

    def get(self, job_id):
        return {"id": job_id, "status": "running", "source": "pcap:job-1:test.pcap"}

    def cancel(self, job_id):
        return {"id": job_id, "status": "cancelling"}

    def shutdown(self):
        pass


def test_pcap_upload_is_streamed_validated_and_queued():
    jobs = FakeJobs()
    with TestClient(create_app(FakeDatabase(), FakeDaemon(), FakeRegistry(), jobs=jobs)) as client:
        response = client.post(
            "/api/v1/pcap/jobs",
            files={"file": ("fixture.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 64, "application/vnd.tcpdump.pcap")},
            data={"mode": "streaming", "backend": "python"},
        )
        assert response.status_code == 202
        assert response.json()["id"] == "job-1"
        assert jobs.submitted == [("fixture.pcap", "streaming", "python", 68)]


def test_pcap_upload_rejects_an_invalid_header():
    jobs = FakeJobs()
    with TestClient(create_app(FakeDatabase(), FakeDaemon(), FakeRegistry(), jobs=jobs)) as client:
        response = client.post(
            "/api/v1/pcap/jobs",
            files={"file": ("fake.pcap", b"not-a-pcap", "application/octet-stream")},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_pcap"
        assert jobs.submitted == []


class FakeEngine:
    def __init__(self, **_kwargs):
        pass

    def analyze_pcap(self, path, progress_callback, source_name, mode, backend, cancel_event):
        size = os.path.getsize(path)
        progress_callback(size, size)
        return SimpleNamespace(
            status="COMPLETE",
            summary={"total_flows": 2, "analysis_mode": mode},
            bytes_processed=size,
            error=None,
        )


def test_pcap_job_manager_reports_progress_and_removes_upload(tmp_path):
    capture = Path(tmp_path) / "small.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    manager = PcapJobManager(
        db=object(),
        engine_factory=FakeEngine,
        credential_store=MemoryCredentialStore(),
    )
    try:
        submitted = manager.submit(str(capture), capture.name, "auto", "python")
        deadline = time.time() + 2
        job = manager.get(submitted["id"])
        while job["status"] not in {"complete", "failed"} and time.time() < deadline:
            time.sleep(0.01)
            job = manager.get(submitted["id"])
        assert job["status"] == "complete"
        assert job["progress"] == 100.0
        assert job["summary"]["total_flows"] == 2
        assert not capture.exists()
    finally:
        manager.shutdown()


def test_v2_pcap_upload_remains_compatible_with_legacy_job_managers():
    jobs = FakeJobs()
    with TestClient(create_app(FakeDatabase(), FakeDaemon(), FakeRegistry(), jobs=jobs)) as client:
        response = client.post(
            "/api/v2/pcap/analyses",
            files={"file": ("fixture.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 64, "application/vnd.tcpdump.pcap")},
            data={"mode": "memory", "backend": "python"},
        )
        assert response.status_code == 202
        assert response.json()["id"] == "job-1"
        assert client.get("/api/v2/pcap/analyses/job-1").status_code == 200


def test_completed_pcap_job_history_survives_manager_restart(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    capture = Path(tmp_path) / "durable.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    credentials = MemoryCredentialStore()
    manager = PcapJobManager(
        db=db,
        engine_factory=FakeEngine,
        credential_store=credentials,
    )
    submitted = manager.submit(str(capture), capture.name, "memory", "python")
    deadline = time.time() + 2
    while manager.get(submitted["id"])["status"] not in {"complete", "failed"} and time.time() < deadline:
        time.sleep(0.01)
    manager.shutdown()

    restored = PcapJobManager(
        db=db,
        engine_factory=FakeEngine,
        credential_store=credentials,
    )
    try:
        job = restored.get(submitted["id"])
        assert job["status"] == "complete"
        assert job["summary"]["total_flows"] == 2
        assert job["progress"] == 100.0
    finally:
        restored.shutdown()
        db.close()


def test_real_forensics_engine_completes_a_tiny_job(tmp_path):
    from scapy.all import Ether, IP, TCP, wrpcap

    db = WatchtowerDB(data_dir=str(tmp_path))
    capture = Path(tmp_path) / "real-engine.pcap"
    wrpcap(str(capture), [
        Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=49152, dport=443, flags="S"),
        Ether() / IP(src="198.51.100.20", dst="192.0.2.10") / TCP(sport=443, dport=49152, flags="SA"),
    ])
    manager = PcapJobManager(db=db, credential_store=MemoryCredentialStore())
    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        deadline = time.time() + 10
        job = manager.get(submitted["id"])
        while job["status"] not in {"complete", "partial", "failed"} and time.time() < deadline:
            time.sleep(0.05)
            job = manager.get(submitted["id"])
        assert job["status"] == "complete", job
        assert job["progress"] == 100.0
        assert job["report_id"] is not None
        assert job["summary"]["total_flows"] == 2
        assert not capture.exists()

        service = WatchtowerApiService(
            db=db,
            daemon=FakeDaemon(),
            registry=FakeRegistry(),
            jobs=manager,
        )
        topology = service.pcap_topology(submitted["id"])
        timeline = service.pcap_timeline(submitted["id"])
        assert len(topology["edges"]) == 1
        assert len(timeline["items"]) == 1
        assert topology["edges"][0]["data"]["packets"] == 2
        assert timeline["items"][0]["to_responder_packets"] == 1
        assert timeline["items"][0]["to_initiator_packets"] == 1
    finally:
        manager.shutdown()
        db.close()
