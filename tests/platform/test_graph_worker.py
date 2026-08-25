import threading
import time

from core.graph.worker import GraphMaterializerWorker


class FakeGraphService:
    def __init__(self):
        self.calls = []
        self.lock = threading.Lock()

    def materialize(self, limit, owner):
        with self.lock:
            self.calls.append((limit, owner))
        return {"materialized": 0, "pending": 0}


def test_graph_worker_polls_and_stops_cleanly():
    service = FakeGraphService()
    worker = GraphMaterializerWorker(service, interval=0.5, batch_size=7)
    worker.start()
    deadline = time.time() + 3
    while time.time() < deadline:
        with service.lock:
            if service.calls:
                break
        time.sleep(0.02)
    worker.stop()
    assert service.calls
    assert service.calls[0][0] == 7
    assert service.calls[0][1].startswith("graph-worker-")
    assert worker.status()["worker_state"] == "stopped"


def test_graph_worker_exposes_last_error_and_keeps_running():
    class FailingService(FakeGraphService):
        def materialize(self, limit, owner):
            raise RuntimeError("neo4j unavailable")

    worker = GraphMaterializerWorker(FailingService(), interval=0.5)
    worker.start()
    deadline = time.time() + 3
    while time.time() < deadline:
        if worker.status()["last_result"]:
            break
        time.sleep(0.02)
    status = worker.status()
    worker.stop()
    assert status["worker_state"] == "running"
    assert status["last_result"]["error"] == "neo4j unavailable"
