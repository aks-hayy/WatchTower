import tracemalloc

from core.calibration.service import _pause_tracemalloc_for_replay


def test_integrated_replay_pauses_and_restores_memory_tracing():
    tracemalloc.start()
    try:
        with _pause_tracemalloc_for_replay():
            assert not tracemalloc.is_tracing()
        assert tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()
