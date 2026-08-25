import time

from sqlalchemy import event

from core.storage.database import WatchtowerDB


def test_reset_remains_bounded_with_another_database_reader(tmp_path):
    writer = WatchtowerDB(data_dir=tmp_path)
    reader = WatchtowerDB(data_dir=tmp_path)
    writer.upsert_entity(ip="10.0.0.2", source="live_test", timestamp=1.0)
    assert reader.get_all_entities(source="live_test")

    started = time.monotonic()
    deleted = writer.reset_all()

    assert time.monotonic() - started < 2.0
    assert deleted["entities"] == 1
    assert "capture_sessions" in deleted
    assert "hardware_observations" in deleted
    assert reader.get_all_entities(source="live_test") == []
    reader.close()
    writer.close()


def test_local_sensor_node_id_is_cached_after_database_initialization(tmp_path):
    db = WatchtowerDB(data_dir=tmp_path)
    expected = db.local_sensor_node_id()
    metadata_queries = 0

    def count_metadata_queries(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ):
        nonlocal metadata_queries
        normalized = statement.lower()
        if normalized.startswith("select") and "system_metadata" in normalized:
            metadata_queries += 1

    event.listen(db.engine, "before_cursor_execute", count_metadata_queries)
    try:
        assert {db.local_sensor_node_id() for _ in range(100)} == {expected}
        assert metadata_queries == 0
    finally:
        event.remove(db.engine, "before_cursor_execute", count_metadata_queries)
        db.close()


def test_local_sensor_cache_tracks_metadata_replacement_across_instances(
    tmp_path,
):
    writer = WatchtowerDB(data_dir=tmp_path)
    reader = WatchtowerDB(data_dir=tmp_path)
    original = writer.local_sensor_node_id()
    assert reader.local_sensor_node_id() == original

    replacement = "local-replacement-node"
    writer.set_metadata("mesh.local_node_id", replacement)

    assert writer.local_sensor_node_id() == replacement
    assert reader.local_sensor_node_id() == replacement
    reader.close()
    writer.close()


def test_local_sensor_cache_tracks_factory_reset_across_instances(tmp_path):
    writer = WatchtowerDB(data_dir=tmp_path)
    reader = WatchtowerDB(data_dir=tmp_path)
    original = writer.local_sensor_node_id()
    assert reader.local_sensor_node_id() == original

    writer.reset_all(mode="factory")
    replacement = writer.local_sensor_node_id()

    assert replacement != original
    assert reader.local_sensor_node_id() == replacement
    reader.close()
    writer.close()
