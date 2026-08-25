from core.endpoint.attribution import EndpointAttributor
from core.endpoint.sysmon import parse_sysmon_event
from core.storage.database import WatchtowerDB


SYSMON_NETWORK_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>3</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-07-20T10:00:00.000Z" /></System>
  <EventData>
    <Data Name="ProcessGuid">{abc}</Data><Data Name="ProcessId">1234</Data>
    <Data Name="Image">C:\\Program Files\\Example\\agent.exe</Data><Data Name="CommandLine">agent.exe --token super-secret</Data>
    <Data Name="User">LAB\\analyst</Data><Data Name="Protocol">tcp</Data><Data Name="Initiated">true</Data>
    <Data Name="SourceIp">10.0.0.10</Data><Data Name="SourcePort">50123</Data>
    <Data Name="DestinationIp">8.8.8.8</Data><Data Name="DestinationPort">443</Data>
    <Data Name="Hashes">SHA256=abcdef,MD5=1234</Data>
  </EventData>
</Event>"""


def test_parse_sysmon_network_event_redacts_command_line():
    event = parse_sysmon_event(SYSMON_NETWORK_XML)
    assert event["event_type"] == "network_connect"
    assert event["protocol"] == "TCP"
    assert event["local_port"] == 50123
    assert event["remote_ip"] == "8.8.8.8"
    assert event["command_line_hash"]
    assert "command_line" not in event
    assert "super-secret" not in repr(event)


def test_malformed_or_unrelated_sysmon_events_are_rejected():
    assert parse_sysmon_event("not xml") is None
    assert parse_sysmon_event("<Event><System><EventID>22</EventID></System><EventData /></Event>") is None


def test_exact_sysmon_observation_wins_and_is_persisted_without_command_line(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    parsed = parse_sysmon_event(SYSMON_NETWORK_XML)
    parsed.update({
        "id": "sysmon:test:network:42", "sensor_node_id": db.local_sensor_node_id(),
        "evidence_ref": "sysmon:42", "service_names": ["WatchTower Agent"],
    })
    db.upsert_endpoint_process_observations([parsed])
    result = EndpointAttributor(db).attribute(
        src_ip="10.0.0.10", src_port=50123, dst_ip="8.8.8.8", dst_port=443,
        protocol="TCP", observed_at=parsed["observed_at"],
    )
    assert result["provenance"] == "sysmon_exact"
    assert result["confidence"] == 0.98
    assert result["service_names"] == ["WatchTower Agent"]
    stored = db.get_endpoint_process_observations(ip="10.0.0.10")
    assert stored[0]["command_line_hash"] == parsed["command_line_hash"]
    assert "super-secret" not in repr(stored)
    db.close()


def test_multiple_exact_sysmon_processes_are_labeled_ambiguous(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    node = db.local_sensor_node_id()
    observations = []
    for record, pid in (("100", 1001), ("101", 1002)):
        observations.append({
            "id": f"sysmon:test:{record}", "sensor_node_id": node, "event_record_id": record,
            "event_type": "network_connect", "observed_at": 100.0, "pid": pid,
            "image": f"C:\\tool{pid}.exe", "protocol": "TCP", "local_ip": "10.0.0.10",
            "local_port": 60000, "remote_ip": "1.1.1.1", "remote_port": 443,
            "evidence_ref": f"sysmon:{record}", "service_names": [],
        })
    db.upsert_endpoint_process_observations(observations)
    result = EndpointAttributor(db).attribute(
        src_ip="10.0.0.10", src_port=60000, dst_ip="1.1.1.1", dst_port=443,
        protocol="TCP", observed_at=100.0,
    )
    assert result["provenance"] == "ambiguous"
    assert len(result["candidates"]) == 2
    db.close()
