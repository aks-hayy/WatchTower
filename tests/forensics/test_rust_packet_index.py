import io
import struct

import pytest

import core.packet_engine.rust_capture as rust_capture


FRAME_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def _short(value):
    encoded = value.encode("ascii")
    return bytes([len(encoded)]) + encoded


def _index_payload(*, decoded=True, reason="", presence=0x0F):
    payload = bytearray(b"\x01\x00\x01")
    payload.extend(struct.pack(">QdII", 7, 1.5, 54, 60))
    payload.extend(_short("ethernet"))
    payload.extend(bytes([int(decoded)]))
    payload.extend(_short(reason))
    payload.extend(_short("10.0.0.1" if decoded else ""))
    payload.extend(_short("10.0.0.2" if decoded else ""))
    payload.extend(bytes([presence]))
    payload.extend(struct.pack(
        ">HHBH",
        12345 if presence & 0x01 else 0,
        443 if presence & 0x02 else 0,
        6 if presence & 0x04 else 0,
        0x12 if presence & 0x08 else 0,
    ))
    payload.extend(bytes.fromhex(FRAME_HASH))
    return bytes(payload)


def _frame(frame_type, payload):
    return (
        rust_capture.MAGIC
        + bytes([1, frame_type])
        + struct.pack(">I", len(payload))
        + payload
    )


class _Process:
    def __init__(self, stdout, *, stderr=b"", exit_code=0):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = None
        self._exit_code = exit_code
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = self._exit_code
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.returncode = -9


def test_decode_packet_index_batch_returns_normalized_payload_free_rows():
    rows = rust_capture.decode_packet_index_batch(_index_payload())

    assert rows == [{
        "packet_ordinal": 7,
        "timestamp": 1.5,
        "caplen": 54,
        "wirelen": 60,
        "link_type": "ethernet",
        "decoded": True,
        "decode_reason": None,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "TCP",
        "tcp_flags": 0x12,
        "frame_sha256": FRAME_HASH,
    }]
    assert "raw" not in rows[0]
    assert "payload" not in rows[0]


@pytest.mark.parametrize("cut", [0, 2, 10, 40, -1])
def test_decode_packet_index_batch_rejects_every_truncated_region(cut):
    payload = _index_payload()

    with pytest.raises(ValueError, match="Truncated packet-index"):
        rust_capture.decode_packet_index_batch(payload[:cut])


def test_decode_packet_index_batch_rejects_malformed_and_noncanonical_fields():
    invalid_schema = b"\x02\x00\x00"
    excessive_count = b"\x01" + struct.pack(">H", 4097)
    invalid_ascii = bytearray(_index_payload())
    invalid_ascii[28] = 0xFF
    invalid_decoded_marker = bytearray(_index_payload())
    invalid_decoded_marker[36] = 2
    invalid_presence = bytearray(_index_payload())
    invalid_presence[-40] = 0x80

    for payload in (
        invalid_schema,
        excessive_count,
        invalid_ascii,
        invalid_decoded_marker,
        invalid_presence,
        _index_payload() + b"\x00",
        _index_payload(decoded=True, reason="unexpected"),
        _index_payload(decoded=False, reason="", presence=0),
    ):
        with pytest.raises(ValueError):
            rust_capture.decode_packet_index_batch(payload)


def test_read_frame_applies_packet_index_specific_bound_before_reading_payload():
    header = (
        rust_capture.MAGIC
        + bytes([1, rust_capture.FRAME_PACKET_INDEX])
        + struct.pack(">I", rust_capture.MAX_PACKET_INDEX_FRAME_BYTES + 1)
    )

    with pytest.raises(ValueError, match="packet-index frame exceeds limit"):
        rust_capture.read_frame(io.BytesIO(header))


def test_iter_packet_index_invokes_index_command_and_yields_rows(
    monkeypatch, tmp_path
):
    binary = tmp_path / "watchtower-sensor"
    binary.write_bytes(b"sensor")
    process = _Process(_frame(rust_capture.FRAME_PACKET_INDEX, _index_payload()))
    spawned = []

    monkeypatch.setattr(rust_capture, "sensor_binary", lambda: binary)

    def popen(command, **kwargs):
        spawned.append(command)
        return process

    monkeypatch.setattr(rust_capture.subprocess, "Popen", popen)

    rows = list(rust_capture.iter_packet_index(tmp_path / "capture.pcap", batch=17))

    assert rows[0]["packet_ordinal"] == 7
    assert spawned == [[
        str(binary),
        "index",
        "--pcap",
        str(tmp_path / "capture.pcap"),
        "--batch",
        "17",
    ]]


@pytest.mark.parametrize("batch", [0, 4097, True, "256"])
def test_iter_packet_index_rejects_invalid_batch_before_starting_child(
    monkeypatch, batch
):
    monkeypatch.setattr(
        rust_capture.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("child must not start"),
    )

    with pytest.raises(ValueError, match="batch"):
        list(rust_capture.iter_packet_index("capture.pcap", batch=batch))


def test_iter_packet_index_rejects_truncated_child_output(monkeypatch, tmp_path):
    binary = tmp_path / "watchtower-sensor"
    binary.write_bytes(b"sensor")
    payload = _index_payload()
    truncated = (
        rust_capture.MAGIC
        + bytes([1, rust_capture.FRAME_PACKET_INDEX])
        + struct.pack(">I", len(payload) + 1)
        + payload
    )
    process = _Process(truncated)
    monkeypatch.setattr(rust_capture, "sensor_binary", lambda: binary)
    monkeypatch.setattr(
        rust_capture.subprocess, "Popen", lambda *args, **kwargs: process
    )

    with pytest.raises(EOFError, match="truncated"):
        list(rust_capture.iter_packet_index(tmp_path / "capture.pcap"))


def test_iter_packet_index_rejects_unexpected_frame_type(monkeypatch, tmp_path):
    binary = tmp_path / "watchtower-sensor"
    binary.write_bytes(b"sensor")
    process = _Process(_frame(rust_capture.FRAME_HEALTH, b"{}"))
    monkeypatch.setattr(rust_capture, "sensor_binary", lambda: binary)
    monkeypatch.setattr(
        rust_capture.subprocess, "Popen", lambda *args, **kwargs: process
    )

    with pytest.raises(ValueError, match="unexpected frame type"):
        list(rust_capture.iter_packet_index(tmp_path / "capture.pcap"))


def test_iter_packet_index_propagates_nonzero_child_exit(monkeypatch, tmp_path):
    binary = tmp_path / "watchtower-sensor"
    binary.write_bytes(b"sensor")
    process = _Process(b"", stderr=b"invalid capture header", exit_code=7)
    monkeypatch.setattr(rust_capture, "sensor_binary", lambda: binary)
    monkeypatch.setattr(
        rust_capture.subprocess, "Popen", lambda *args, **kwargs: process
    )

    with pytest.raises(RuntimeError, match="invalid capture header"):
        list(rust_capture.iter_packet_index(tmp_path / "corrupt.pcap"))
