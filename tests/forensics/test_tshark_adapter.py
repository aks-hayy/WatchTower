import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from core.forensics.tshark_adapter import (
    TSHARK_FIELD_ALLOWLIST,
    TSharkDissector,
)


def _json_output(records):
    return json.dumps(
        [{"_source": {"layers": record}} for record in records],
        separators=(",", ":"),
    ).encode("utf-8")


def test_missing_tshark_is_a_first_class_visibility_limitation(tmp_path):
    called = []
    dissector = TSharkDissector(
        configured_executable=tmp_path / "missing-tshark.exe",
        trusted_installations=(),
        runner=lambda *_args, **_kwargs: called.append(True),
    )

    result = dissector.dissect(tmp_path / "capture.pcap")

    assert result.records == ()
    assert result.limitations == ("tshark_unavailable",)
    assert result.health["state"] == "unavailable"
    assert result.health["error_code"] == "tshark_unavailable"
    assert called == []


def test_tshark_discovers_only_configured_or_trusted_local_installations(tmp_path):
    untrusted = tmp_path / "path" / "tshark.exe"
    trusted = tmp_path / "Wireshark" / "tshark.exe"
    untrusted.parent.mkdir()
    trusted.parent.mkdir()
    untrusted.write_bytes(b"untrusted")
    trusted.write_bytes(b"trusted")
    calls = []

    def runner(arguments, **_bounds):
        calls.append(arguments)
        return SimpleNamespace(returncode=0, stdout=b"[]", stderr=b"")

    dissector = TSharkDissector(
        trusted_installations=(trusted,),
        runner=runner,
    )
    result = dissector.dissect(tmp_path / "capture.pcap")

    assert result.health["state"] == "healthy"
    assert Path(calls[0][0]) == trusted.resolve()
    assert str(untrusted) not in calls[0]


def test_tshark_uses_fixed_arguments_fields_and_packet_bound(tmp_path):
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"fixture")
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")
    calls = []

    def runner(arguments, **bounds):
        calls.append((arguments, bounds))
        return SimpleNamespace(
            returncode=0,
            stdout=_json_output(
                [{
                    "frame.number": ["1"],
                    "frame.time_epoch": ["10.25"],
                    "ip.src": ["10.0.0.2"],
                    "ip.dst": ["203.0.113.8"],
                    "tcp.srcport": ["49152"],
                    "tcp.dstport": ["443"],
                    "tls.handshake.extensions_server_name": ["example.test"],
                }]
            ),
            stderr=b"",
        )

    result = TSharkDissector(
        configured_executable=executable,
        trusted_installations=(),
        runner=runner,
        max_packets=25,
        timeout_seconds=3.5,
        max_output_bytes=4096,
    ).dissect(capture)

    arguments, bounds = calls[0]
    emitted_fields = {
        arguments[index + 1]
        for index, value in enumerate(arguments[:-1])
        if value == "-e"
    }
    assert arguments[arguments.index("-c") + 1] == "25"
    assert arguments[arguments.index("-r") + 1] == str(capture.resolve())
    assert arguments[arguments.index("-T") + 1] == "json"
    assert "-Y" not in arguments
    assert "-R" not in arguments
    assert emitted_fields == set(TSHARK_FIELD_ALLOWLIST)
    assert bounds == {"timeout_seconds": 3.5, "max_output_bytes": 4096}
    assert result.records[0]["ip.src"] == "10.0.0.2"
    assert result.records[0]["tls.handshake.extensions_server_name"] == "example.test"


def test_tshark_accepts_fixed_metadata_in_real_json_envelope(tmp_path):
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"fixture")
    output = json.dumps([{
        "_index": "packets-2026-07-29",
        "_type": "doc",
        "_score": None,
        "_source": {
            "layers": {
                "frame.number": ["1"],
                "ip.src": ["10.0.0.2"],
                "tcp.dstport": ["443"],
            }
        },
    }]).encode("utf-8")

    result = TSharkDissector(
        configured_executable=executable,
        trusted_installations=(),
        runner=lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=output, stderr=b""
        ),
    ).dissect(tmp_path / "capture.pcap")

    assert result.limitations == ()
    assert result.records == ({
        "frame.number": "1",
        "ip.src": "10.0.0.2",
        "tcp.dstport": "443",
    },)


def test_tshark_timeout_and_crash_return_health_without_evidence(tmp_path):
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"fixture")

    def timeout_runner(arguments, **_bounds):
        raise subprocess.TimeoutExpired(arguments, timeout=0.1)

    timed_out = TSharkDissector(
        configured_executable=executable,
        trusted_installations=(),
        runner=timeout_runner,
    ).dissect(tmp_path / "capture.pcap")
    crashed = TSharkDissector(
        configured_executable=executable,
        trusted_installations=(),
        runner=lambda *_args, **_kwargs: SimpleNamespace(
            returncode=2, stdout=b"", stderr=b"private path"
        ),
    ).dissect(tmp_path / "capture.pcap")

    assert timed_out.records == crashed.records == ()
    assert timed_out.limitations == ("tshark_timeout",)
    assert crashed.limitations == ("tshark_crashed",)
    assert timed_out.health["state"] == crashed.health["state"] == "degraded"
    assert "private path" not in repr(crashed)


def test_tshark_rejects_malformed_and_oversized_output(tmp_path):
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"fixture")

    malformed = TSharkDissector(
        configured_executable=executable,
        trusted_installations=(),
        runner=lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=b"{", stderr=b""
        ),
    ).dissect(tmp_path / "capture.pcap")
    oversized = TSharkDissector(
        configured_executable=executable,
        trusted_installations=(),
        max_output_bytes=100,
        runner=lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=b"x" * 101, stderr=b""
        ),
    ).dissect(tmp_path / "capture.pcap")
    oversized_record = TSharkDissector(
        configured_executable=executable,
        trusted_installations=(),
        max_output_bytes=4096,
        max_record_bytes=100,
        runner=lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=_json_output([{"http.host": ["x" * 200]}]),
            stderr=b"",
        ),
    ).dissect(tmp_path / "capture.pcap")

    assert malformed.records == oversized.records == oversized_record.records == ()
    assert malformed.limitations == ("tshark_malformed_output",)
    assert oversized.limitations == ("tshark_output_oversized",)
    assert oversized_record.limitations == ("tshark_record_oversized",)
    assert all(
        result.health["state"] == "degraded"
        for result in (malformed, oversized, oversized_record)
    )


@pytest.mark.parametrize("failure_mode", ["timeout", "oversize"])
def test_bounded_runner_terminates_real_child_process(tmp_path, failure_mode):
    pid_path = tmp_path / f"{failure_mode}.pid"
    if failure_mode == "timeout":
        child_code = (
            "import os,pathlib,sys,time;"
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));"
            "time.sleep(30)"
        )
        with pytest.raises(subprocess.TimeoutExpired):
            TSharkDissector._bounded_runner(
                [sys.executable, "-c", child_code, str(pid_path)],
                timeout_seconds=0.5,
                max_output_bytes=1024,
            )
    else:
        child_code = (
            "import os,pathlib,sys,time;"
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));"
            "sys.stdout.buffer.write(b'x'*1048576);"
            "sys.stdout.buffer.flush();"
            "time.sleep(30)"
        )
        completed = TSharkDissector._bounded_runner(
            [sys.executable, "-c", child_code, str(pid_path)],
            timeout_seconds=3.0,
            max_output_bytes=1024,
        )
        assert completed.output_oversized is True

    child_pid = int(pid_path.read_text())
    deadline = time.time() + 2.0
    while psutil.pid_exists(child_pid) and time.time() < deadline:
        time.sleep(0.02)
    assert not psutil.pid_exists(child_pid)
