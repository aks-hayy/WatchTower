"""Optional bounded TShark deep-dissection adapter."""

import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterable, Tuple

TSHARK_FIELD_ALLOWLIST = (
    "frame.number",
    "frame.time_epoch",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "dns.flags.response",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
    "tls.handshake.ciphersuite",
)


@dataclass(frozen=True)
class TSharkResult:
    records: Tuple[Dict[str, Any], ...]
    limitations: Tuple[str, ...]
    health: Dict[str, Any]


class TSharkDissector:
    def __init__(
        self,
        *,
        configured_executable: str | Path | None = None,
        trusted_installations: Iterable[str | Path] | None = None,
        runner: Callable[..., Any] | None = None,
        max_packets: int = 1_000,
        timeout_seconds: float = 10.0,
        max_output_bytes: int = 2 * 1024 * 1024,
        max_record_bytes: int = 64 * 1024,
    ):
        self.configured_executable = (
            Path(configured_executable).expanduser()
            if configured_executable
            else None
        )
        self.trusted_installations = tuple(
            Path(path).expanduser()
            for path in (
                trusted_installations
                if trusted_installations is not None
                else self._default_trusted_installations()
            )
        )
        self.runner = runner or self._bounded_runner
        self.max_packets = max(1, min(int(max_packets), 10_000))
        self.timeout_seconds = max(0.1, min(float(timeout_seconds), 60.0))
        self.max_output_bytes = max(100, min(int(max_output_bytes), 16 * 1024 * 1024))
        self.max_record_bytes = max(100, min(int(max_record_bytes), 256 * 1024))

    @staticmethod
    def _default_trusted_installations() -> Tuple[Path, ...]:
        if sys.platform == "win32":
            roots = [
                os.environ.get("ProgramFiles"),
                os.environ.get("ProgramFiles(x86)"),
            ]
            return tuple(
                Path(root) / "Wireshark" / "tshark.exe"
                for root in roots
                if root
            )
        return (Path("/usr/bin/tshark"), Path("/usr/local/bin/tshark"))

    def discover(self) -> Path | None:
        candidates = (
            (self.configured_executable,)
            if self.configured_executable is not None
            else self.trusted_installations
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file():
                return candidate.resolve()
        return None

    def build_arguments(self, executable: Path, pcap_path: str | Path) -> list[str]:
        arguments = [
            str(executable),
            "-n",
            "-r",
            str(Path(pcap_path).resolve()),
            "-c",
            str(self.max_packets),
            "-T",
            "json",
        ]
        for field in TSHARK_FIELD_ALLOWLIST:
            arguments.extend(("-e", field))
        return arguments

    def dissect(self, pcap_path: str | Path) -> TSharkResult:
        executable = self.discover()
        if executable is None:
            return self._failure("tshark_unavailable", "unavailable")
        arguments = self.build_arguments(executable, pcap_path)
        try:
            completed = self.runner(
                arguments,
                timeout_seconds=self.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
            )
        except subprocess.TimeoutExpired:
            return self._failure("tshark_timeout")
        except (OSError, ValueError):
            return self._failure("tshark_crashed")

        stdout = bytes(getattr(completed, "stdout", b"") or b"")
        if getattr(completed, "output_oversized", False) or len(stdout) > self.max_output_bytes:
            return self._failure("tshark_output_oversized")
        if int(getattr(completed, "returncode", 1)) != 0:
            return self._failure("tshark_crashed")
        try:
            records = self._parse_output(stdout)
        except _TSharkRecordOversized:
            return self._failure("tshark_record_oversized")
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            return self._failure("tshark_malformed_output")
        return TSharkResult(
            records=records,
            limitations=(),
            health={
                "plugin": "tshark",
                "state": "healthy",
                "error_code": None,
                "records": len(records),
            },
        )

    def _parse_output(self, output: bytes) -> Tuple[Dict[str, Any], ...]:
        decoded = json.loads(output.decode("utf-8"))
        if not isinstance(decoded, list) or len(decoded) > self.max_packets:
            raise ValueError("TShark output must be a bounded JSON array")
        records = []
        allowed = set(TSHARK_FIELD_ALLOWLIST)
        for envelope in decoded:
            if (
                not isinstance(envelope, dict)
                or "_source" not in envelope
                or not set(envelope).issubset({"_source", "_index", "_type", "_score"})
            ):
                raise ValueError("TShark record envelope is malformed")
            if "_index" in envelope and (
                not isinstance(envelope["_index"], str)
                or len(envelope["_index"]) > 256
            ):
                raise ValueError("TShark index metadata is malformed")
            if "_type" in envelope and (
                not isinstance(envelope["_type"], str)
                or len(envelope["_type"]) > 64
            ):
                raise ValueError("TShark type metadata is malformed")
            if "_score" in envelope and envelope["_score"] is not None and not isinstance(
                envelope["_score"], (int, float)
            ):
                raise ValueError("TShark score metadata is malformed")
            source = envelope["_source"]
            if not isinstance(source, dict) or set(source) != {"layers"}:
                raise ValueError("TShark record source is malformed")
            layers = source["layers"]
            if not isinstance(layers, dict) or not set(layers).issubset(allowed):
                raise ValueError("TShark record fields are malformed")
            if len(
                json.dumps(layers, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ) > self.max_record_bytes:
                raise _TSharkRecordOversized()
            record: Dict[str, Any] = {}
            for name, value in layers.items():
                if isinstance(value, list):
                    if not value or len(value) > 32 or any(
                        not isinstance(item, (str, int, float, bool))
                        for item in value
                    ):
                        raise ValueError("TShark field value is malformed")
                    normalized = [
                        item[:2048] if isinstance(item, str) else item
                        for item in value
                    ]
                    record[name] = normalized[0] if len(normalized) == 1 else normalized
                elif isinstance(value, (str, int, float, bool)):
                    record[name] = value[:2048] if isinstance(value, str) else value
                else:
                    raise ValueError("TShark field value is malformed")
            records.append(record)
        return tuple(records)

    @staticmethod
    def _failure(error_code: str, state: str = "degraded") -> TSharkResult:
        return TSharkResult(
            records=(),
            limitations=(error_code,),
            health={
                "plugin": "tshark",
                "state": state,
                "error_code": error_code,
                "records": 0,
            },
        )

    @staticmethod
    def _bounded_runner(
        arguments: list[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ):
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        stdout = bytearray()
        stderr = bytearray()
        oversized = threading.Event()

        def read_stdout() -> None:
            while process.stdout is not None:
                chunk = process.stdout.read(64 * 1024)
                if not chunk:
                    return
                remaining = max_output_bytes + 1 - len(stdout)
                if remaining > 0:
                    stdout.extend(chunk[:remaining])
                if len(stdout) > max_output_bytes or len(chunk) > remaining:
                    oversized.set()
                    process.kill()
                    return

        def read_stderr() -> None:
            while process.stderr is not None:
                chunk = process.stderr.read(4096)
                if not chunk:
                    return
                if len(stderr) < 4096:
                    stderr.extend(chunk[: 4096 - len(stderr)])

        readers = [
            threading.Thread(target=read_stdout, daemon=True),
            threading.Thread(target=read_stderr, daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            for reader in readers:
                reader.join(timeout=1.0)
            raise
        for reader in readers:
            reader.join(timeout=1.0)
        return SimpleNamespace(
            returncode=returncode,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            output_oversized=oversized.is_set(),
        )


class _TSharkRecordOversized(ValueError):
    pass
