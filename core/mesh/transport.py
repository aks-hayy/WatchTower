"""Versioned gRPC mesh transport; v2 carries canonical JSON bytes in typed protobuf."""

from __future__ import annotations

from concurrent import futures
from hashlib import sha256
import json
from typing import Any, Dict, Optional

import grpc

from core.mesh.contracts import (
    MESH_PROTOCOL_VERSION,
    TelemetryEnvelope,
    canonical_json_bytes,
    decode_message,
    encode_message,
)
from core.mesh.proto import JsonMessage, TelemetryMessage


SERVICE_NAME = "watchtower.mesh.v1.Mesh"
V2_SERVICE_NAME = "watchtower.mesh.v2.Mesh"


def _response(value: Dict[str, Any]) -> bytes:
    return encode_message(value)


class MeshGrpcServer:
    def __init__(self, service, host: str = "127.0.0.1", enrollment_port: int = 9443, ingest_port: int = 9444):
        self.service, self.host, self.enrollment_port, self.ingest_port = service, host, int(enrollment_port), int(ingest_port)
        self._enrollment_server = None
        self._ingest_server = None

    def start(self) -> Dict[str, Any]:
        if not self.service.authority.ready:
            self.service.initialize(self.host)
        key, certificate, ca_certificate = self.service.authority.server_credentials()
        enroll_handlers = grpc.method_handlers_generic_handler(SERVICE_NAME, {
            "Enroll": grpc.unary_unary_rpc_method_handler(
                self._enroll, request_deserializer=decode_message, response_serializer=_response,
            ),
        })
        ingest_handlers = grpc.method_handlers_generic_handler(SERVICE_NAME, {
            "Ingest": grpc.unary_unary_rpc_method_handler(
                self._ingest, request_deserializer=decode_message, response_serializer=_response,
            ),
        })
        self._enrollment_server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        self._enrollment_server.add_generic_rpc_handlers((enroll_handlers, self._v2_enrollment_handlers()))
        enrollment_port = self._enrollment_server.add_secure_port(
            f"{self.host}:{self.enrollment_port}", grpc.ssl_server_credentials(((key, certificate),)),
        )
        if not enrollment_port:
            raise RuntimeError("Unable to bind mesh enrollment listener")
        self._ingest_server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
        self._ingest_server.add_generic_rpc_handlers((ingest_handlers, self._v2_ingest_handlers()))
        ingest_port = self._ingest_server.add_secure_port(
            f"{self.host}:{self.ingest_port}",
            grpc.ssl_server_credentials(((key, certificate),), root_certificates=ca_certificate, require_client_auth=True),
        )
        if not ingest_port:
            raise RuntimeError("Unable to bind mesh ingest listener")
        self.enrollment_port, self.ingest_port = enrollment_port, ingest_port
        self._enrollment_server.start()
        self._ingest_server.start()
        return {"host": self.host, "enrollment_port": self.enrollment_port, "ingest_port": self.ingest_port}

    def stop(self) -> None:
        for server in (self._enrollment_server, self._ingest_server):
            if server is not None:
                server.stop(grace=2)

    def wait(self) -> None:
        if self._ingest_server is not None:
            self._ingest_server.wait_for_termination()

    def _enroll(self, request: Dict[str, Any], _context) -> Dict[str, Any]:
        try:
            return {"ok": True, "result": self.service.enroll(request)}
        except (ValueError, PermissionError, RuntimeError) as exc:
            return {"ok": False, "error": str(exc)}

    def _v2_enrollment_handlers(self):
        return grpc.method_handlers_generic_handler(V2_SERVICE_NAME, {
            "Enroll": grpc.unary_unary_rpc_method_handler(
                self._enroll_v2,
                request_deserializer=JsonMessage.FromString,
                response_serializer=lambda value: value.SerializeToString(deterministic=True),
            ),
        })

    def _v2_ingest_handlers(self):
        return grpc.method_handlers_generic_handler(V2_SERVICE_NAME, {
            "Ingest": grpc.unary_unary_rpc_method_handler(
                self._ingest_v2,
                request_deserializer=TelemetryMessage.FromString,
                response_serializer=lambda value: value.SerializeToString(deterministic=True),
            ),
        })

    @staticmethod
    def _json_message(value: Dict[str, Any]):
        return JsonMessage(json=canonical_json_bytes(value))

    @staticmethod
    def _decode_json_message(request) -> Dict[str, Any]:
        try:
            value = json.loads(bytes(request.json).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError("Mesh JSON request is invalid") from exc
        if not isinstance(value, dict):
            raise ValueError("Mesh JSON request must be an object")
        return value

    def _enroll_v2(self, request, _context):
        try:
            return self._json_message({"ok": True, "result": self.service.enroll(self._decode_json_message(request))})
        except (ValueError, PermissionError, RuntimeError) as exc:
            return self._json_message({"ok": False, "error": str(exc)})

    def _ingest(self, request: Dict[str, Any], context) -> Dict[str, Any]:
        try:
            node_id = str(request.get("node_id") or "")
            identities = context.auth_context().get("x509_common_name", [])
            common_name = identities[0].decode("utf-8") if identities else ""
            if common_name != node_id:
                return {"ok": False, "error": "mTLS certificate does not match mesh node"}
            return {"ok": True, "result": self.service.ingest(node_id, request)}
        except (ValueError, PermissionError, RuntimeError) as exc:
            return {"ok": False, "error": str(exc)}

    def _ingest_v2(self, request, context):
        try:
            node_id = str(request.node_id or "")
            identities = context.auth_context().get("x509_common_name", [])
            common_name = identities[0].decode("utf-8") if identities else ""
            if common_name != node_id:
                return self._json_message({"ok": False, "error": "mTLS certificate does not match mesh node"})
            raw_payload = bytes(request.payload_json)
            if len(raw_payload) > 2 * 1024 * 1024:
                raise ValueError("Mesh payload exceeds the 2 MiB transport limit")
            if sha256(raw_payload).hexdigest() != str(request.payload_digest or ""):
                raise ValueError("Mesh payload hash mismatch before decode")
            payload = json.loads(raw_payload.decode("utf-8"))
            if canonical_json_bytes(payload) != raw_payload:
                raise ValueError("Mesh payload is not canonical JSON")
            envelope = TelemetryEnvelope(
                node_id=node_id,
                sequence=int(request.sequence),
                envelope_type=str(request.envelope_type or ""),
                payload=payload,
                created_at=float(request.created_at),
                protocol_version=str(request.protocol_version or MESH_PROTOCOL_VERSION),
                payload_digest=str(request.payload_digest or ""),
                digest_algorithm=str(request.digest_algorithm or ""),
            )
            result = self.service.ingest(node_id, envelope.to_dict())
            return self._json_message({"ok": True, "result": result})
        except (ValueError, PermissionError, RuntimeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self._json_message({"ok": False, "error": str(exc)})


class MeshGrpcClient:
    def __init__(self, controller: str, enrollment_port: int = 9443, ingest_port: int = 9444,
                 ca_certificate: bytes = None, client_key: bytes = None, client_certificate: bytes = None):
        self.controller = controller
        self.enrollment_port, self.ingest_port = int(enrollment_port), int(ingest_port)
        self.ca_certificate, self.client_key, self.client_certificate = ca_certificate, client_key, client_certificate

    @staticmethod
    def _json_message(value: Dict[str, Any]):
        return JsonMessage(json=canonical_json_bytes(value))

    def enroll(self, request: Dict[str, Any], root_certificate: bytes) -> Dict[str, Any]:
        credentials = grpc.ssl_channel_credentials(root_certificates=root_certificate)
        with grpc.secure_channel(f"{self.controller}:{self.enrollment_port}", credentials) as channel:
            call = channel.unary_unary(
                f"/{V2_SERVICE_NAME}/Enroll",
                request_serializer=lambda value: self._json_message(value).SerializeToString(deterministic=True),
                response_deserializer=JsonMessage.FromString,
            )
            response = json.loads(bytes(call(request, timeout=20).json).decode("utf-8"))
        if not response.get("ok"):
            raise PermissionError(str(response.get("error") or "Mesh enrollment failed"))
        return dict(response["result"])

    def ingest(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        if not all((self.ca_certificate, self.client_key, self.client_certificate)):
            raise RuntimeError("Mesh client is not enrolled")
        credentials = grpc.ssl_channel_credentials(
            root_certificates=self.ca_certificate, private_key=self.client_key, certificate_chain=self.client_certificate,
        )
        typed = TelemetryEnvelope.from_dict(envelope)
        payload_bytes = canonical_json_bytes(typed.payload)
        message = TelemetryMessage(
            protocol_version=typed.protocol_version,
            node_id=typed.node_id,
            sequence=typed.sequence,
            envelope_type=typed.envelope_type,
            payload_json=payload_bytes,
            created_at=typed.created_at,
            payload_digest=typed.payload_digest,
            digest_algorithm=typed.digest_algorithm,
        )
        with grpc.secure_channel(f"{self.controller}:{self.ingest_port}", credentials) as channel:
            call = channel.unary_unary(
                f"/{V2_SERVICE_NAME}/Ingest",
                request_serializer=lambda value: value.SerializeToString(deterministic=True),
                response_deserializer=JsonMessage.FromString,
            )
            response = json.loads(bytes(call(message, timeout=20).json).decode("utf-8"))
        if not response.get("ok"):
            raise RuntimeError(str(response.get("error") or "Mesh telemetry rejected"))
        return dict(response["result"])
