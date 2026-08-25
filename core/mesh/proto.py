"""Small runtime protobuf definitions for the mesh v2 wire contract.

The repository keeps the source schema in ``core/mesh/mesh.proto``.  The
runtime descriptors avoid requiring protoc on an operator workstation while
still giving gRPC typed protobuf messages instead of a Struct-wrapped
envelope.
"""

from __future__ import annotations

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory


_PACKAGE = "watchtower.mesh.v2"
_FILE_NAME = "watchtower/mesh/v2/mesh.proto"


def _field(message, name, number, field_type):
    field = message.field.add()
    field.name = name
    field.number = number
    field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    field.type = field_type


def _build_classes():
    try:
        pool = descriptor_pool.Default()
        pool.FindFileByName(_FILE_NAME)
    except KeyError:
        file_proto = descriptor_pb2.FileDescriptorProto(
            name=_FILE_NAME,
            package=_PACKAGE,
            syntax="proto3",
        )
        json_message = file_proto.message_type.add(name="JsonMessage")
        _field(json_message, "json", 1, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES)

        telemetry = file_proto.message_type.add(name="TelemetryEnvelope")
        _field(telemetry, "protocol_version", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        _field(telemetry, "node_id", 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        _field(telemetry, "sequence", 3, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64)
        _field(telemetry, "envelope_type", 4, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        _field(telemetry, "payload_json", 5, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES)
        _field(telemetry, "created_at", 6, descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE)
        _field(telemetry, "payload_digest", 7, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
        _field(telemetry, "digest_algorithm", 8, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

        service = file_proto.service.add(name="Mesh")
        enroll = service.method.add(name="Enroll")
        enroll.input_type = f".{_PACKAGE}.JsonMessage"
        enroll.output_type = f".{_PACKAGE}.JsonMessage"
        ingest = service.method.add(name="Ingest")
        ingest.input_type = f".{_PACKAGE}.TelemetryEnvelope"
        ingest.output_type = f".{_PACKAGE}.JsonMessage"
        pool.Add(file_proto)

    pool = descriptor_pool.Default()
    return (
        message_factory.GetMessageClass(pool.FindMessageTypeByName(f"{_PACKAGE}.JsonMessage")),
        message_factory.GetMessageClass(pool.FindMessageTypeByName(f"{_PACKAGE}.TelemetryEnvelope")),
    )


JsonMessage, TelemetryMessage = _build_classes()

