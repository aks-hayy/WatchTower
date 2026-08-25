"""Typed, bounded query AST for immutable forensic packet indexes."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import math
from typing import Any, Mapping, Sequence


class PacketQueryError(ValueError):
    pass


PUBLIC_FIELDS = frozenset({
    "packet_ordinal",
    "timestamp",
    "caplen",
    "wirelen",
    "link_type",
    "decoded",
    "decode_reason",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "ip_protocol",
    "tcp_flags",
    "frame_sha256",
    "partition_id",
})
ORDER_FIELDS = frozenset({
    "packet_ordinal",
    "timestamp",
    "caplen",
    "wirelen",
})
OPERATORS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte", "in", "between", "cidr"})
MAX_LIMIT = 500
MAX_FILTERS = 64
MAX_IN_VALUES = 100
MAX_PARTITIONS = 32
MAX_TEXT_LENGTH = 512


@dataclass(frozen=True)
class PacketFilter:
    field: str
    op: str
    value: Any


@dataclass(frozen=True)
class PacketQuery:
    select: tuple[str, ...] = (
        "packet_ordinal",
        "timestamp",
        "caplen",
        "wirelen",
        "link_type",
        "decoded",
        "decode_reason",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "tcp_flags",
        "frame_sha256",
    )
    filters: tuple[PacketFilter, ...] = field(default_factory=tuple)
    partition_ids: tuple[int, ...] = field(default_factory=tuple)
    order_by: str = "packet_ordinal"
    descending: bool = False
    cursor: int | None = None
    limit: int = 100

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "PacketQuery":
        if not isinstance(payload, Mapping):
            raise PacketQueryError("packet query must be an object")
        allowed = {
            "select",
            "filters",
            "partition_ids",
            "order_by",
            "descending",
            "cursor",
            "limit",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise PacketQueryError(f"unsupported packet query keys: {', '.join(sorted(unknown))}")

        raw_select = payload.get("select", cls.select)
        if isinstance(raw_select, (str, bytes)) or not isinstance(raw_select, Sequence):
            raise PacketQueryError("select must be a list of fields")
        raw_filters = payload.get("filters", ())
        if isinstance(raw_filters, (str, bytes)) or not isinstance(raw_filters, Sequence):
            raise PacketQueryError("filters must be a list")
        if len(raw_filters) > MAX_FILTERS:
            raise PacketQueryError(f"at most {MAX_FILTERS} filters may be applied")
        filters = []
        for item in raw_filters:
            if not isinstance(item, Mapping) or set(item) != {"field", "op", "value"}:
                raise PacketQueryError("each filter requires only field, op, and value")
            filters.append(PacketFilter(str(item["field"]), str(item["op"]), item["value"]))

        raw_partitions = payload.get("partition_ids", ())
        if isinstance(raw_partitions, (str, bytes)) or not isinstance(raw_partitions, Sequence):
            raise PacketQueryError("partition_ids must be a list")
        if len(raw_partitions) > MAX_PARTITIONS:
            raise PacketQueryError(f"at most {MAX_PARTITIONS} partitions may be scanned")
        return cls(
            select=tuple(str(value) for value in raw_select),
            filters=tuple(filters),
            partition_ids=tuple(raw_partitions),
            order_by=str(payload.get("order_by", "packet_ordinal")),
            descending=bool(payload.get("descending", False)),
            cursor=payload.get("cursor"),
            limit=payload.get("limit", 100),
        )


@dataclass(frozen=True)
class CompiledPacketQuery:
    sql: str
    parameters: tuple[Any, ...]
    columns: tuple[str, ...]
    fetch_limit: int


def _bounded_scalar(field_name: str, value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if field_name in {"src_port", "dst_port"} and not 0 <= value <= 65_535:
            raise PacketQueryError(f"{field_name} must be between 0 and 65535")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PacketQueryError("numeric filter values must be finite")
        return value
    if value is None:
        return None
    if isinstance(value, str):
        if len(value) > MAX_TEXT_LENGTH:
            raise PacketQueryError(f"text filter values may not exceed {MAX_TEXT_LENGTH} characters")
        return value
    raise PacketQueryError(f"unsupported value for {field_name}")


def _compile_filter(packet_filter: PacketFilter) -> tuple[str, tuple[Any, ...]]:
    field_name = str(packet_filter.field)
    operator = str(packet_filter.op).lower()
    if field_name not in PUBLIC_FIELDS:
        raise PacketQueryError(f"unsupported packet field: {field_name}")
    if operator not in OPERATORS:
        raise PacketQueryError(f"unsupported packet operator: {operator}")

    if operator == "cidr":
        if field_name not in {"src_ip", "dst_ip"}:
            raise PacketQueryError("CIDR filters apply only to source or destination IP")
        value = _bounded_scalar(field_name, packet_filter.value)
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise PacketQueryError("CIDR filter is invalid") from exc
        return (
            f"({field_name}_version = ? AND {field_name}_packed BETWEEN ? AND ?)",
            (network.version, network.network_address.packed, network.broadcast_address.packed),
        )

    if operator in {"in", "between"}:
        value = packet_filter.value
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            raise PacketQueryError(f"{operator} requires a list")
        values = tuple(_bounded_scalar(field_name, item) for item in value)
        if operator == "between":
            if len(values) != 2:
                raise PacketQueryError("between requires exactly two values")
            return f"{field_name} BETWEEN ? AND ?", values
        if not values or len(values) > MAX_IN_VALUES:
            raise PacketQueryError(f"in requires between 1 and {MAX_IN_VALUES} values")
        return f"{field_name} IN ({','.join('?' for _ in values)})", values

    value = _bounded_scalar(field_name, packet_filter.value)
    if value is None:
        if operator == "eq":
            return f"{field_name} IS NULL", ()
        if operator == "ne":
            return f"{field_name} IS NOT NULL", ()
        raise PacketQueryError("null supports only eq and ne")
    symbols = {
        "eq": "=",
        "ne": "!=",
        "lt": "<",
        "lte": "<=",
        "gt": ">",
        "gte": ">=",
    }
    return f"{field_name} {symbols[operator]} ?", (value,)


def compile_packet_query(query: PacketQuery) -> CompiledPacketQuery:
    if not isinstance(query, PacketQuery):
        raise PacketQueryError("query must be a PacketQuery")
    columns = tuple(query.select)
    if not columns or len(columns) > len(PUBLIC_FIELDS):
        raise PacketQueryError("select must contain a bounded non-empty field list")
    if len(set(columns)) != len(columns) or any(column not in PUBLIC_FIELDS for column in columns):
        raise PacketQueryError("select contains unsupported or duplicate fields")
    if query.order_by not in ORDER_FIELDS:
        raise PacketQueryError("unsupported packet order field")
    if not isinstance(query.descending, bool):
        raise PacketQueryError("descending must be boolean")
    if isinstance(query.limit, bool) or not isinstance(query.limit, int) or not 1 <= query.limit <= MAX_LIMIT:
        raise PacketQueryError(f"limit must be between 1 and {MAX_LIMIT}")
    if query.cursor is not None:
        if query.order_by != "packet_ordinal":
            raise PacketQueryError("cursor pagination requires packet_ordinal ordering")
        if isinstance(query.cursor, bool) or not isinstance(query.cursor, int) or query.cursor < 0:
            raise PacketQueryError("cursor must be a non-negative packet ordinal")
    if len(query.partition_ids) > MAX_PARTITIONS:
        raise PacketQueryError(f"at most {MAX_PARTITIONS} partitions may be scanned")
    if len(query.filters) > MAX_FILTERS:
        raise PacketQueryError(f"at most {MAX_FILTERS} filters may be applied")

    predicates = []
    parameters: list[Any] = []
    for packet_filter in query.filters:
        predicate, values = _compile_filter(packet_filter)
        predicates.append(predicate)
        parameters.extend(values)
    if query.partition_ids:
        partitions = sorted(set(query.partition_ids))
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in partitions):
            raise PacketQueryError("partition IDs must be non-negative integers")
        predicates.append(f"partition_id IN ({','.join('?' for _ in partitions)})")
        parameters.extend(partitions)
    if query.cursor is not None:
        comparator = "<" if query.descending else ">"
        predicates.append(f"packet_ordinal {comparator} ?")
        parameters.append(query.cursor)

    sql = f"SELECT {','.join(columns)} FROM packet_index"
    if predicates:
        sql += " WHERE " + " AND ".join(predicates)
    direction = "DESC" if query.descending else "ASC"
    sql += f" ORDER BY {query.order_by} {direction}"
    if query.order_by != "packet_ordinal":
        sql += f",packet_ordinal {direction}"
    fetch_limit = query.limit + 1
    sql += " LIMIT ?"
    parameters.append(fetch_limit)
    return CompiledPacketQuery(
        sql=sql,
        parameters=tuple(parameters),
        columns=columns,
        fetch_limit=fetch_limit,
    )
