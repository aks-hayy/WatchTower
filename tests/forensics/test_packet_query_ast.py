import pytest

from core.forensics.packet_query import (
    PacketFilter,
    PacketQuery,
    PacketQueryError,
    compile_packet_query,
)


def test_packet_query_compiles_deterministically_with_parameterized_values():
    query = PacketQuery(
        select=("packet_ordinal", "timestamp", "src_ip", "dst_ip", "dst_port"),
        filters=(
            PacketFilter("dst_port", "eq", 443),
            PacketFilter("protocol", "in", ("TCP", "UDP")),
            PacketFilter("timestamp", "between", (100.0, 200.0)),
        ),
        order_by="packet_ordinal",
        limit=100,
    )

    first = compile_packet_query(query)
    second = compile_packet_query(query)

    assert first == second
    assert "443" not in first.sql
    assert "TCP" not in first.sql
    assert first.parameters == (443, "TCP", "UDP", 100.0, 200.0, 101)
    assert first.sql.endswith("LIMIT ?")
    assert first.fetch_limit == 101


def test_packet_query_uses_packet_ordinal_as_a_stable_keyset_cursor():
    compiled = compile_packet_query(PacketQuery(
        select=("packet_ordinal", "timestamp"),
        cursor=500,
        limit=25,
    ))

    assert "packet_ordinal > ?" in compiled.sql
    assert compiled.parameters[-2:] == (500, 26)


def test_packet_query_compiles_ipv4_and_ipv6_cidr_without_sql_extensions():
    ipv4 = compile_packet_query(PacketQuery(filters=(
        PacketFilter("src_ip", "cidr", "192.0.2.0/24"),
    )))
    ipv6 = compile_packet_query(PacketQuery(filters=(
        PacketFilter("dst_ip", "cidr", "2001:db8::/32"),
    )))

    assert "src_ip_version = ?" in ipv4.sql
    assert "src_ip_packed BETWEEN ? AND ?" in ipv4.sql
    assert ipv4.parameters[0] == 4
    assert ipv4.parameters[1] == b"\xc0\x00\x02\x00"
    assert ipv4.parameters[2] == b"\xc0\x00\x02\xff"
    assert "dst_ip_version = ?" in ipv6.sql
    assert len(ipv6.parameters[1]) == 16
    assert len(ipv6.parameters[2]) == 16


@pytest.mark.parametrize(
    "query",
    [
        PacketQuery(select=("timestamp; DROP TABLE packet_index",)),
        PacketQuery(filters=(PacketFilter("src_ip OR 1=1", "eq", "192.0.2.1"),)),
        PacketQuery(filters=(PacketFilter("src_ip", "raw_sql", "1=1"),)),
        PacketQuery(order_by="random()"),
        PacketQuery(limit=501),
        PacketQuery(filters=(PacketFilter("dst_port", "in", tuple(range(101))),)),
        PacketQuery(filters=(PacketFilter("src_ip", "cidr", "not-a-network"),)),
        PacketQuery(order_by="timestamp", cursor=10),
    ],
)
def test_packet_query_rejects_unsafe_or_unbounded_shapes(query):
    with pytest.raises(PacketQueryError):
        compile_packet_query(query)


def test_packet_query_treats_injection_text_as_a_value_not_an_expression():
    malicious = "192.0.2.1' OR 1=1 --"
    compiled = compile_packet_query(PacketQuery(filters=(
        PacketFilter("src_ip", "eq", malicious),
    )))

    assert malicious not in compiled.sql
    assert compiled.parameters[0] == malicious


def test_packet_query_from_dict_rejects_unknown_keys_and_bounds_partitions():
    with pytest.raises(PacketQueryError):
        PacketQuery.from_dict({"sql": "select * from secrets"})
    with pytest.raises(PacketQueryError):
        PacketQuery.from_dict({"partition_ids": list(range(33))})

    query = PacketQuery.from_dict({
        "select": ["packet_ordinal", "frame_sha256"],
        "filters": [{"field": "decoded", "op": "eq", "value": True}],
        "partition_ids": [2, 3],
        "limit": 10,
    })
    compiled = compile_packet_query(query)

    assert "partition_id IN (?,?)" in compiled.sql
    assert compiled.parameters == (True, 2, 3, 11)


def test_packet_query_bounds_total_filters_for_dicts_and_direct_queries():
    filters = [
        {"field": "dst_port", "op": "eq", "value": index}
        for index in range(65)
    ]

    with pytest.raises(PacketQueryError, match="filters"):
        PacketQuery.from_dict({"filters": filters})
    with pytest.raises(PacketQueryError, match="filters"):
        compile_packet_query(PacketQuery(filters=tuple(
            PacketFilter("dst_port", "eq", index) for index in range(65)
        )))


def test_packet_query_applies_text_bound_before_cidr_parsing():
    with pytest.raises(PacketQueryError, match="512"):
        compile_packet_query(PacketQuery(filters=(
            PacketFilter("src_ip", "cidr", "1" * 513),
        )))
