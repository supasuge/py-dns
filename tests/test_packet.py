import struct

from py_dns.packet import QTYPE_A, build_query, build_response, parse_query, parse_response


def test_build_response_round_trips_as_valid_dns_answer() -> None:
    txid, query = build_query("example.com", QTYPE_A)
    question = parse_query(query)

    response = build_response(question, ["93.184.216.34"], ttl=120)
    parsed = parse_response(response, expected_txid=txid)

    assert parsed.rcode == 0
    assert parsed.answers == ["93.184.216.34"]


def test_parse_query_rejects_response_packets() -> None:
    txid, query = build_query("example.com", QTYPE_A)
    response_header = struct.pack("!HHHHHH", txid, 0x8180, 1, 0, 0, 0)
    response = response_header + query[12:]

    try:
        parse_query(response)
    except ValueError as exc:
        assert "response" in str(exc)
    else:
        raise AssertionError("parse_query accepted a response packet")
