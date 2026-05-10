from py_dns.packet import QTYPE_A, build_query, parse_response
from py_dns.resolver import SecureUDPServer


class FakeResolver:
    def resolve(self, domain: str, record_type: str = "A") -> str | None:
        assert domain == "example.com"
        assert record_type == "A"
        return "93.184.216.34"


def test_secure_udp_server_handles_a_query_without_network() -> None:
    txid, query = build_query("example.com", QTYPE_A)
    server = SecureUDPServer()
    server.resolver = FakeResolver()  # type: ignore[assignment]

    response = server._handle_packet(query)
    parsed = parse_response(response, txid)

    assert parsed.answers == ["93.184.216.34"]
