from py_dns.cache import NegativeEntry, SecureDNSCache, VulnerableCache


def test_secure_cache_positive_and_negative_entries() -> None:
    cache = SecureDNSCache()

    cache.put_positive("Example.COM", "93.184.216.34", 30)
    assert cache.get("example.com") == "93.184.216.34"

    cache.put_negative("missing.example")
    assert isinstance(cache.get("missing.example"), NegativeEntry)


def test_vulnerable_cache_has_no_ttl_or_negative_semantics() -> None:
    cache = VulnerableCache()
    cache.put("example.com", 1, "192.0.2.1")

    assert cache.get("EXAMPLE.COM", 1) == "192.0.2.1"
    assert cache.get("example.com", 28) is None
