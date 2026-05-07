from __future__ import annotations

from bitscope.discovery.subdomain import SubdomainDiscovery, normalize_target_hostname


def test_discover_normalizes_url_target(monkeypatch) -> None:
    sd = SubdomainDiscovery()

    def _fake_crt(domain: str):
        assert domain == "example.com"
        return ["www.example.com"]

    monkeypatch.setattr(sd, "_from_crtsh", _fake_crt)
    monkeypatch.setattr(sd, "_common_subdomains", lambda d: [])
    monkeypatch.setattr(sd, "_from_ssl_cert", lambda d: [])

    out = sd.discover("https://example.com/path?q=1")
    assert out["all_unique"] == ["www.example.com"]


def test_normalize_target_hostname_strips_url_and_path() -> None:
    assert normalize_target_hostname("HTTPS://Example.COM/path") == "example.com"
    assert normalize_target_hostname("  ") == ""


def test_discover_empty_input_returns_empty_collections() -> None:
    sd = SubdomainDiscovery()
    out = sd.discover("   ")
    assert out == {
        "certificate_transparency": [],
        "common_wordlist": [],
        "ssl_certificate": [],
        "all_unique": [],
    }
