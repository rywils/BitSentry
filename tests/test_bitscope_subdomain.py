from __future__ import annotations

import threading
import time

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


def test_common_subdomains_filters_and_orders_correctly(monkeypatch) -> None:
    sd = SubdomainDiscovery()

    resolvable = {"www.example.com", "api.example.com"}

    def _fake_resolvable(hostname: str) -> bool:
        return hostname in resolvable

    monkeypatch.setattr(sd, "_is_resolvable", _fake_resolvable)

    found = sd._common_subdomains("example.com")
    assert found == ["api.example.com", "www.example.com"]


def test_common_subdomains_actually_runs_checks_concurrently(monkeypatch) -> None:
    # Prove genuine parallelism, not just correct-looking output, by
    # tracking how many _is_resolvable calls are in flight at once. A
    # sequential implementation can never have more than 1 in flight.
    sd = SubdomainDiscovery()
    lock = threading.Lock()
    state = {"current": 0, "peak": 0}

    def _fake_resolvable(hostname: str) -> bool:
        with lock:
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
        time.sleep(0.05)
        with lock:
            state["current"] -= 1
        return False

    monkeypatch.setattr(sd, "_is_resolvable", _fake_resolvable)

    sd._common_subdomains("example.com")

    assert state["peak"] > 1, "checks should overlap when run through a thread pool"


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
