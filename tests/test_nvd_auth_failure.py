from __future__ import annotations

import sys
from pathlib import Path


_BITPROBE = Path(__file__).resolve().parents[1] / "bitprobe"
if str(_BITPROBE) not in sys.path:
    sys.path.insert(0, str(_BITPROBE))


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.text = ""


def _patch_requests(monkeypatch, status_code: int) -> list[dict]:
    from scanner import cve_db_manager as manager

    calls: list[dict] = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append({"headers": dict(headers or {})})
        return _Response(status_code)

    monkeypatch.setattr(manager.requests, "get", fake_get)
    monkeypatch.setattr(manager.time, "sleep", lambda seconds: None)
    return calls


def test_404_with_api_key_does_not_retry(monkeypatch) -> None:
    """An invalid NVD API key returns 404 permanently; retrying it wastes attempts."""
    from scanner import cve_db_manager as manager

    calls = _patch_requests(monkeypatch, 404)
    response = manager._nvd_get({}, {"apiKey": "bogus-key"})

    assert response.status_code == 404
    assert len(calls) == 1, f"expected fail-fast on bad key, made {len(calls)} attempts"


def test_404_without_api_key_still_retries(monkeypatch) -> None:
    """Without a key a 404 is genuinely transient, so retries must be preserved."""
    from scanner import cve_db_manager as manager

    calls = _patch_requests(monkeypatch, 404)
    response = manager._nvd_get({}, {"User-Agent": "BitSentry/1.0"})

    assert response.status_code == 404
    assert len(calls) == manager.NVD_MAX_RETRIES


def test_429_with_api_key_still_retries(monkeypatch) -> None:
    """Rate limiting is transient even with a valid key."""
    from scanner import cve_db_manager as manager

    calls = _patch_requests(monkeypatch, 429)
    manager._nvd_get({}, {"apiKey": "good-key"})

    assert len(calls) == manager.NVD_MAX_RETRIES
