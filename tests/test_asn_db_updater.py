from __future__ import annotations

import json
import sys
from pathlib import Path

_BITPROBE = Path(__file__).resolve().parents[1] / "bitprobe"
if str(_BITPROBE) not in sys.path:
    sys.path.insert(0, str(_BITPROBE))

import scanner.asn_db_updater as m
import scanner.update_state as st


class _FakeResponse:
    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code
        self.headers: dict[str, str] = {}


def _fake_delegated_text(registry: str, asn: int, cc: str) -> str:
    return (
        f"2.3|{registry}|3|20240101|18800|20240101|+0000\n"
        f"{registry}|*|asn|*|1|summary\n"
        f"{registry}|{cc}|asn|{asn}|1|20200101|allocated\n"
    )


def test_update_asn_db_merges_all_five_registries(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(st, "STATE_DIR", tmp_path / ".bitsentry")
    monkeypatch.setattr(st, "STATE_PATH", tmp_path / ".bitsentry" / "state.json")
    monkeypatch.setattr(m, "ASN_DB_PATH", str(tmp_path / "asn_db.json"))

    fixtures = {
        "ripencc": _fake_delegated_text("ripencc", 100, "DE"),
        "arin": _fake_delegated_text("arin", 200, "US"),
        "apnic": _fake_delegated_text("apnic", 300, "JP"),
        "lacnic": _fake_delegated_text("lacnic", 400, "BR"),
        "afrinic": _fake_delegated_text("afrinic", 500, "ZA"),
    }

    def _fake_get(url: str, timeout: int = 120):
        for registry, text in fixtures.items():
            if registry in url:
                return _FakeResponse(text)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(m.requests, "get", _fake_get)

    m.update_asn_db(verbose=False, force=True)

    with open(m.ASN_DB_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert set(data["metadata"]["sources"]) == set(m.ASN_SOURCES.values())
    registries = {entry["registry"] for entry in data["asns"].values()}
    assert registries == {"ripencc", "arin", "apnic", "lacnic", "afrinic"}
    assert data["asns"]["100"] == {
        "registry": "ripencc",
        "country": "DE",
        "status": "allocated",
        "allocated": "20200101",
    }
    assert data["asns"]["500"]["country"] == "ZA"


def test_update_asn_db_skips_download_when_all_sources_unchanged(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(st, "STATE_DIR", tmp_path / ".bitsentry")
    monkeypatch.setattr(st, "STATE_PATH", tmp_path / ".bitsentry" / "state.json")
    monkeypatch.setattr(m, "ASN_DB_PATH", str(tmp_path / "asn_db.json"))

    fixtures = {name: _fake_delegated_text(name, i, "XX") for i, name in enumerate(m.ASN_SOURCES)}
    calls = {"get": 0}

    def _fake_get(url: str, timeout: int = 120):
        calls["get"] += 1
        for registry, text in fixtures.items():
            if registry in url:
                resp = _FakeResponse(text)
                resp.headers["ETag"] = f'"{registry}-etag"'
                return resp
        raise AssertionError(f"unexpected URL: {url}")

    def _fake_head(url: str, timeout=30, allow_redirects=True, headers=None):
        for registry in fixtures:
            if registry in url:
                resp = _FakeResponse("")
                resp.headers["ETag"] = f'"{registry}-etag"'
                return resp
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(m.requests, "get", _fake_get)
    monkeypatch.setattr(m.requests, "head", _fake_head)

    m.update_asn_db(verbose=False, force=True)
    assert calls["get"] == 5

    # Force past the age-based "up to date" short-circuit so the per-source
    # identity check (the thing this test actually exercises) runs again.
    st.set_state_timestamp("asn", "last_updated", "2000-01-01T00:00:00.000")

    m.update_asn_db(verbose=False, force=False)
    assert calls["get"] == 5, "unchanged ETags should skip re-downloading every source"
