from __future__ import annotations

import json

import pytest

from bitsentry import _parse_bitscope_discovery_json


def test_parse_plain_object() -> None:
    assert _parse_bitscope_discovery_json(' {"ok": true} \n') == {"ok": True}


def test_parse_extracts_outermost_braces() -> None:
    text = 'BitScope output:\n{"discovery": {"subdomains": {}}}\nDONE'
    assert _parse_bitscope_discovery_json(text) == {"discovery": {"subdomains": {}}}


def test_parse_empty_returns_empty_dict() -> None:
    assert _parse_bitscope_discovery_json("") == {}
    assert _parse_bitscope_discovery_json("  \n  ") == {}


def test_parse_invalid_raises() -> None:
    with pytest.raises(json.JSONDecodeError):
        _parse_bitscope_discovery_json("not json at all")
