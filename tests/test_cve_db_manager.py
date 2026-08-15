from __future__ import annotations

import sys
from pathlib import Path

_BITPROBE = Path(__file__).resolve().parents[1] / "bitprobe"
if str(_BITPROBE) not in sys.path:
    sys.path.insert(0, str(_BITPROBE))

from scanner.cve_db_manager import (
    NVD_SLEEP_NO_KEY,
    NVD_SLEEP_WITH_KEY,
    _extract_cpe_matches_from_node,
    _extract_cve_data,
    _nvd_inter_request_sleep,
)


def _cpe_match(criteria: str, vulnerable: bool = True) -> dict:
    return {"vulnerable": vulnerable, "criteria": criteria}


def test_extract_cpe_matches_from_flat_node() -> None:
    node = {"cpeMatch": [_cpe_match("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")]}
    products = _extract_cpe_matches_from_node(node)
    assert products == [
        {
            "vendor": "nginx",
            "product": "nginx",
            "version_start": "1.18.0",
            "version_end": "1.18.0",
            "version_start_including": 0,
            "version_end_including": 0,
        }
    ]


def test_extract_cpe_matches_recurses_into_children() -> None:
    # NVD configuration nodes can nest CPE matches under 'children' for
    # AND/OR logic ("product A AND (component B OR component C)"). A CVE
    # whose match only lives in a nested child has no top-level cpeMatch.
    node = {
        "operator": "AND",
        "cpeMatch": [],
        "children": [
            {"cpeMatch": [_cpe_match("cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*")]},
            {
                "children": [
                    {"cpeMatch": [_cpe_match("cpe:2.3:a:apache:mod_ssl:2.8.0:*:*:*:*:*:*:*")]},
                ]
            },
        ],
    }
    products = _extract_cpe_matches_from_node(node)
    found = {(p["vendor"], p["product"]) for p in products}
    assert found == {("apache", "http_server"), ("apache", "mod_ssl")}


def test_extract_cpe_matches_skips_non_vulnerable_matches() -> None:
    node = {"cpeMatch": [_cpe_match("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", vulnerable=False)]}
    assert _extract_cpe_matches_from_node(node) == []


def test_extract_cve_data_finds_products_nested_under_children_only() -> None:
    cve_data = {
        "id": "CVE-2024-00001",
        "descriptions": [{"lang": "en", "value": "test"}],
        "references": [],
        "metrics": {},
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "AND",
                        "children": [
                            {"cpeMatch": [_cpe_match("cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*")]},
                        ],
                    }
                ]
            }
        ],
    }
    normalized = _extract_cve_data(cve_data)
    assert normalized is not None
    assert [(p["vendor"], p["product"]) for p in normalized["products"]] == [
        ("apache", "http_server")
    ]


def test_nvd_inter_request_sleep_respects_documented_limits() -> None:
    # NVD: 5 req/30s without a key, 50 req/30s with one.
    assert _nvd_inter_request_sleep(None) == NVD_SLEEP_NO_KEY == 6.0
    assert _nvd_inter_request_sleep("some-key") == NVD_SLEEP_WITH_KEY
    assert NVD_SLEEP_WITH_KEY <= 0.6 + 0.1  # small safety margin over 30/50
