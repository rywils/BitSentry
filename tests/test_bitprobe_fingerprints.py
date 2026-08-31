import pytest
from requests import Response

from plugins import cve_correlation
from plugins.cve_correlation import CVECorrelationPlugin
from scanner.fingerprints import fingerprint_technologies


def versioned_wordpress_response():
    response = Response()
    response.status_code = 200
    response.url = "https://example.test"
    response.headers = {
        "Content-Type": "text/html",
        "X-Powered-By": "PHP/8.5.5",
    }
    response._content = (
        b'<meta name="generator" content="WordPress 6.7.1">'
        b'<link href="/wp-content/site.css">'
    )
    response.encoding = "utf-8"
    return response


def test_fingerprinting_keeps_php_and_wordpress_versions():
    detected = fingerprint_technologies(versioned_wordpress_response())

    assert detected["framework_version"] == "6.7.1"
    assert detected["_detailed"]["languages"][0] == {
        "name": "PHP",
        "version": "8.5.5",
    }


def test_php_header_alone_does_not_claim_wordpress():
    response = versioned_wordpress_response()
    response._content = b"<html>PHP application</html>"

    detected = fingerprint_technologies(response)

    assert "framework" not in detected


@pytest.mark.parametrize(
    ("header", "name", "version"),
    [
        ("Apache/2.4.62", "Apache", "2.4.62"),
        ("nginx/1.27.4", "Nginx", "1.27.4"),
        ("Microsoft-IIS/10.0", "IIS", "10.0"),
    ],
)
def test_fingerprinting_keeps_server_versions(header, name, version):
    response = versioned_wordpress_response()
    response.headers = {"Content-Type": "text/html", "Server": header}

    detected = fingerprint_technologies(response)

    assert detected["_detailed"]["servers"] == [
        {"name": name, "version": version}
    ]


def test_cve_correlation_uses_the_fingerprinted_php_version(monkeypatch):
    response = versioned_wordpress_response()

    class Handler:
        def get(self, _url):
            return response

    def query_cves(_name, version=None):
        if version != "8.5.5":
            return []
        return [
            {
                "cve_id": "CVE-2026-17543",
                "cvss_score": 9.8,
                "confidence": "confirmed",
                "description": "PHP test advisory",
                "references": [],
                "kev": False,
                "kev_date_added": None,
                "epss_score": None,
                "epss_percentile": None,
            }
        ]

    monkeypatch.setattr(cve_correlation, "sqlite_cve_db_available", lambda: True)
    monkeypatch.setattr(cve_correlation, "query_cves", query_cves)

    findings = CVECorrelationPlugin().scan(
        {"url": response.url, "depth": 0},
        Handler(),
    )

    assert [finding.evidence["cve_id"] for finding in findings] == [
        "CVE-2026-17543"
    ]
