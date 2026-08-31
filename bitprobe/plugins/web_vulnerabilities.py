import re
import secrets
from typing import Dict, List
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from plugins.base_plugin import BasePlugin, Finding


SQL_ERRORS = [
    re.compile(pattern, re.I)
    for pattern in (
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"postgresql.*error",
        r"sqlite(?:3)?(?:.|\s)*error",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"ora-\d{5}",
    )
]
MAX_PARAMETERS = 6


def _form_values(form) -> Dict[str, str]:
    values = {}
    for control in form.find_all(["input", "select", "textarea"]):
        name = control.get("name")
        if not name or control.has_attr("disabled"):
            continue
        if control.name == "input":
            if control.get("type", "text").lower() in {
                "submit",
                "button",
                "file",
                "password",
                "reset",
                "image",
            }:
                continue
            values[name] = control.get("value", "")
        elif control.name == "textarea":
            values[name] = control.get_text()
        else:
            option = control.find("option", selected=True) or control.find("option")
            values[name] = option.get("value", option.get_text()) if option else ""
    return values


def discover_get_targets(url: str, html: str) -> List[tuple[str, Dict[str, str]]]:
    parsed = urlparse(url)
    origin = (parsed.scheme.lower(), parsed.netloc.lower())
    targets = []
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if query:
        endpoint = urlunparse(parsed._replace(query="", fragment=""))
        targets.append((endpoint, query))

    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        if form.get("method", "get").lower() != "get":
            continue
        action = urljoin(url, form.get("action") or url)
        action_parsed = urlparse(action)
        if (action_parsed.scheme.lower(), action_parsed.netloc.lower()) != origin:
            continue
        values = dict(parse_qsl(action_parsed.query, keep_blank_values=True))
        values.update(_form_values(form))
        if not values:
            continue
        endpoint = urlunparse(action_parsed._replace(query="", fragment=""))
        target = (endpoint, values)
        if target not in targets:
            targets.append(target)
    return targets


class WebVulnerabilitiesPlugin(BasePlugin):
    def get_name(self) -> str:
        return "web_vulnerabilities"

    def get_description(self) -> str:
        return "Safe active checks for common GET parameter vulnerabilities"

    def _probe(self, handler, endpoint, params, parameter, payload):
        mutated = params.copy()
        mutated[parameter] = payload
        return handler.get(endpoint, params=mutated, allow_redirects=False)

    def _finding(self, title, severity, endpoint, parameter, payload, reason, response):
        return Finding(
            plugin_name=self.get_name(),
            severity=severity,
            title=f"{title} in parameter '{parameter}'",
            description=f"The GET parameter '{parameter}' is vulnerable to {title.lower()}.",
            url=endpoint,
            evidence={
                "method": "GET",
                "parameter": parameter,
                "payload": payload,
                "status_code": response.status_code,
                "reason": reason[:500],
            },
            remediation=(
                "Validate input against an allowlist, use context-appropriate output encoding, "
                "and use parameterized APIs instead of constructing commands or queries."
            ),
        )

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        page_url = url_info["url"]
        page = url_info.get("response")
        if page is None:
            page = request_handler.get(page_url)
        if page is None or "text/html" not in page.headers.get("Content-Type", "").lower():
            return []

        findings = []
        tested = 0
        for endpoint, params in discover_get_targets(page_url, page.text):
            baseline = request_handler.get(
                endpoint,
                params=params,
                allow_redirects=False,
            )
            if baseline is None:
                continue
            baseline_text = baseline.text
            baseline_sql = {
                pattern.pattern
                for pattern in SQL_ERRORS
                if pattern.search(baseline_text)
            }

            for parameter in params:
                if tested >= MAX_PARAMETERS:
                    return findings
                tested += 1
                original = params[parameter]

                token = f"bitsentryxss{secrets.token_hex(4)}"
                xss_payload = f'\"><bitsentry-probe data-token="{token}">'
                probe = self._probe(
                    request_handler,
                    endpoint,
                    params,
                    parameter,
                    xss_payload,
                )
                if probe is not None and token not in baseline_text:
                    tag = BeautifulSoup(probe.text, "html.parser").find(
                        "bitsentry-probe",
                        attrs={"data-token": token},
                    )
                    if tag is not None:
                        findings.append(
                            self._finding(
                                "Reflected XSS",
                                "high",
                                endpoint,
                                parameter,
                                xss_payload,
                                f"Injected HTML element {tag.name} was parsed in the response",
                                probe,
                            )
                        )

                sql_payload = f"{original}'"
                probe = self._probe(
                    request_handler,
                    endpoint,
                    params,
                    parameter,
                    sql_payload,
                )
                if probe is not None:
                    new_errors = [
                        pattern.pattern
                        for pattern in SQL_ERRORS
                        if pattern.pattern not in baseline_sql and pattern.search(probe.text)
                    ]
                    if new_errors:
                        findings.append(
                            self._finding(
                                "SQL Injection Error",
                                "high",
                                endpoint,
                                parameter,
                                sql_payload,
                                f"New database error signature: {new_errors[0]}",
                                probe,
                            )
                        )

                traversal_payloads = (
                    ("../../../../../../etc/passwd", "root:x:0:0"),
                    (r"..\..\..\..\windows\win.ini", "[fonts]"),
                )
                for payload, signature in traversal_payloads:
                    probe = self._probe(
                        request_handler,
                        endpoint,
                        params,
                        parameter,
                        payload,
                    )
                    if (
                        probe is not None
                        and signature.lower() not in baseline_text.lower()
                        and signature.lower() in probe.text.lower()
                    ):
                        findings.append(
                            self._finding(
                                "Path Traversal",
                                "high",
                                endpoint,
                                parameter,
                                payload,
                                f"File signature found: {signature}",
                                probe,
                            )
                        )
                        break

                redirect_token = secrets.token_hex(4)
                destination = f"https://example.com/bitsentry-redirect-{redirect_token}"
                probe = self._probe(
                    request_handler,
                    endpoint,
                    params,
                    parameter,
                    destination,
                )
                if (
                    probe is not None
                    and 300 <= probe.status_code < 400
                    and probe.headers.get("Location") == destination
                ):
                    findings.append(
                        self._finding(
                            "Open Redirect",
                            "medium",
                            endpoint,
                            parameter,
                            destination,
                            f"Location header redirects to {destination}",
                            probe,
                        )
                    )

        return findings
