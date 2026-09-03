"""
Drive IDOR / BOLA checks for a single URL under a shared request budget.

Principal selection, strongest first:
  * a configured secondary identity  -> "secondary"
  * authenticated baseline, replay with no session -> "anonymous"
  * otherwise the same identity walks its own id space -> "self" (heuristic)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Callable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from scanner.access_control.comparison import idor_verdict, summarize
from scanner.access_control.identifiers import find_id_locations, mutation_values


@dataclass
class AccessControlContext:
    primary_get: Callable[[str], object]
    primary_authenticated: bool = False
    secondary_get: Optional[Callable[[str], object]] = None
    anonymous_get: Optional[Callable[[str], object]] = None
    per_location_mutations: int = 4
    budget: int = 150
    _used: int = field(default=0, init=False)
    _lock: Lock = field(default_factory=Lock, init=False)

    def take(self) -> bool:
        with self._lock:
            if self._used >= self.budget:
                return False
            self._used += 1
            return True

    def principal(self):
        if self.secondary_get is not None:
            return "secondary", self.secondary_get
        if self.primary_authenticated and self.anonymous_get is not None:
            return "anonymous", self.anonymous_get
        return "self", self.primary_get


def _apply_mutation(url: str, location, new_value: str) -> str:
    parsed = urlparse(url)
    if location.where == "query":
        pairs = [
            (name, new_value if name == location.name else value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunparse(parsed._replace(query=urlencode(pairs)))

    segments = parsed.path.split("/")
    non_empty = [i for i, seg in enumerate(segments) if seg]
    if location.index is None or location.index >= len(non_empty):
        return url
    segments[non_empty[location.index]] = new_value
    return urlunparse(parsed._replace(path="/".join(segments)))


def scan_url_for_idor(
    ctx: AccessControlContext,
    url: str,
    params=None,
    harvested=None,
) -> List[dict]:
    findings: List[dict] = []

    locations = find_id_locations(url, params)
    if not locations or not ctx.take():
        return findings

    baseline = summarize(ctx.primary_get(url))
    if baseline is None or baseline.status != 200 or baseline.denied:
        return findings

    principal, get = ctx.principal()

    for location in locations:
        for value in mutation_values(location, harvested)[: ctx.per_location_mutations]:
            if not ctx.take():
                return findings
            tested_url = _apply_mutation(url, location, value)
            if tested_url == url:
                continue
            verdict = idor_verdict(baseline, summarize(get(tested_url)), principal=principal)
            if verdict:
                verdict.update(
                    {
                        "url": url,
                        "tested_url": tested_url,
                        "location": location.where,
                        "parameter": location.name,
                        "original_value": location.value,
                        "mutated_value": value,
                        "id_kind": location.kind,
                    }
                )
                findings.append(verdict)
                break

    return findings
