"""Limit broad CVE indexes to text around the requested identifier."""

from __future__ import annotations

import re


_CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_MIN_PAGE_CHARS = 50_000
_MIN_DISTINCT_CVES = 100
_CONTEXT_CHARS = 2_000


def focus_broad_cve_reference(text: str, cve_id: str) -> str:
    """Keep target-CVE excerpts only for very large, multi-CVE indexes."""

    if len(text) < _MIN_PAGE_CHARS:
        return text
    matches = list(_CVE_ID_PATTERN.finditer(text))
    if len({match.group().upper() for match in matches}) < _MIN_DISTINCT_CVES:
        return text

    target_matches = [
        match for match in matches if match.group().upper() == cve_id.upper()
    ]
    if not target_matches:
        return text

    spans: list[tuple[int, int]] = []
    for match in target_matches:
        start = max(0, match.start() - _CONTEXT_CHARS)
        end = min(len(text), match.end() + _CONTEXT_CHARS)
        if spans and start <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], end))
        else:
            spans.append((start, end))

    focused = "\n\n...\n\n".join(text[start:end] for start, end in spans)
    return focused if len(focused) < len(text) else text
