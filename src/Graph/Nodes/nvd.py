from collections.abc import Callable
from typing import Any

import requests

from Definitions.cwe import recorded_cwe_context
from Graph.audit import request_scope
from Graph.errors import PipelineStageError, make_pipeline_warning
from Graph.reporting import get_logger
from Graph.resilience import RetryPolicy, execute_with_retry
from Graph.state import CVEClassifierState
from Graph.url_safety import normalize_http_url


LOGGER = get_logger("nvd")


DEFAULT_TAG_PRIORITIES = { # according to enum at https://github.com/CVEProject/cve-schema/blob/main/schema/tags/reference-tags.json
    "technical-description": 1, "vendor-advisory": 2, "patch": 3, "exploit": 4,
    "third-party-advisory": 5, "government-resource": 6, "issue-tracking": 7,
    "mitigation": 8, "release-notes": 9, "media-coverage": 10, "mailing-list": 11,
    "related": 12, "vdb-entry": 13,
    "broken-link": -1, "customer-entitlement": -1, "not-applicable": -1,
    "permissions-required": -1, "product": -1, "signature": -1
}


def __nvd_resource_reorder(
    refs: list,
    weights: dict | None = None,
) -> tuple[list[str], list[dict[str, str]]]:
    """
    Filter and reorder NVD references based on tag priority.
    Normalizes tags (e.g., "Vendor Advisory" -> "vendor-advisory") and checks for 
    substrings like "government resource".
    """
    weights = weights or DEFAULT_TAG_PRIORITIES
    ranked_refs: list[tuple[float, int, str]] = []
    warnings: list[dict[str, str]] = []

    for index, reference in enumerate(refs):
        try:
            if not isinstance(reference, dict):
                raise TypeError("NVD reference must be an object")
            tags = reference.get("tags", [])
            if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
                raise TypeError("NVD reference tags must be strings")
            url = normalize_http_url(reference.get("url"))
            norm_tags = [
                "government-resource" if "government resource" in tag.lower()
                else tag.lower().replace(" ", "-")
                for tag in tags
            ]

            scores = [weights.get(tag, 99) for tag in norm_tags]
            if -1 in scores:
                continue

            rank = sum(scores) / len(scores) if scores else 99
            ranked_refs.append((rank, index, url))
        except Exception as error:
            warnings.append(
                make_pipeline_warning(
                    stage="nvd",
                    source=f"reference[{index}]",
                    error=error,
                    safe_message="Malformed NVD reference was skipped",
                )
            )

    ordered: list[str] = []
    seen: set[str] = set()
    for _, _, url in sorted(ranked_refs, key=lambda item: (item[0], item[1])):
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    return ordered, warnings


def _parse_nvd_response(data: Any, cve_id: str) -> tuple[str, list[str], list[dict[str, str]]]:
    if not isinstance(data, dict):
        raise TypeError("NVD response must be an object")
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise TypeError("NVD vulnerabilities must be an array")
    matches = []
    for entry in vulnerabilities:
        if not isinstance(entry, dict) or not isinstance(entry.get("cve"), dict):
            continue
        record = entry["cve"]
        if record.get("id") == cve_id:
            matches.append(record)
    if len(matches) != 1:
        raise ValueError("NVD response must contain exactly one matching CVE record")
    record = matches[0]
    descriptions = record.get("descriptions")
    if not isinstance(descriptions, list):
        raise TypeError("NVD descriptions must be an array")
    english = [
        item.get("value").strip()
        for item in descriptions
        if isinstance(item, dict)
        and str(item.get("lang", "")).lower() == "en"
        and isinstance(item.get("value"), str)
        and item["value"].strip()
    ]
    if not english:
        raise ValueError("NVD response has no non-empty English description")
    references = record.get("references", [])
    if not isinstance(references, list):
        raise TypeError("NVD references must be an array")
    urls, warnings = __nvd_resource_reorder(references)
    return english[0], urls, warnings


def nvd_caller(
    state: CVEClassifierState,
    *,
    base_url: str,
    timeout_seconds: float,
    request_pacer: Callable[[], None],
    connect_timeout_seconds: float | None = None,
    retry_policy: RetryPolicy | None = None,
    session: requests.Session | None = None,
    api_key: str | None = None,
) -> CVEClassifierState:
    """
    Retrieves official CVE information from the National Vulnerability Database (NVD) API.

    This function acts as the entry point of the pipeline. It fetches the official 
    vulnerability description and the complete list of external reference URLs 
    associated with the provided CVE ID using the NIST NVD REST API.

    Args:
        state: Current pipeline state containing `cve_id`.
        base_url: Complete NVD CVE API URL.
        timeout_seconds: Timeout for the NVD HTTP request.
        request_pacer: Shared callback invoked before the HTTP attempt.

    Returns:
        The state updated with `nvd_description` and `nvd_url_references`.

    Raises:
        PipelineStageError: If pacing, the request, or response parsing fails.
    """
    cve_id = state["cve_id"]
    params = {"cveId": cve_id}
    warnings = list(state.get("pipeline_warnings", []))
    LOGGER.debug("NVD retrieval started for %s", cve_id)
    
    try:
        requester = session.get if session is not None else requests.get
        headers = {"apiKey": api_key} if api_key else None
        policy = retry_policy or RetryPolicy(max_attempts=1)

        def fetch():
            response = requester(
                base_url,
                params=params,
                headers=headers,
                timeout=(connect_timeout_seconds or timeout_seconds, timeout_seconds),
            )
            response.raise_for_status()
            return response

        with request_scope(stage="nvd", operation="lookup", source=cve_id):
            resp = execute_with_retry(fetch, policy=policy, pacer=request_pacer)
        data = resp.json()
        description, reranked_refs, parsing_warnings = _parse_nvd_response(data, cve_id)
        record = next(e["cve"] for e in data["vulnerabilities"] if e.get("cve", {}).get("id") == cve_id)
        cwe = recorded_cwe_context(record.get("weaknesses", []))
        warnings.extend(parsing_warnings)
        LOGGER.debug(
            "NVD retrieval completed for %s: references=%s description_chars=%s",
            cve_id,
            len(reranked_refs),
            len(description),
        )
        
        return {
            **state,
            "nvd_description": description,
            **cwe,
            **cwe,
            "nvd_url_references": reranked_refs,
            "pipeline_warnings": warnings,
        }

    except Exception as error:
        raise PipelineStageError(
            stage="nvd",
            cve_id=cve_id,
            error=error,
            safe_message="NVD request or response parsing failed",
            partial_state={**state, "pipeline_warnings": warnings},
        ) from error
