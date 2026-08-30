from collections.abc import Callable

import requests

from Graph.errors import PipelineStageError
from Graph.reporting import get_logger
from Graph.state import CVEClassifierState


LOGGER = get_logger("nvd")


DEFAULT_TAG_PRIORITIES = { # according to enum at https://github.com/CVEProject/cve-schema/blob/main/schema/tags/reference-tags.json
    "technical-description": 1, "vendor-advisory": 2, "patch": 3, "exploit": 4,
    "third-party-advisory": 5, "government-resource": 6, "issue-tracking": 7,
    "mitigation": 8, "release-notes": 9, "media-coverage": 10, "mailing-list": 11,
    "related": 12, "vdb-entry": 13,
    "broken-link": -1, "customer-entitlement": -1, "not-applicable": -1,
    "permissions-required": -1, "product": -1, "signature": -1
}


def __nvd_resource_reorder(refs: list, weights: dict = None) -> list[str]:
    """
    Filter and reorder NVD references based on tag priority.
    Normalizes tags (e.g., "Vendor Advisory" -> "vendor-advisory") and checks for 
    substrings like "government resource".
    """
    weights = weights or DEFAULT_TAG_PRIORITIES
    ranked_refs = []

    for r in refs:
        # Normalize: lowercase, check for "government resource", replace spaces with hyphens
        tags = r.get("tags", [])
        norm_tags = ["government-resource" if "government resource" in t.lower() 
                     else t.lower().replace(" ", "-") for t in tags]

        scores = [weights.get(t, 99) for t in norm_tags]
        
        # If any tag maps to -1, discard the reference entirely
        if -1 in scores: continue

        # Calculate average rank (default to 99 if no tags present)
        rank = sum(scores) / len(scores) if scores else 99
        ranked_refs.append((rank, r["url"]))

    return [url for _, url in sorted(ranked_refs, key=lambda x: x[0])]


def nvd_caller(
    state: CVEClassifierState,
    *,
    base_url: str,
    timeout_seconds: float,
    request_pacer: Callable[[], None],
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
    LOGGER.debug("NVD retrieval started for %s", cve_id)
    
    try:
        request_pacer()
        resp = requests.get(base_url, params=params, timeout=timeout_seconds)
        resp.raise_for_status()
        data = resp.json()

        vuln = data["vulnerabilities"][0]["cve"]
        description = vuln["descriptions"][0]["value"]
        
        # Filter the refs depending on the tags provided by NIST and rerank the order depending on them
        reranked_refs = __nvd_resource_reorder(vuln.get("references", []))
        LOGGER.debug(
            "NVD retrieval completed for %s: references=%s description_chars=%s",
            cve_id,
            len(reranked_refs),
            len(description),
        )
        
        return {**state, 
                "nvd_description": description,
                "nvd_url_references": reranked_refs}

    except Exception as error:
        raise PipelineStageError(
            stage="nvd",
            cve_id=cve_id,
            error=error,
            safe_message="NVD request or response parsing failed",
        ) from error
