import requests
from Graph.state import CVEClassifierState

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

from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

def is_retryable_exception(exception):
    """
    Return True if we should retry.
    Do NOT retry on HTTP 404 (Not Found).
    """
    if isinstance(exception, requests.exceptions.HTTPError):
        if exception.response.status_code == 404:
            return False
    return True

@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(is_retryable_exception),
    reraise=True
)
def fetch_nvd_data(cve_id: str):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    resp = requests.get(url, params=params, timeout=20)
    resp.raise_for_status()
    return resp.json()

def nvd_caller(state: CVEClassifierState) -> CVEClassifierState:
    """
    Retrieves official CVE information from the National Vulnerability Database (NVD) API.
    ...
    """
    print("Contacting NVD API")
    cve_id = state["cve_id"]
    
    try:
        data = fetch_nvd_data(cve_id)

        vuln = data["vulnerabilities"][0]["cve"]
        description = vuln["descriptions"][0]["value"]
        
        # Filter the refs depending on the tags provided by NIST and rerank the order depending on them
        reranked_refs = __nvd_resource_reorder(vuln.get("references", []))
        
        return {**state, 
                "nvd_description": description,
                "nvd_url_references": reranked_refs}

    except Exception as e:
        print(f"Error during nvd_call:\n{e}")
        raise RuntimeError(f"NVD API call failed for {cve_id}: {e}") from e