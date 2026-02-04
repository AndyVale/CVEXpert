import requests
from Graph.state import CVEClassifierState

def nvd_caller(state: CVEClassifierState) -> CVEClassifierState:
    """
    Retrieves official CVE information from the National Vulnerability Database (NVD) API.

    This function acts as the entry point of the pipeline. It fetches the official 
    vulnerability description and the complete list of external reference URLs 
    associated with the provided CVE ID using the NIST NVD REST API.

    Args:
        state (CVEClassifierState): The current pipeline state containing 'cve_id'.

    Returns:
        CVEClassifierState: The state updated with 'nvd_description' and 
            'nvd_url_references' extracted from the API response.
    Raises:
        requests.exceptions.HTTPError: If the NVD API request fails (status code != 200).
    """
    cve_id = state["cve_id"]
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    resp = requests.get(url, params=params, timeout=20)

    resp.raise_for_status()

    data = resp.json()

    try:
        vuln = data["vulnerabilities"][0]["cve"]
        description = vuln["descriptions"][0]["value"]
        refs = [ref.get("url") for ref in vuln.get("references", [])]
        return {**state, 
                "nvd_description": description,
                "nvd_url_references": refs}

    except Exception as e:
        print(f"Error during nvd_call:\n{e}")
        return {**state,
                "nvd_description": "No description found",
                "nvd_url_references": [],}