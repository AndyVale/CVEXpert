import requests
from Graph.state import CVEClassifierState

def nvd_caller(state: CVEClassifierState):
    cve_id = state["cve_id"]
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    resp = requests.get(url, params=params, timeout=20)

    if resp.status_code != 200:
        return {**state, "references": [f"Error calling NVD API: {resp.text}"]}

    data = resp.json()

    try:
        vuln = data["vulnerabilities"][0]["cve"]
        description = vuln["descriptions"][0]["value"]
        refs = [ref.get("url") for ref in vuln.get("references", [])]
        return {**state, "references": [description] + refs}

    except Exception as e:
        return {**state, "references": [f"Parsing error: {e}"]}