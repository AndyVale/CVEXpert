import requests
from cvss import CVSS3  # <-- Use CVSS3 now

# =============================
# FULL CVSS 3.x METRIC NAMES
# =============================
METRIC_NAMES = {
    # Base Metrics
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality Impact",
    "I": "Integrity Impact",
    "A": "Availability Impact",

    # Temporal Metrics
    "E": "Exploit Code Maturity",
    "RL": "Remediation Level",
    "RC": "Report Confidence",

    # Environmental Metrics
    "CR": "Confidentiality Requirement",
    "IR": "Integrity Requirement",
    "AR": "Availability Requirement",
    "MAV": "Modified Attack Vector",
    "MAC": "Modified Attack Complexity",
    "MPR": "Modified Privileges Required",
    "MUI": "Modified User Interaction",
    "MS": "Modified Scope",
    "MC": "Modified Confidentiality",
    "MI": "Modified Integrity",
    "MA": "Modified Availability",
}

# =============================
# FULL CVSS 3.x VALUE LABELS
# =============================
VALUE_LABELS = {
    # Base Metrics
    "AV": {"N": "Network", "A": "Adjacent Network", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},

    # Temporal
    "E": {"X": "Not Defined", "U": "Unproven", "P": "Proof-of-Concept", "F": "Functional", "H": "High"},
    "RL": {"X": "Not Defined", "O": "Official Fix", "T": "Temporary Fix", "W": "Workaround", "U": "Unavailable"},
    "RC": {"X": "Not Defined", "U": "Unknown", "R": "Reasonable", "C": "Confirmed"},

    # Environmental Requirements
    "CR": {"H": "High", "M": "Medium", "L": "Low", "X": "Not Defined"},
    "IR": {"H": "High", "M": "Medium", "L": "Low", "X": "Not Defined"},
    "AR": {"H": "High", "M": "Medium", "L": "Low", "X": "Not Defined"},

    # Modified Base Metrics (same as Base)
    "MAV": {"N": "Network", "A": "Adjacent Network", "L": "Local", "P": "Physical", "X": "Not Defined"},
    "MAC": {"L": "Low", "H": "High", "X": "Not Defined"},
    "MPR": {"N": "None", "L": "Low", "H": "High", "X": "Not Defined"},
    "MUI": {"N": "None", "R": "Required", "X": "Not Defined"},
    "MS": {"U": "Unchanged", "C": "Changed", "X": "Not Defined"},
    "MC": {"H": "High", "L": "Low", "N": "None", "X": "Not Defined"},
    "MI": {"H": "High", "L": "Low", "N": "None", "X": "Not Defined"},
    "MA": {"H": "High", "L": "Low", "N": "None", "X": "Not Defined"},
}

# =============================
# Convert raw metrics to human-readable
# =============================
def humanize_metrics(raw):
    out = {}
    for k, v in raw.items():
        name = METRIC_NAMES.get(k, k)
        val = VALUE_LABELS.get(k, {}).get(v, v)
        out[name] = val
    return out

# =============================
# Fetch CVSS3 vector and human-readable metrics
# =============================
def get_cvss_vector_and_labels(cve_id: str):
    resp = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id},
        timeout=20
    )
    resp.raise_for_status()

    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        raise ValueError("No CVE data returned")

    metrics = vulns[0]['cve'].get("metrics", {})
    vector = None

    # CVSS 3.x metrics can be v30 or v31
    for ver in ("cvssMetricV31", "cvssMetricV30"):
        if ver in metrics:
            vector = metrics[ver][0]['cvssData']['vectorString']
            break

    if not vector:
        raise ValueError("No CVSS3 vector found")

    cv = CVSS3(vector)
    raw_metrics = cv.metrics
    human_metrics = humanize_metrics(raw_metrics)

    return {
        "vector": vector,
        "raw_metrics": raw_metrics,
        "human_metrics": human_metrics,
        #"score": cv.base_score,
        #"severity": cv.severities,
    }

# =============================
# Example usage
# =============================
if __name__ == "__main__":
    cve = "CVE-2025-24472"
    r = get_cvss_vector_and_labels(cve)
    print(r)

