# Map threat intelligence findings to MITRE ATT&CK techniques
def map_to_mitre(
    vt_result,
    abuse_result,
    risk_result
):

    techniques = []

    # Skip mapping for low-risk indicators
    if risk_result["severity"] == "LOW":
        return techniques

    # Ignore any source whose lookup failed and returned an error instead
    if not vt_result or "error" in vt_result:
        vt_result = {}

    if not abuse_result or "error" in abuse_result:
        abuse_result = {}

    if vt_result.get("malicious", 0) >= 1:

        techniques.append({
            "id": "T1071",
            "name": "Application Layer Protocol"
        })

    if abuse_result.get("abuse_score", 0) >= 50:

        techniques.append({
            "id": "T1110",
            "name": "Brute Force"
        })

    if abuse_result.get("reports", 0) >= 100:

        techniques.append({
            "id": "T1595",
            "name": "Active Scanning"
        })

    return techniques