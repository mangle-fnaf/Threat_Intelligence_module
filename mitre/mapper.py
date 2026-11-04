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

    if vt_result and vt_result["malicious"] >= 1:

        techniques.append({
            "id": "T1071",
            "name": "Application Layer Protocol"
        })

    if abuse_result and abuse_result["abuse_score"] >= 50:

        techniques.append({
            "id": "T1110",
            "name": "Brute Force"
        })

    if abuse_result and abuse_result["reports"] >= 100:

        techniques.append({
            "id": "T1595",
            "name": "Active Scanning"
        })

    return techniques