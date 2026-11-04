# Map threat intelligence findings to MITRE ATT&CK techniques
# Techniques are only added when there is real evidence of malicious activity,
# using the same thresholds as the risk engine so the two always agree.
def map_to_mitre(vt_result, abuse_result):

    techniques = []

    # Ignore any source whose lookup failed
    vt_ok = vt_result and "error" not in vt_result
    abuse_ok = abuse_result and "error" not in abuse_result

    malicious = vt_result.get("malicious", 0) if vt_ok else 0
    abuse_score = abuse_result.get("abuse_score", 0) if abuse_ok else 0
    reports = abuse_result.get("reports", 0) if abuse_ok else 0

    # Several security vendors flag it as malicious
    # (1-2 flags out of ~90 is usually a false positive)
    if malicious >= 5:

        techniques.append({
            "id": "T1071",
            "name": "Application Layer Protocol"
        })

    # AbuseIPDB is confident the IP is abusive
    if abuse_score >= 50:

        techniques.append({
            "id": "T1110",
            "name": "Brute Force"
        })

    # Widely reported AND AbuseIPDB agrees it's abusive
    # (popular safe IPs like 8.8.8.8 collect mistaken reports)
    if reports >= 100 and abuse_score >= 25:

        techniques.append({
            "id": "T1595",
            "name": "Active Scanning"
        })

    return techniques