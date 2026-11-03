def calculate_risk_score(vt_result, abuse_result):

    score = 0

    # VirusTotal detections
    if vt_result:

        if vt_result["malicious"] > 0:
            score += 30

        if vt_result["suspicious"] > 0:
            score += 15

        if vt_result["reputation"] > 100:
            score += 10

    # AbuseIPDB results
    if abuse_result:

        if abuse_result["abuse_score"] >= 75:
            score += 40

        elif abuse_result["abuse_score"] >= 50:
            score += 25

        elif abuse_result["abuse_score"] >= 25:
            score += 10

        if abuse_result["reports"] >= 100:
            score += 20

    # Determine severity
    if score >= 80:
        severity = "CRITICAL"

    elif score >= 60:
        severity = "HIGH"

    elif score >= 30:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return {
        "risk_score": score,
        "severity": severity
    }