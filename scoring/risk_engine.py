def calculate_risk_score(vt_result, abuse_result):

    score = 0

    # VirusTotal detections
    # (skipped if the lookup failed and returned an error instead)
    if vt_result and "error" not in vt_result:

        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        reputation = vt_result.get("reputation", 0)

        # More vendors flagging it = more risk.
        # 1-2 flags out of ~90 vendors is often a false positive.
        if malicious >= 10:
            score += 40
        elif malicious >= 5:
            score += 30
        elif malicious >= 3:
            score += 15
        elif malicious >= 1:
            score += 5

        if suspicious >= 3:
            score += 10

        # Community reputation: negative = voted bad, positive = voted good
        if reputation < 0:
            score += 10
        elif reputation > 100:
            score -= 10

    # AbuseIPDB results
    if abuse_result and "error" not in abuse_result:

        abuse_score = abuse_result.get("abuse_score", 0)
        reports = abuse_result.get("reports", 0)

        if abuse_score >= 75:
            score += 40
        elif abuse_score >= 50:
            score += 25
        elif abuse_score >= 25:
            score += 10

        # Only count report volume when AbuseIPDB also thinks it's abusive,
        # since popular IPs (like 8.8.8.8) collect mistaken reports
        if reports >= 100 and abuse_score >= 25:
            score += 20

    # Keep the score between 0 and 100
    score = max(0, min(score, 100))

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