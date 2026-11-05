# Store dashboard statistics
dashboard_stats = {
    "total_iocs": 0,
    "high_risk_iocs": 0,
    "average_risk_score": 0,
    "risk_scores": []
}


def update_statistics(risk_score):

    dashboard_stats["total_iocs"] += 1

    dashboard_stats["risk_scores"].append(
        risk_score
    )

    if risk_score >= 60:
        dashboard_stats["high_risk_iocs"] += 1

    dashboard_stats["average_risk_score"] = round(
        sum(dashboard_stats["risk_scores"])
        / len(dashboard_stats["risk_scores"]),
        2
    )

    return dashboard_stats