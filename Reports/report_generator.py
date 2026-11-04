# Generate HTML intelligence report
def generate_report(
    ioc,
    vt_result,
    abuse_result,
    risk_result,
    mitre_result
):

    html = f"""
    <html>

    <head>

        <title>Threat Intelligence Report</title>

    </head>

    <body>

        <h1>Threat Intelligence Report</h1>

        <h2>Indicator</h2>

        <p>{ioc}</p>

        <h2>VirusTotal</h2>

        <p>Reputation: {vt_result['reputation']}</p>
        <p>Malicious: {vt_result['malicious']}</p>

        <h2>AbuseIPDB</h2>

        <p>Abuse Score: {abuse_result['abuse_score']}</p>
        <p>Reports: {abuse_result['reports']}</p>

        <h2>Risk Assessment</h2>

        <p>Risk Score: {risk_result['risk_score']}</p>

        <p>Severity: {risk_result['severity']}</p>

        <h2>MITRE ATT&CK</h2>

        <ul>
    """

    for technique in mitre_result:

        html += (
            f"<li>{technique['id']} - "
            f"{technique['name']}</li>"
        )

    html += """

        </ul>

    </body>

    </html>
    """

    return html