from flask import Flask, render_template, request

from parsers.ioc_parser import detect_ioc_type
from integrations.virustotal import check_virustotal_ip
from integrations.abuseipdb import check_abuseipdb
from scoring.risk_engine import calculate_risk_score

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    # Store values for displaying results
    result = None
    vt_result = None
    abuse_result = None
    risk_result = None
    ioc = None

    # Run analysis when form is submitted
    if request.method == "POST":

        ioc = request.form.get("ioc")

        # Detect IOC type
        result = detect_ioc_type(ioc)

        # Only lookup IP addresses for now
        if result == "IPv4":

            vt_result = check_virustotal_ip(ioc)

            abuse_result = check_abuseipdb(ioc)

            # Calculate overall risk score
            risk_result = calculate_risk_score(
                vt_result,
                abuse_result
            )

    return render_template(
        "index.html",
        result=result,
        ioc=ioc,
        vt_result=vt_result,
        abuse_result=abuse_result,
        risk_result=risk_result
    )


if __name__ == "__main__":
    # Start Flask application
    app.run(debug=True)