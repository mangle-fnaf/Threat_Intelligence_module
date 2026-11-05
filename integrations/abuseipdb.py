import os
import requests

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API key securely (strip removes any stray spaces or quotes)
API_KEY = (os.getenv("ABUSEIPDB_API_KEY") or "").strip().strip('"').strip("'")


def check_abuseipdb(ip):

    ip = str(ip).strip()

    if not ip:
        return {"error": "No IP address provided"}

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }

    try:

        # Send request to AbuseIPDB
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=15
        )


        if response.status_code == 200:

            data = response.json()["data"]

            return {
                "abuse_score": data["abuseConfidenceScore"],
                "country": data["countryCode"],
                "reports": data["totalReports"]
            }

        return {
            "error": f"API Error {response.status_code}: {response.text}"
        }

    except Exception as error:

        return {
            "error": str(error)
        }