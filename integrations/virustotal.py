import os
import requests

from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

# Get API key securely
API_KEY = os.getenv("VT_API_KEY")


def check_virustotal_ip(ip):

    # VirusTotal endpoint for IP lookups
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": API_KEY
    }

    try:

        # Send request to VirusTotal
        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:

            data = response.json()

            # Extract analysis statistics
            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "reputation": data["data"]["attributes"].get(
                    "reputation",
                    0
                ),
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "harmless": stats["harmless"]
            }

        return {
            "error": f"API Error: {response.status_code}"
        }

    except Exception as error:

        return {
            "error": str(error)
        }