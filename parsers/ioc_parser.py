import re
import ipaddress


def detect_ioc_type(ioc):

    # Remove any spaces before or after the input
    ioc = (ioc or "").strip()

    # Check for a valid IP address (each number must be 0-255)
    try:

        ip = ipaddress.ip_address(ioc)

        if ip.version == 4:

            # Private/internal IPs (e.g. 192.168.x.x) aren't looked up
            if not ip.is_global:
                return "Private IPv4"

            return "IPv4"

    except ValueError:
        pass

    # Different patterns used to identify IOC types
    patterns = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA1": r"^[a-fA-F0-9]{40}$",
        "SHA256": r"^[a-fA-F0-9]{64}$",
        "URL": r"^https?://",
        "Domain": r"^(?!:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    }

    # Loop through each pattern and check for a match
    for ioc_type, pattern in patterns.items():

        if re.match(pattern, ioc):
            return ioc_type

    # Return unknown if no pattern matched
    return "Unknown"
