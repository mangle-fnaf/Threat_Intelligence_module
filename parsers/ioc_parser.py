import re


def detect_ioc_type(ioc):

    # Different patterns used to identify IOC types
    patterns = {
        "IPv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
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