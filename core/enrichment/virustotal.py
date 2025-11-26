# core/enrichment/virustotal.py

import re
import time
import base64
import requests
import argparse

VT_API_BASE = "https://www.virustotal.com/api/v3"

VT_ENDPOINTS = {
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
    "md5": "files",
    "sha1": "files",
    "sha256": "files"
}

def normalize_type_for_vt(ioc_type):
    if ioc_type in ("ipv4", "ipv6"):
        return "ip"
    elif ioc_type == "hostname":
        return "domain"
    return ioc_type

def generate_vt_url(ioc_value, ioc_type):
    if ioc_type in ("ipv4", "ipv6", "ip"):
        return f"https://www.virustotal.com/gui/ip-address/{ioc_value}"
    elif ioc_type in ("domain", "hostname"):
        return f"https://www.virustotal.com/gui/domain/{ioc_value}"
    elif ioc_type == "url":
        encoded = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
        return f"https://www.virustotal.com/gui/url/{encoded}"
    elif ioc_type in ("md5", "sha1", "sha256"):
        return f"https://www.virustotal.com/gui/file/{ioc_value}"
    return None

def lookup_virustotal(ioc_value, ioc_type, api_key):
    if not api_key:
        return {"error": "missing_api_key"}

    normalized_type = normalize_type_for_vt(ioc_type)
    endpoint = VT_ENDPOINTS.get(normalized_type)
    if not endpoint:
        return {"error": f"Unsupported IoC type for VirusTotal: {ioc_type}"}

    headers = {
        "Accept": "application/json",
        "x-apikey": api_key
    }

    vt_gui_url = generate_vt_url(ioc_value, ioc_type)

    if normalized_type == "url":
        ioc_value = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")

    url = f"{VT_API_BASE}/{endpoint}/{ioc_value}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return {
                "found": False,
                "message": "Not found on VirusTotal",
                "vt_link": vt_gui_url
            }

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})

        result = {
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "reputation": attributes.get("reputation"),
            "tags": attributes.get("tags", []),
            "whois": attributes.get("whois") if normalized_type == "domain" else None,
            "as_owner": attributes.get("as_owner") if normalized_type == "ip" else None,
            "last_analysis_date": time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.gmtime(attributes.get("last_analysis_date", 0))
            ),
            "vt_link": vt_gui_url
        }

        return {k: v for k, v in result.items() if v is not None}

    except requests.RequestException as e:
        return {
            "error": "lookup_failed",
            "detail": str(e),
            "vt_link": vt_gui_url
        }

# === CLI TESTING SUPPORT ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test VirusTotal lookup from CLI")
    parser.add_argument("ioc", help="The IoC value to look up (IP, domain, hash, or URL)")
    parser.add_argument("type", help="The type of the IoC (ip, domain, url, md5, sha1, sha256, hostname, ipv6)")
    parser.add_argument("--apikey", help="Your VirusTotal API key (required)")

    args = parser.parse_args()

    result = lookup_virustotal(args.ioc, args.type, api_key=args.apikey)
    import json
    print(json.dumps(result, indent=2))
