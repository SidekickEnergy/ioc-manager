import requests
import os

def query_abuseipdb(ip, api_key=None, verbose=False):
    api_key = (api_key or os.getenv("ABUSEIPDB_API_KEY") or "").strip()
    if not api_key:
        return {"error": "missing_abuseipdb_api_key"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": verbose
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})

        return {
            "ip": data.get("ipAddress"),
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
            "categories": data.get("usageType")
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


# Optional CLI testing support
if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Query AbuseIPDB for IP reputation")
    parser.add_argument("ip", help="IPv4 address to check")
    args = parser.parse_args()

    result = query_abuseipdb(args.ip, verbose=True)
    if result:
        print("\n[AbuseIPDB Result]")
        print(json.dumps(result, indent=2))
    else:
        print("No data returned.")

