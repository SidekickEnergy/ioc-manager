import requests
import os

def load_abuseipdb_key():
    # Load API key from environment variable
    return os.environ.get("ABUSEIPDB_API_KEY") or "950413a64d68ca802ff84f722b6d9044287b7a6362238c2ba38812f24f84a66ca3ef3785a836f12f"

def query_abuseipdb(ip, verbose=False):
    api_key = load_abuseipdb_key()
    if not api_key:
        raise ValueError("Missing ABUSEIPDB_API_KEY environment variable")

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
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()["data"]

        result = {
            "ip": data.get("ipAddress"),
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
            "categories": data.get("usageType")
        }

        return result

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] AbuseIPDB query failed: {e}")
        return None

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

