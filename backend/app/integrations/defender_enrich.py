# integrations/defender_enrich.py

import requests, os, sys, json
from typing import List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.defender_auth import get_defender_token

BASE_URL = "https://api.security.microsoft.com"


def build_kql_for_ioc(ioc: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        return f'DeviceNetworkEvents | where RemoteIP == "{ioc}" | top 50 by Timestamp desc'
    elif ioc_type in ["sha1", "sha256", "md5"]:
        return f'DeviceFileEvents | where SHA256 == "{ioc}" or SHA1 == "{ioc}" or MD5 == "{ioc}" | top 50 by Timestamp desc'
    else:
        return f'DeviceNetworkEvents | where RemoteUrl contains "{ioc}" | top 50 by Timestamp desc'


def post_kql(kql: str) -> dict:
    token = get_defender_token()
    if not token:
        return {"error": "Auth failed"}

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{BASE_URL}/api/advancedhunting/run"
    try:
        resp = requests.post(url, headers=headers, json={"Query": kql})
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        return {
            "error": str(e),
            "raw": getattr(e.response, "text", ""),
            "query": kql
        }


def query_advanced_hunting(ioc: str, ioc_type: str) -> dict:
    kql = build_kql_for_ioc(ioc, ioc_type)
    return {"advanced_hunting": post_kql(kql)}


def query_alerts_from_hunting(ioc_list: List[str], days: int = 30) -> dict:
    arr = json.dumps(ioc_list)
    kql = f"""
let ioc_list = dynamic({arr});
AlertEvidence
| where TimeGenerated > ago({days}d)
| where RemoteIP in (ioc_list)
    or RemoteUrl has_any(ioc_list)
    or AdditionalFields has_any(ioc_list)
| extend AlertLink = strcat("https://security.microsoft.com/alerts/", AlertId)
| project TimeGenerated, AlertId, Title, DeviceName, RemoteIP, RemoteUrl, Severity, AlertLink
| sort by TimeGenerated desc
"""
    return {"hunting_alerts": post_kql(kql)}


def smart_hunting_check(ioc: str, ioc_type: str) -> bool:
    """Try multiple hunting queries to increase chances of a match."""
    token = get_defender_token()
    if not token:
        return False

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{BASE_URL}/api/advancedhunting/run"

    queries = []

    if ioc_type in ["ip", "ipv4", "ipv6"]:
        queries.append(f'DeviceNetworkEvents | where RemoteIP == "{ioc}" | take 5')
        queries.append(f'DeviceEvents | where AdditionalFields has "{ioc}" | take 5')

    elif ioc_type in ["domain", "hostname"]:
        queries.append(f'DeviceNetworkEvents | where RemoteUrl contains "{ioc}" | take 5')

    elif ioc_type in ["sha1", "sha256", "md5"]:
        queries.append(f'DeviceFileEvents | where SHA256 == "{ioc}" or SHA1 == "{ioc}" or MD5 == "{ioc}" | take 5')

    for kql in queries:
        try:
            resp = requests.post(url, headers=headers, json={"Query": kql})
            resp.raise_for_status()
            result = resp.json()
            if result.get("Results"):
                return True
        except Exception:
            continue

    return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("ioc")
    parser.add_argument("--type", default="ip")
    parser.add_argument("--mode", choices=["hunting", "alert-hunting", "smart"], default="hunting")
    args = parser.parse_args()

    if args.mode == "hunting":
        result = query_advanced_hunting(args.ioc, args.type)
    elif args.mode == "alert-hunting":
        result = query_alerts_from_hunting([args.ioc])
    elif args.mode == "smart":
        found = smart_hunting_check(args.ioc, args.type)
        result = {"smart_hunting_match": found}
    else:
        result = {"error": "Unknown mode"}

    print(json.dumps(result, indent=2))
