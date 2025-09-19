# edl.py — CLI wrapper for EDL add/remove

import argparse
import requests

def check_edl(apikey: str, ip: str) -> bool:
    url = "http://edlapp01pl.unicph.domain/edl.txt"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        edl_content = set(response.text.splitlines())
        return ip.strip() in edl_content

    except Exception as e:
        print(f"[!] Failed to check EDL for {ip}: {e}")
        return False  # assume not blocked if it fails


def update_edl(apikey, ip, action):
    url = "http://edlapp01pl.unicph.domain/update_edl"
    headers = {
        "Content-Type": "text/plain"
    }

    payload = f"apikey={apikey}&action={action}&data={ip}"
    print(f"[DEBUG] Sending: {payload}")

    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()
        print(f"Successfully {action}ed IP {ip} in EDL.")
        return {
            "success": True,
            "ip": ip,
            "action": action,
            "status_code": response.status_code,
            "response": response.text
        }
    except requests.exceptions.RequestException as e:
        print(f"Failed to {action} IP {ip}: {e}")
        return {
            "success": False,
            "ip": ip,
            "action": action,
            "error": str(e),
            "status_code": getattr(e.response, "status_code", None),
            "response": getattr(e.response, "text", "")
        }


# === CLI entry ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add, remove, or check IPs in EDL.")
    parser.add_argument("--apikey", required=True, help="EDL API token")
    parser.add_argument("--ip", required=True, help="IP address to add/remove/check")
    parser.add_argument("--action", required=True, choices=["add", "remove", "check"], help="Action to perform")

    args = parser.parse_args()

    if args.action == "check":
        result = check_edl(apikey=args.apikey, ip=args.ip)
        print(f"[✓] IP {args.ip} is {'BLOCKED' if result else 'not blocked'} in EDL.")
    else:
        update_edl(apikey=args.apikey, ip=args.ip, action=args.action)

