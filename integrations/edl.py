# app/integrations/edl.py

import argparse
import requests

def _norm(base_url: str) -> str:
    base_url = (base_url or "").strip()
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("EDL base_url must start with http:// or https://")
    return base_url.rstrip("/")

def check_edl(apikey: str, ip: str, base_url: str) -> bool:
    """
    Check if IP exists in EDL. Uses `${base_url}/edl.txt`.
    """
    url = f"{_norm(base_url)}/edl.txt"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        edl_content = set(resp.text.splitlines())
        return ip.strip() in edl_content
    except Exception as e:
        print(f"[!] Failed to check EDL for {ip}: {e}")
        return False  # assume not blocked if it fails

def update_edl(apikey: str, ip: str, action: str, base_url: str):
    """
    Update EDL via `${base_url}/update_edl`.
    action ∈ {"add","remove"}.
    """
    url = f"{_norm(base_url)}/update_edl"
    headers = {"Content-Type": "text/plain"}
    payload = f"apikey={apikey}&action={action}&data={ip}"
    print(f"[DEBUG] Sending: {payload}")

    try:
        resp = requests.post(url, headers=headers, data=payload, timeout=10)
        resp.raise_for_status()
        print(f"Successfully {action}ed IP {ip} in EDL.")
        return {"success": True, "ip": ip, "action": action,
                "status_code": resp.status_code, "response": resp.text}
    except requests.exceptions.RequestException as e:
        print(f"Failed to {action} IP {ip}: {e}")
        return {"success": False, "ip": ip, "action": action,
                "error": str(e),
                "status_code": getattr(e.response, "status_code", None),
                "response": getattr(e.response, "text", "")}

# === CLI (optional) ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add, remove, or check IPs in EDL.")
    parser.add_argument("--base-url", required=True, help="EDL base URL, e.g. https://edl.example.com")
    parser.add_argument("--apikey", required=True, help="EDL API token")
    parser.add_argument("--ip", required=True, help="IP address to add/remove/check")
    parser.add_argument("--action", required=True, choices=["add", "remove", "check"], help="Action to perform")
    args = parser.parse_args()

    if args.action == "check":
        blocked = check_edl(apikey=args.apikey, ip=args.ip, base_url=args.base_url)
        print(f"[✓] IP {args.ip} is {'BLOCKED' if blocked else 'not blocked'} in EDL.")
    else:
        print(update_edl(apikey=args.apikey, ip=args.ip, action=args.action, base_url=args.base_url))
