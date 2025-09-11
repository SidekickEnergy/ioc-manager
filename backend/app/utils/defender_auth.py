# backend/app/utils/defender_auth.py

import os
import requests
import yaml


def load_config():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    config_path = os.path.join(project_root, "config.yaml")

    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def get_defender_token():
    config = load_config()
    tenant_id = config["defender"]["tenant_id"]
    client_id = config["defender"]["client_id"]
    client_secret = config["defender"]["client_secret"]

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    payload = {
        "client_id": client_id,
        "scope": "https://api.security.microsoft.com/.default", # "scope": "https://graph.microsoft.com/.default",   ✅ Microsoft Graph!
        "client_secret": client_secret,
        "grant_type": "client_credentials"
    }

    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        return response.json().get("access_token")
    except Exception as e:
        print(f"[!] Failed to get token: {e}")
        return None


if __name__ == "__main__":
    token = get_defender_token()
    if token:
        print("[+] Access token retrieved successfully.")
        print(token)
    else:
        print("[!] Failed to retrieve token.")
