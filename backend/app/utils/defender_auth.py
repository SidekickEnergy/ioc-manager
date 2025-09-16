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
    # Try environment variables first
    tenant_id = os.environ.get("DEFENDER_TENANT_ID")
    client_id = os.environ.get("DEFENDER_CLIENT_ID")
    client_secret = os.environ.get("DEFENDER_CLIENT_SECRET")
    scope = os.environ.get("DEFENDER_SCOPE", "https://api.security.microsoft.com/.default")

    # If any value is missing, fallback to config.yaml
    if not all([tenant_id, client_id, client_secret]):
        try:
            config = load_config()
            tenant_id = tenant_id or config["defender"]["tenant_id"]
            client_id = client_id or config["defender"]["client_id"]
            client_secret = client_secret or config["defender"]["client_secret"]
            scope = scope or config["defender"].get("scope", "https://api.security.microsoft.com/.default")
        except Exception as e:
            print(f"[!] Failed to load Defender config: {e}")
            return None

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    payload = {
        "client_id": client_id,
        "scope": scope,
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
