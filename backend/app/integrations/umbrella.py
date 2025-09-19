import os
import requests
import json
from datetime import datetime, timezone
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth

# === Configuration ===
TOKEN_URL = 'https://api.umbrella.com/auth/v2/token'


def format_timestamp(ts):
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return "N/A"


class UmbrellaAPI:
    def __init__(self, token_url, client_id, client_secret):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None

    def get_token(self):
        auth = HTTPBasicAuth(self.client_id, self.client_secret)
        client = BackendApplicationClient(client_id=self.client_id)
        oauth = OAuth2Session(client=client)
        self.token = oauth.fetch_token(token_url=self.token_url, auth=auth)
        return self.token

    def req_get(self, endpoint):
        if self.token is None:
            self.get_token()
        bearer_token = "Bearer " + self.token['access_token']
        headers = {
            "Authorization": bearer_token,
            "Content-Type": "application/json"
        }
        resp = requests.get(f'https://api.umbrella.com/{endpoint}', headers=headers)
        resp.raise_for_status()
        return resp

    def req_post(self, endpoint, payload):
        if self.token is None:
            self.get_token()
        bearer_token = "Bearer " + self.token['access_token']
        headers = {
            "Authorization": bearer_token,
            "Content-Type": "application/json"
        }
        resp = requests.post(f'https://api.umbrella.com/{endpoint}', headers=headers, json=payload)
        resp.raise_for_status()
        return resp

    def get_destination_list_metadata(self, dest_list_id):
        endpoint = f'policies/v2/destinationlists/{dest_list_id}'
        return self.req_get(endpoint).json().get("data", {})

    def get_destinations(self, dest_list_id):
        if self.token is None:
            self.get_token()
        bearer_token = "Bearer " + self.token['access_token']
        headers = {
            "Authorization": bearer_token,
            "Content-Type": "application/json"
        }

        all_destinations = []
        limit = 100
        offset = 0

        while True:
            url = f'https://api.umbrella.com/policies/v2/destinationlists/{dest_list_id}/destinations?limit={limit}&offset={offset}'
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json().get("data", [])
            all_destinations.extend(data)
            if len(data) < limit:
                break
            offset += limit

        return all_destinations

    
    def get_destination_lists(self) -> list:
        endpoint = "policies/v2/destinationlists"
        response = self.req_get(endpoint)
        return response.json().get("data", [])

    def is_domain_blocked(self, domain: str, dest_list_id: int = None) -> bool:
        if dest_list_id is not None:
            # Legacy behavior — check specific list
            destinations = self.get_destinations(dest_list_id)
            return any(entry["destination"].lower() == domain.lower() for entry in destinations)

        # Otherwise, check all lists
        return len(self.find_lists_containing_domain(domain)) > 0
    
    def find_lists_containing_domain(self, domain: str) -> list[int]:
        matched_lists = []
        if self.token is None:
            self.get_token()
        bearer_token = "Bearer " + self.token['access_token']
        headers = {
            "Authorization": bearer_token,
            "Content-Type": "application/json"
        }

        lists = self.get_destination_lists()
        for lst in lists:
            try:
                destinations = self.get_destinations(lst["id"])
                for entry in destinations:
                    if entry["destination"].lower() == domain.lower():
                        matched_lists.append(lst["id"])
                        break
            except Exception as e:
                print(f"[!] Failed to check list {lst['id']}: {e}")
        return matched_lists

    def remove_domain_from_list(self, domain: str, dest_list_id: int) -> bool:
        domain = domain.strip().lower()
        destinations = self.get_destinations(dest_list_id)

        for entry in destinations:
            print(f"[DEBUG] Entry: {entry}")
            if entry["destination"].strip().lower() == domain:
                destination_id = int(entry["id"])

                endpoint = f"policies/v2/destinationlists/{dest_list_id}/destinations/remove"
                if self.token is None:
                    self.get_token()
                bearer_token = "Bearer " + self.token['access_token']
                headers = {
                    "Authorization": bearer_token,
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }

                response = requests.request(
                    method="DELETE",
                    url=f"https://api.umbrella.com/{endpoint}",
                    headers=headers,
                    data=json.dumps([destination_id])  # <- raw array!
                )

                print("[DEBUG] DELETE URL:", f'https://api.umbrella.com/{endpoint}')
                print("[DEBUG] Body:", [destination_id])
                print("[DEBUG] Response:", response.status_code, response.text)
                response.raise_for_status()
                return True

        print(f"[!] Domain '{domain}' not found in list {dest_list_id}")
        return False





# CLI Test (Optional)
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Umbrella destination list tool")
    parser.add_argument("--action", choices=["check", "remove", "find"], required=True)
    parser.add_argument("--domain", required=True, help="Domain to check/remove")
    parser.add_argument("--list", type=int, default=None, help="Destination list ID (optional for check/remove)")

    args = parser.parse_args()

    try:
        client_id = os.environ.get("UMBRELLA_CLIENT_ID")
        client_secret = os.environ.get("UMBRELLA_CLIENT_SECRET")

        if not client_id or not client_secret:
            raise ValueError("Missing UMBRELLA_CLIENT_ID or UMBRELLA_CLIENT_SECRET")

        umbrella_api = UmbrellaAPI(TOKEN_URL, client_id, client_secret)


        if args.action == "check":
            is_blocked = umbrella_api.is_domain_blocked(args.domain, args.list)
            if args.list:
                print(f"[✓] Domain '{args.domain}' is {'BLOCKED' if is_blocked else 'not blocked'} in list {args.list}")
            else:
                print(f"[✓] Domain '{args.domain}' is {'BLOCKED' if is_blocked else 'not blocked'} in any list")

        elif args.action == "find":
            matched_lists = umbrella_api.find_lists_containing_domain(args.domain)
            if matched_lists:
                print(f"[✓] Domain '{args.domain}' found in lists: {matched_lists}")
            else:
                print(f"[✓] Domain '{args.domain}' not found in any destination list")

        elif args.action == "remove":
            success = False
            if args.list:
                success = umbrella_api.remove_domain_from_list(args.domain, args.list)
            else:
                matched_lists = umbrella_api.find_lists_containing_domain(args.domain)
                for lid in matched_lists:
                    removed = umbrella_api.remove_domain_from_list(args.domain, lid)
                    success = success or removed
            if success:
                print(f"[✓] Domain '{args.domain}' removed")
            else:
                print(f"[!] Domain '{args.domain}' not removed (not found?)")
    except Exception as e:
        print(f"[!] Error: {e}")
