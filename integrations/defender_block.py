# backend/app/integrations/defender_block.py

import os
import sys
import json
import requests
from datetime import datetime, timedelta, timezone

# Ensure we can import from utils
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.defender_auth import get_defender_token

GRAPH_TI_ENDPOINT = "https://graph.microsoft.com/beta/security/tiIndicators"  # ✅ Updated endpoint


def submit_threat_indicator(indicator_type, indicator_value, action="Alert", severity="High", description=None):
    token = get_defender_token()
    if not token:
        return {"error": "Failed to get token"}

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    severity_map = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3
    }

    expiration = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat().replace("+00:00", "Z")

    payload = {
        "indicatorValue": indicator_value,
        "indicatorType": indicator_type,
        "action": action.lower(),
        "confidence": 100,
        "severity": severity_map.get(severity.lower(), 3),
        "expirationDateTime": expiration,
        "title": "Test IoC",
        "description": "Minimal working payload",
        "targetProduct": "MicrosoftDefenderForEndpoint",
        "threatType": "phishing"
    }

    print("[DEBUG] Payload to be sent:")
    print(json.dumps(payload, indent=2))

    try:
        response = requests.post(GRAPH_TI_ENDPOINT, headers=headers, json=payload)
        print(f"[DEBUG] HTTP {response.status_code}")
        print(f"[DEBUG] Response body: {response.text}")
        response.raise_for_status()
        return {"success": True, "submitted": response.json()}
    except requests.exceptions.RequestException as e:
        return {
            "error": str(e),
            "status_code": getattr(e.response, "status_code", None),
            "response_body": getattr(e.response, "text", None)
        }



if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python defender_block.py <indicator_type> <indicator_value>")
        print("Example: python defender_block.py url http://malicious.example.com")
        sys.exit(1)

    indicator_type = sys.argv[1].lower()
    indicator_value = sys.argv[2]

    result = submit_threat_indicator(indicator_type, indicator_value)
    print(json.dumps(result, indent=2))
