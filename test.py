import requests
import json

# ====== CONFIG ======
APP_URL = "https://iocmanager.azurewebsites.net"
IIOC = "8.8.8.8"  # Replace with a test IoC

# Optional API keys for enrichment
API_KEYS = {
    "DNSDB_API_KEY": "your-key-if-needed",
    # Add others if needed for testing
}

# ====== TESTS ======

def test_health():
    try:
        res = requests.get(f"{APP_URL}/health")
        print("[+] Health check:", res.status_code, res.text.strip())
    except Exception as e:
        print("[!] Health check failed:", e)


def test_enrich(ioc):
    payload = {
        "ioc": ioc,
        "keys": API_KEYS
    }

    try:
        res = requests.post(f"{APP_URL}/enrich", json=payload)
        print("[+] Enrich POST status:", res.status_code)
        print("[+] Response JSON:")
        print(json.dumps(res.json(), indent=2))
    except Exception as e:
        print("[!] Enrichment failed:", e)


if __name__ == "__main__":
    print("=== Running IoC Manager API Tests ===\n")
    test_health()
    print("\n---\n")
    test_enrich(IIOC)
