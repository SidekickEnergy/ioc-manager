import requests
import json
from core.config_loader import load_config

_config = load_config()
""" API_KEY = _config["dnsdb"]["api_key"] """
BASE_URL = _config["dnsdb"]["base_url"]
DEFAULT_LIMIT = _config["dnsdb"].get("default_limit", 5)


def normalize_type_for_dnsdb(ioc_type: str) -> str:
    """Map extended types to what DNSDB supports."""
    if ioc_type in ("hostname", "domain"):
        return "domain"
    elif ioc_type in ("ipv4", "ipv6"):
        return "ip"
    return ioc_type


def enrich_dnsdb(ioc: str, ioc_type: str, limit: int = DEFAULT_LIMIT, api_key: str = None) -> dict:
    normalized_type = normalize_type_for_dnsdb(ioc_type)

    if normalized_type == "domain":
        url = f"{BASE_URL}/lookup/rrset/name/{ioc}?limit={limit}"
        key_to_extract = "rdata"
        label = "related_ips"

    elif normalized_type == "ip":
        url = f"{BASE_URL}/lookup/rdata/ip/{ioc}?limit={limit}"
        key_to_extract = "rrname"
        label = "related_domains"

    else:
        return {
            "source": "dnsdb",
            "ioc": ioc,
            "type": normalized_type,
            "skip": True,
            "reason": "unsupported IoC type"
        }

    result_set = set()
    raw_lines = []

    try:
        headers = {
            "Accept": "application/x-ndjson",
            "X-API-Key": api_key #or API_KEY   fallback to config if not provided
        }

        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()

        for line in response.text.strip().splitlines():
            raw_lines.append(line)
            try:
                obj = json.loads(line)
                if "obj" in obj:
                    values = obj["obj"].get(key_to_extract)
                    if isinstance(values, list):
                        result_set.update(values)
                    elif isinstance(values, str):
                        result_set.add(values)
            except json.JSONDecodeError:
                continue

        return {
            "source": "dnsdb",
            "ioc": ioc,
            "type": normalized_type,
            label: list(result_set),
            "raw_count": len(raw_lines)
        }

    except requests.exceptions.RequestException as e:
        return {
            "source": "dnsdb",
            "ioc": ioc,
            "type": normalized_type,
            "error": str(e)
        }
