import requests
import json
import os

DEFAULT_LIMIT = int(os.environ.get("DNSDB_DEFAULT_LIMIT", 5))

def _resolve_dnsdb_config(base_url: str | None, verify_ssl: bool | None) -> tuple[str, bool]:
    """
    Resolve base URL and SSL verify flag.
    - base_url: prefer function arg, otherwise DNSDB_BASE_URL env.
      Must point to the versioned root, e.g. https://api.dnsdb.info/dnsdb/v2
    - verify_ssl: prefer function arg, otherwise DNSDB_VERIFY_SSL env (default true).
    """
    url = (base_url or os.getenv("DNSDB_BASE_URL") or "").strip()
    if not url:
        raise ValueError("DNSDB base URL is required (pass base_url or set DNSDB_BASE_URL).")
    if verify_ssl is None:
        v = os.getenv("DNSDB_VERIFY_SSL", "true").lower() in ("1", "true", "yes", "on")
    else:
        v = bool(verify_ssl)
    return url.rstrip("/"), v


def normalize_type_for_dnsdb(ioc_type: str) -> str:
    """Map extended types to what DNSDB supports."""
    if ioc_type in ("hostname", "domain"):
        return "domain"
    elif ioc_type in ("ipv4", "ipv6"):
        return "ip"
    return ioc_type


def enrich_dnsdb(
    ioc: str,
    ioc_type: str,
    api_key: str | None = None,
    base_url: str | None = None,
    limit: int = DEFAULT_LIMIT,
    verify_ssl: bool | None = None,
) -> dict:
    # Require an API key (either passed or via env)
    api_key = api_key or os.getenv("DNSDB_API_KEY")
    if not api_key:
        return {"source": "dnsdb", "ioc": ioc, "type": ioc_type, "error": "missing_api_key"}

    # Resolve base URL + SSL verify (no config file)
    base_url, verify_ssl = _resolve_dnsdb_config(base_url, verify_ssl)

    normalized_type = normalize_type_for_dnsdb(ioc_type)

    if normalized_type == "domain":
        url = f"{base_url}/lookup/rrset/name/{ioc}?limit={limit}"
        key_to_extract = "rdata"
        label = "related_ips"
    elif normalized_type == "ip":
        url = f"{base_url}/lookup/rdata/ip/{ioc}?limit={limit}"
        key_to_extract = "rrname"
        label = "related_domains"
    else:
        return {"source": "dnsdb", "ioc": ioc, "type": normalized_type, "skip": True, "reason": "unsupported IoC type"}

    result_set, raw_lines = set(), []
    try:
        headers = {
            "Accept": "application/x-ndjson",
            "X-API-Key": api_key
        }
        response = requests.get(url, headers=headers, verify=verify_ssl, timeout=10)
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

        return {"source": "dnsdb", "ioc": ioc, "type": normalized_type, label: list(result_set), "raw_count": len(raw_lines)}
    except requests.exceptions.RequestException as e:
        return {"source": "dnsdb", "ioc": ioc, "type": normalized_type, "error": str(e)}

