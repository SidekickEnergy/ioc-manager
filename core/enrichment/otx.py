# core/enrichment/otx.py

import json
import argparse
from OTXv2 import OTXv2, IndicatorTypes

def check_ioc(ioc_type, ioc_value, api_key=None):
    try:
        otx_instance = OTXv2(api_key)
        result = otx_instance.get_indicator_details_by_section(ioc_type, ioc_value, section="general")
        # NOTE: if the OTX SDK does not support timeout, you'll need to monkey patch or catch long delays at thread level
        pulses = result.get("pulse_info", {}).get("pulses", [])

        return {
            "pulse_count": len(pulses),
            "pulses": [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "author": p.get("author_name"),
                    "created": p.get("created"),
                    "description": p.get("description"),
                    "tags": p.get("tags"),
                    "references": p.get("references"),
                }
                for p in pulses
            ],
            "found": len(pulses) > 0
        }

    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Query OTX for threat intelligence")
    parser.add_argument("ioc", help="IoC value")
    parser.add_argument("type", help="IoC type (ip, domain, url, md5, sha1, sha256)")
    args = parser.parse_args()

    type_map = {
        "ip": IndicatorTypes.IPv4,
        "ipv4": IndicatorTypes.IPv4,
        "ipv6": IndicatorTypes.IPv6,
        "domain": IndicatorTypes.DOMAIN,
        "hostname": IndicatorTypes.HOSTNAME,
        "url": IndicatorTypes.URL,
        "md5": IndicatorTypes.FILE_HASH_MD5,
        "sha1": IndicatorTypes.FILE_HASH_SHA1,
        "sha256": IndicatorTypes.FILE_HASH_SHA256,
        "cve": IndicatorTypes.CVE
    }

    indicator_type = type_map.get(args.type.lower())
    if not indicator_type:
        print(json.dumps({"error": f"Unsupported type: {args.type}"}))
        exit(1)

    result = check_ioc(indicator_type, args.ioc)
    print(json.dumps(result, indent=2))
