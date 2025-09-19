import requests
import urllib3
import os
import yaml
from datetime import datetime, timezone
import pytz
from pymisp import PyMISP, MISPEvent, MISPAttribute
import logging
import json

# === Configuration Loader ===
def load_misp_config():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
    return config.get("misp", {})


# === Helper: Convert Epoch to Copenhagen Time ===
def format_timestamp(ts_str):
    try:
        ts = int(ts_str)
        utc_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        copenhagen_tz = pytz.timezone("Europe/Copenhagen")
        local_dt = utc_dt.astimezone(copenhagen_tz)
        return local_dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    except Exception:
        return "Invalid timestamp"

# === MISP Connection Test ===
def test_misp_connection(api_key, base_url="https://misp.cert.dk", verify_ssl=True, timeout=5):
    url = f"{base_url.rstrip('/')}/servers/getVersion"
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.get(url, headers=headers, verify=verify_ssl)
        response.raise_for_status()
        version = response.json().get("version", "unknown")
        return {"success": True, "version": version}
    except requests.RequestException as e:
        return {"success": False, "error": str(e), "details": getattr(e.response, "text", "")}


# === MISP Lookup ===
def search_ioc_in_misp(ioc_value, api_key, base_url=None, verify_ssl=True):
    if not api_key:
        return {"error": "missing_api_key"}

    misp_url = (base_url or "https://misp.cert.dk").rstrip("/")
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = f"{misp_url}/attributes/restSearch"
    payload = {
        "value": ioc_value,
        "returnFormat": "json"
    }

    try:
        response = requests.post(url, headers=headers, json=payload, verify=verify_ssl, timeout=5)
        response.raise_for_status()
        attributes = response.json().get("response", {}).get("Attribute", [])

        enriched = []
        for attr in attributes:
            enriched.append({
                "type": attr.get("type"),
                "value": attr.get("value"),
                "category": attr.get("category"),
                "comment": attr.get("comment"),
                "timestamp": format_timestamp(attr.get("timestamp")),
                "event_info": attr.get("Event", {}).get("info"),
                "event_id": attr.get("event_id"),
                "event_published": format_timestamp(attr.get("Event", {}).get("publish_timestamp")),
            })

        return enriched

    except requests.RequestException as e:
        print(f"[ERROR] MISP query failed: {e}")
        return []

    
def custom_color_for_tag(tag):
    if "tlp:red" in tag: return "#ff0000"
    if "tlp:amber" in tag: return "#ffc200"
    if "tlp:green" in tag: return "#009933"
    if "tlp:white" in tag: return "#fafafa"
    return "#00ace6"  # Default MISP blue

# === Add/Block IoC in MISP ===
def block_ioc_in_misp(
    ioc_value,
    api_key,
    base_url="https://misp.cert.dk",
    verify_ssl=True,
    ioc_type="domain",
    category="Network activity",
    comment="Blocked via Chrome Extension",
    to_ids=True,
    tlp="tlp:red",
    event_info="Chrome Extension Blocks - Unknown"
):

    misp = PyMISP(base_url.rstrip("/"), api_key, verify_ssl, "json")

    # Step 1: Try to find existing event using restSearch (match by event info)
    event = None
    try:
        search_payload = {
            "returnFormat": "json",
            "eventinfo": event_info
        }
        search_result = misp.direct_call("events/restSearch", search_payload)
        print("[DEBUG] search_result:", json.dumps(search_result, indent=2))  # Optional debug

        # Handle both list and dict formats (some versions return list directly)
        if isinstance(search_result, list):
            for result in search_result:
                evt = result.get("Event", {})
                if evt.get("info") == event_info:
                    event = result
                    break

        elif isinstance(search_result, dict) and "response" in search_result:
            for result in search_result["response"]:
                evt = result.get("Event", {})
                if evt.get("info") == event_info:
                    event = result
                    break

    except Exception as e:
        logging.error("[MISP] Search failed: %s", str(e))
        return {"error": "Failed to search MISP", "details": str(e)}


    # Step 2: Create event if not found
    if not event:
        try:
            new_event = MISPEvent()
            new_event.info = event_info
            new_event.distribution = 1
            new_event.analysis = 0
            new_event.threat_level_id = 2
            event = misp.add_event(new_event)
        except Exception as e:
            return {"error": "Failed to create event", "details": str(e)}

    # Step 3: Extract event ID safely
    event_id = None
    if isinstance(event, dict):
        event_id = event.get("Event", {}).get("id")
    elif hasattr(event, "id"):
        event_id = str(event.id)

    if not event_id:
        return {"error": "Failed to extract event_id", "raw_event": event}

    # Step 4: Add IoC as attribute
    try:
        attribute = MISPAttribute()
        attribute.type = ioc_type
        attribute.category = category
        attribute.value = ioc_value
        attribute.to_ids = to_ids
        attribute.comment = comment

        added = misp.add_attribute(event_id, attribute)
    except Exception as e:
        return {"error": "Failed to add attribute", "details": str(e)}

    # Step 5: Tag event
    try:
        allowed_tlp = {"tlp:red", "tlp:amber", "tlp:green", "tlp:white"}
        if tlp in allowed_tlp:
            misp.tag(misp.get_event(event_id), tlp)
    except Exception as e:
        logging.warning("[MISP] Failed to tag event: %s", str(e))

    return {
        "success": True,
        "event_id": event_id,
        "attribute_id": added["Attribute"]["id"] if "Attribute" in added else None
    }


# === CLI Entry Point ===
if __name__ == "__main__":
    import argparse   
    parser = argparse.ArgumentParser(description="MISP integration CLI")
    parser.add_argument("ioc", nargs="?", help="The IoC to search or block")
    parser.add_argument("--test", action="store_true", help="Test MISP connection only")
    parser.add_argument("--block", action="store_true", help="Block the IoC by adding to MISP")
    parser.add_argument("--tlp", default="tlp:red", help="TLP tag to apply (default: tlp:red)")
    parser.add_argument("--comment", default="Blocked via Chrome Extension", help="Comment for the attribute")
    args = parser.parse_args()

    if args.test:
        apikey = os.getenv("MISP_API_KEY")
        result = test_misp_connection(api_key=apikey)
        print(result)
    elif args.block and args.ioc:
        apikey = os.getenv("MISP_API_KEY")
        result = block_ioc_in_misp(
            ioc_value=args.ioc,
            api_key=apikey,
            tlp=args.tlp,
            comment=args.comment
        )
        print(result)
    elif args.ioc:
        results = search_ioc_in_misp(args.ioc)
        if results:
            print(f"Found {len(results)} MISP hits:")
            for r in results:
                print(f"- {r['type']}: {r['value']}")
                print(f"  Event: {r['event_info']} (ID: {r['event_id']})")
                print(f"  Category: {r['category']}")
                print(f"  Comment: {r['comment']}")
                print(f"  Attribute timestamp: {r['timestamp']}")
                print(f"  Event published: {r['event_published']}")
                print()
        else:
            print("No results found in MISP.")
    else:
        print("Please provide an IoC or use --test.")
