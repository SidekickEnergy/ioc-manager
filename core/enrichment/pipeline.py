import os
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.ioc_model import IoC
from core.enrichment.dnsdb import enrich_dnsdb
from core.enrichment.abuseipdb import query_abuseipdb
from core.enrichment.virustotal import lookup_virustotal
from core.enrichment.otx import check_ioc
from integrations.misp import search_ioc_in_misp
from integrations.edl import check_edl
from integrations.umbrella import UmbrellaAPI, TOKEN_URL
from integrations.defender_enrich import query_advanced_hunting, query_alerts_from_hunting
from OTXv2 import IndicatorTypes

# Load config.yaml
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../../config.yaml")
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

OTX_API_KEY = config.get("otx", {}).get("api_key")


def enrich_single_ioc(ioc, umbrella_api, vt_api_key, misp_api_key, dnsdb_api_key, otx_api_key, edl_api_key, verbose=False):
    results = {}

    def dnsdb():
        r = enrich_dnsdb(ioc.value, ioc.type, api_key=dnsdb_api_key)
        if r: results["dnsdb"] = r
        if verbose: print("    [✓] DNSDB enriched.")

    def abuseipdb():
        if ioc.type in ["ip", "ipv4", "ipv6"]:
            r = query_abuseipdb(ioc.value)
            if r: results["abuseipdb"] = r
            if verbose: print("    [✓] AbuseIPDB enriched.")

#    def umbrella():
#        if ioc.type in ["domain", "hostname"]:
#            blocked = umbrella_api.is_domain_blocked(ioc.value, DEST_LIST_ID)
#            results["umbrella"] = {"blocked": blocked}
#           if verbose: print(f"    [✓] Umbrella check: {'Blocked' if blocked else 'Not blocked'}")

    def misp():
        try:
            hits = search_ioc_in_misp(ioc.value, misp_api_key)
            if hits:
                results["misp"] = {"count": len(hits), "hits": hits}
                if verbose: print(f"    [✓] MISP hits: {len(hits)}")
        except Exception as e:
            if verbose: print(f"    [!] MISP enrichment failed: {e}")


    def virustotal():
        r = lookup_virustotal(ioc.value, ioc.type, vt_api_key)
        if r: results["virustotal"] = r
        if verbose: print("    [✓] VirusTotal enriched.")

    def otx():
        otx_map = {
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
        otx_type = otx_map.get(ioc.type)
        if otx_type and otx_api_key:
            r = check_ioc(otx_type, ioc.value, api_key=otx_api_key)
            if r: results["otx"] = r
            if verbose: print("    [✓] OTX enriched.")

    def defender():
        try:
            defender_type_map = {
                "ipv4": "ip",
                "ipv6": "ip",
                "hostname": "domain",
                "domain": "domain",
                "url": "url",
                "sha1": "sha1",
                "sha256": "sha256",
                "md5": "md5"
            }
            d_type = defender_type_map.get(ioc.type, ioc.type)

            alert_data = query_alerts_from_hunting([ioc.value])
            alerts = alert_data.get("hunting_alerts", {}).get("Results", [])
            hunt = query_advanced_hunting(ioc.value, d_type)
            found = len(hunt.get("advanced_hunting", {}).get("Results", [])) > 0

            results["defender"] = {
                "found_in_hunting": found,
                "alerts": alerts,
                "alert_count": len(alerts)
            }
            if verbose:
                print(f"    [✓] Defender enriched: {len(alerts)} alerts, hunting match = {found}")
        except Exception as e:
            if verbose: print(f"    [!] Defender enrichment failed: {e}")

    def edl():
        if ioc.type in ["ip", "ipv4", "ipv6"] and edl_api_key:
            try:
                is_blocked = check_edl(edl_api_key, ioc.value)
                results["edl"] = {"blocked": is_blocked}
                if verbose: print(f"    [✓] EDL check: {'Blocked' if is_blocked else 'Not blocked'}")
            except Exception as e:
                if verbose: print(f"    [!] EDL enrichment failed: {e}")

    enrich_funcs = [dnsdb, abuseipdb, misp, virustotal, otx, defender, edl]


    from concurrent.futures import TimeoutError

    with ThreadPoolExecutor(max_workers=len(enrich_funcs)) as executor:
        futures = {executor.submit(fn): fn.__name__ for fn in enrich_funcs}

        for future in as_completed(futures):
            fn_name = futures[future]
            try:
                future.result(timeout=5)
            except TimeoutError:
                if verbose:
                    print(f"    [!] {fn_name} timed out after 5s.")
            except Exception as e:
                if verbose:
                    print(f"    [!] {fn_name} failed: {e}")


    for key, val in results.items():
        ioc.enrich_with(key, val)

    return ioc


def run_enrichment(ioc_values, verbose=False, api_keys=None):
    umbrella_key = (api_keys.get("umbrella") or {}).get("apiKey")
    umbrella_secret = (api_keys.get("umbrella") or {}).get("apiSecret")

    umbrella_api = None
    if umbrella_key and umbrella_secret:
        umbrella_api = UmbrellaAPI(TOKEN_URL, umbrella_key, umbrella_secret)
    enriched_iocs = []

    # New: safely extract VT key from nested api_keys
    api_keys = api_keys or {}
    vt_api_key = (api_keys.get("virustotal") or {}).get("apiKey", None)
    misp_api_key = (api_keys.get("misp") or {}).get("apiKey", None)
    edl_api_key = (api_keys.get("edl") or {}).get("apiKey", None)
    dnsdb_api_key = (api_keys.get("dnsdb") or {}).get("apiKey", None)
    otx_api_key = (api_keys.get("otx") or {}).get("apiKey", None)


    for raw_ioc in ioc_values:
        ioc = IoC(raw_ioc)
        if verbose:
            print(f"\n[~] Processing: {ioc.value} ({ioc.type})")
        enriched = enrich_single_ioc(
            ioc, umbrella_api, vt_api_key, misp_api_key, dnsdb_api_key, otx_api_key, edl_api_key, verbose
        )
        enriched_iocs.append(enriched)

    return [ioc.to_dict() for ioc in enriched_iocs]

