# core/api.py

from flask import Flask, request, jsonify
from core.enrichment.pipeline import run_enrichment
from integrations.umbrella import UmbrellaAPI, TOKEN_URL
from integrations.misp import block_ioc_in_misp
from integrations.edl import update_edl
import os

app = Flask(__name__)
if os.environ.get("FLASK_ENV") != "production":
    from flask_cors import CORS
    CORS(app)


@app.route("/umbrella/destination-lists", methods=["GET"])
def get_destination_lists():
    try:
        client_id = request.args.get("api_key")
        client_secret = request.args.get("api_secret")

        if not client_id or not client_secret:
            return jsonify({"error": "Missing Umbrella credentials"}), 400

        api = UmbrellaAPI(TOKEN_URL, client_id, client_secret)
        response = api.req_get("policies/v2/destinationlists?limit=100")
        lists = response.json().get("data", [])
        return jsonify(lists)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/umbrella/block", methods=["POST"])
def block_ioc_in_umbrella():
    try:
        data = request.get_json()
        ioc = data.get("ioc")
        list_id = data.get("list_id")  # Expect from frontend

        if not ioc or not list_id:
            return jsonify({"error": "Missing IoC or list_id"}), 400

        print(f"Received payload: {data}")
        print("Attempting to POST to Umbrella...")

        client_id = data.get("api_key")
        client_secret = data.get("api_secret")

        if not client_id or not client_secret:
            return jsonify({"error": "Missing Umbrella credentials"}), 400

        api = UmbrellaAPI(TOKEN_URL, client_id, client_secret)

        # NOTE: Send list of objects as required by Umbrella API
        comment = data.get("comment", "Added via IoC Blocker UI")

        resp = api.req_post(
            f"policies/v2/destinationlists/{list_id}/destinations",
            [{
                "destination": ioc,
                "comment": comment
            }]
        )

        print(f"Success: {resp.status_code} {resp.text}")
        return jsonify({"message": f"IoC '{ioc}' added to destination list {list_id}."})
    except Exception as e:
        print(f"Umbrella block error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/edl/block", methods=["POST"])
def edl_block():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    action = data.get("action")
    apikey = data.get("apikey")
    edl_base_url = data.get("edl_base_url") or os.getenv("EDL_BASE_URL")

    if not ip or action not in ["add", "remove"] or not apikey:
        return jsonify({"error": "Missing or invalid IP, action, or API key"}), 400
    if not edl_base_url:
        return jsonify({"error": "Missing EDL base URL (edl_base_url)"}), 400

    result = update_edl(ip=ip, apikey=apikey, action=action, base_url=edl_base_url)
    return (jsonify(result), 200) if result.get("success") else (jsonify(result), 500)


@app.route("/misp/block", methods=["POST"])
def misp_block():
    data = request.get_json(force=True, silent=True) or {}

    ioc = data.get("ioc")
    ioc_type = data.get("ioc_type", "domain")
    comment = data.get("comment", "Blocked via Chrome Extension")
    tlp = data.get("tlp", "tlp:red")
    user_name = f"{data.get('first_name', '')} {data.get('last_name', '')}".strip()
    user_org = data.get("organization", "Unknown Org")

    # New: Extract API key from frontend
    api_key = data.get("api_key")
    base_url = data.get("base_url")
    verify_ssl = data.get("verify_ssl", True)

    if not ioc:
        return jsonify({"error": "Missing IoC"}), 400

    if not api_key:
        return jsonify({"error": "Missing MISP API key"}), 400

    event_info = f"Chrome Extension Blocks - {user_name} @ {user_org}"

    try:
        result = block_ioc_in_misp(
            ioc_value=ioc,
            api_key=api_key,
            base_url=base_url,
            verify_ssl=verify_ssl,
            ioc_type=ioc_type,
            comment=comment,
            tlp=tlp,
            event_info=event_info
        )
    except Exception as e:
        print("[ERROR] MISP block failed:", e)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

    print("[DEBUG] MISP result:", result)
    return jsonify(result)


    
@app.route("/enrich", methods=["POST"])
def enrich():
    payload = request.get_json(force=True, silent=True) or {}
    iocs = payload.get("iocs", [])
    verbose = bool(payload.get("verbose", False))
    api_keys = payload.get("api_keys", {})

    if not isinstance(api_keys, dict):
        return jsonify({"error": "api_keys must be an object"}), 400

    try:
        result = run_enrichment(iocs, api_keys=api_keys, verbose=verbose)
        return jsonify(result)
    except Exception as e:
        # Don’t log secrets; keep error generic
        if verbose:
            print(f"/enrich failed: {e}")
        return jsonify({"error": "enrichment_failed"}), 500
    
@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

