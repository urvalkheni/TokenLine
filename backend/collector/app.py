from flask import Flask, request, jsonify, send_from_directory
import json
import os
import re
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from jsonschema import validate, ValidationError
from db import init_db, insert_event, get_session, Event, TokenFamilyMember, TokenReuseRecord
from correlator import process_event, reconstruct_chain

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

# Load schema
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "schema", "event.schema.json")
try:
    with open(SCHEMA_PATH, "r") as f:
        event_schema = json.load(f)
except Exception as e:
    print(f"Error loading event schema from {SCHEMA_PATH}: {e}")
    event_schema = None

# Regex to detect JWT (3 base64 strings separated by dots) or Authorization header pattern
JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
BEARER_PATTERN = re.compile(r"^(Bearer|Basic|Token)\s+.*", re.IGNORECASE)

def contains_raw_credentials(data):
    """Recursively checks if any value in the data contains a JWT or Bearer token pattern."""
    if isinstance(data, dict):
        for key, val in data.items():
            # Check keys and values
            if contains_raw_credentials(val):
                return True
    elif isinstance(data, list):
        for item in data:
            if contains_raw_credentials(item):
                return True
    elif isinstance(data, str):
        # Check if the string matches JWT format or Authorization Bearer format
        if JWT_PATTERN.match(data.strip()) or BEARER_PATTERN.match(data.strip()):
            return True
    return False

@app.route("/events", methods=["POST", "OPTIONS"])
def ingest_event():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    if not event_schema:
        return jsonify({"error": "Schema not loaded on server"}), 500

    # Ensure payload is JSON
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({"error": f"Invalid JSON payload: {str(e)}"}), 400

    # Validate against JSON schema
    try:
        validate(instance=data, schema=event_schema)
    except ValidationError as ve:
        return jsonify({
            "error": "Schema validation failed",
            "message": ve.message,
            "path": list(ve.path)
        }), 400
    except Exception as e:
        return jsonify({"error": f"Validation error: {str(e)}"}), 400

    # Security check: Ensure no raw credentials (JWTs, auth headers) are stored in any field
    if contains_raw_credentials(data):
        return jsonify({
            "error": "Security validation failed",
            "message": "Raw credentials (such as JWTs or authorization headers) are not allowed in event payloads."
        }), 400

    # Store event in the database
    try:
        res = insert_event(data)
        if isinstance(res, tuple):
            db_event, created = res
        else:
            db_event, created = res, True

        # Correlate token families in real-time
        if created:
            db_sess = get_session()
            try:
                process_event(data, db_sess)
            finally:
                db_sess.close()
    except Exception as e:
        # Prevent database exceptions from crashing the service
        return jsonify({
            "error": "Database error",
            "message": "Failed to store event in the database"
        }), 500

    return jsonify({"status": "event persisted" if created else "event already exists"}), 201 if created else 200

# --- READ-ONLY API ROUTES FOR FRONTEND & CLIENTS ---

@app.route("/events", methods=["GET", "OPTIONS"])
@app.route("/api/events", methods=["GET", "OPTIONS"])
def get_events():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    limit = request.args.get("limit", default=100, type=int)
    db = get_session()
    try:
        events = db.query(Event).order_by(Event.time.desc()).limit(limit).all()
        result = []
        for ev in events:
            result.append({
                "event_id": ev.event_id,
                "event_type": ev.event_type,
                "time": ev.time,
                "user_id": ev.user_id,
                "token_hash": ev.token_hash,
                "token_family": ev.token_family,
                "parent_token_hash": ev.parent_token_hash,
                "ip_hash": ev.ip_hash,
                "country": ev.country,
                "device_id": ev.device_id,
                "user_agent_family": ev.user_agent_family,
                "endpoint": ev.endpoint,
                "result": ev.result
            })
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/api/families", methods=["GET"])
def get_families():
    db = get_session()
    try:
        members = db.query(TokenFamilyMember).all()
        families_dict = {}
        for m in members:
            fam_id = m.token_family
            if fam_id not in families_dict:
                families_dict[fam_id] = []
            families_dict[fam_id].append({
                "token_hash": m.token_hash,
                "token_family": m.token_family,
                "parent_token_hash": m.parent_token_hash,
                "is_rotated": m.is_rotated,
                "rotated_at": m.rotated_at,
                "superseded_by": m.superseded_by,
                "user_id": m.user_id,
                "status": "rotated" if m.is_rotated else "active"
            })
        
        # Check reuse records to mark reused status
        reuse_records = db.query(TokenReuseRecord).all()
        reused_hashes = {r.token_hash for r in reuse_records}
        for fam_id, token_list in families_dict.items():
            for tok in token_list:
                if tok["token_hash"] in reused_hashes:
                    tok["status"] = "reused"

        return jsonify(families_dict), 200
    finally:
        db.close()

@app.route("/api/families/<family_id>", methods=["GET"])
def get_family_detail(family_id):
    db = get_session()
    try:
        members = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_family == family_id).all()
        if not members:
            return jsonify({"error": "Family not found"}), 404
        
        reuse_records = db.query(TokenReuseRecord).filter(TokenReuseRecord.token_family == family_id).all()
        reused_map = {r.token_hash: r for r in reuse_records}

        tokens = []
        for m in members:
            status = "reused" if m.token_hash in reused_map else ("rotated" if m.is_rotated else "active")
            tokens.append({
                "token_hash": m.token_hash,
                "token_family": m.token_family,
                "parent_token_hash": m.parent_token_hash,
                "is_rotated": m.is_rotated,
                "rotated_at": m.rotated_at,
                "superseded_by": m.superseded_by,
                "user_id": m.user_id,
                "status": status,
                "reuse_details": {
                    "reused_at": reused_map[m.token_hash].reused_at,
                    "attempted_event_id": reused_map[m.token_hash].attempted_event_id
                } if m.token_hash in reused_map else None
            })
        
        # Reconstruct chain from first member
        chain = reconstruct_chain(members[0].token_hash, db) if members else []

        return jsonify({
            "token_family": family_id,
            "tokens": tokens,
            "chain": chain,
            "reuse_count": len(reuse_records)
        }), 200
    finally:
        db.close()

@app.route("/api/reuse-records", methods=["GET"])
def get_reuse_records():
    db = get_session()
    try:
        records = db.query(TokenReuseRecord).all()
        result = []
        for r in records:
            result.append({
                "id": r.id,
                "token_hash": r.token_hash,
                "token_family": r.token_family,
                "reused_at": r.reused_at,
                "attempted_event_id": r.attempted_event_id
            })
        return jsonify(result), 200
    finally:
        db.close()

@app.route("/api/scenarios", methods=["GET"])
def get_scenarios():
    scenarios = [
        {
            "id": "replay",
            "name": "Token Replay",
            "description": "Valid token is issued and used legitimately, then replayed by an adversary from an unauthorized host.",
            "detection_signal": "replay_detected"
        },
        {
            "id": "refresh-reuse",
            "name": "Refresh-Token Reuse",
            "description": "Legitimate rotation from Token A to Token B, followed by adversary presenting rotated Token A to request a new token.",
            "detection_signal": "token_refreshed (flags reuse record)"
        },
        {
            "id": "revoked-token",
            "name": "Use After Logout",
            "description": "User logs in, accesses resources, terminates session via logout, then adversary presents the revoked token.",
            "detection_signal": "logout -> token_used (rejected)"
        },
        {
            "id": "concurrent-use",
            "name": "Concurrent Use",
            "description": "The same authentication token is presented almost simultaneously from two distinct physical devices/IPs.",
            "detection_signal": "suspicious_device"
        },
        {
            "id": "impossible-travel",
            "name": "Impossible Travel",
            "description": "Same token presented from distant geographical coordinates (India to US) within an impossibly brief 5-minute window.",
            "detection_signal": "suspicious_location"
        }
    ]
    return jsonify(scenarios), 200

@app.route("/api/scenarios/<scenario_name>/run", methods=["POST"])
def run_simulator_scenario(scenario_name):
    try:
        # Import simulator runner
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        from simulator.runner import run_scenario

        events = run_scenario(scenario_name)
        
        # Persist and correlate
        db_sess = get_session()
        try:
            for evt in events:
                try:
                    insert_event(evt)
                    process_event(evt, db_sess)
                except Exception:
                    pass
        finally:
            db_sess.close()

        return jsonify({
            "scenario": scenario_name,
            "event_count": len(events),
            "events": events
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to run scenario: {str(e)}"}), 400

# --- FRONTEND STATIC SERVING ---

@app.route("/")
def serve_index():
    if os.path.exists(os.path.join(FRONTEND_DIR, "index.html")):
        return send_from_directory(FRONTEND_DIR, "index.html")
    return jsonify({"service": "TokenLine Event Collector & API", "status": "running"}), 200

@app.route("/<path:path>")
def serve_static(path):
    if os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    return jsonify({"error": "Resource not found"}), 404

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

if __name__ == "__main__":
    init_db()
    # Read port from env or default to 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)

