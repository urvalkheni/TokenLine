from flask import Flask, request, jsonify
import json
import os
import re
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from jsonschema import validate, ValidationError
from db import init_db, insert_event, get_session
from correlator import process_event

app = Flask(__name__)

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

@app.route("/events", methods=["POST"])
def ingest_event():
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
        insert_event(data)
        # Correlate token families in real-time
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

    return jsonify({"status": "event persisted"}), 201

if __name__ == "__main__":
    init_db()
    # Read port from env or default to 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
