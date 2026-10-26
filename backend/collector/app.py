import hmac
import sys
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, current_app, has_app_context
from werkzeug.exceptions import RequestEntityTooLarge
import json
import os
import re
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

import math
import urllib.parse


from collections import Counter
import jsonschema
from jsonschema import validate, ValidationError

format_checker = jsonschema.FormatChecker()

@format_checker.checks("date-time")
def check_datetime(val):
    if not isinstance(val, str):
        return False
    try:
        s = val.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        datetime.fromisoformat(s)
        return True
    except Exception:
        return False

import uuid
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError


try:
    from backend.collector.db import (
        init_db,
        insert_event,
        get_session,
        Event,
        TokenFamilyMember,
        TokenReuseRecord,
        ScenarioExecution,
    )
    from backend.correlator import (
        TokenFamilyCorrelator,
        process_event,
        reconstruct_chain,
        correlator_transaction,
    )
except ImportError:
    from db import (
        init_db,
        insert_event,
        get_session,
        Event,
        TokenFamilyMember,
        TokenReuseRecord,
        ScenarioExecution,
    )
    from backend.correlator import (
        TokenFamilyCorrelator,
        process_event,
        reconstruct_chain,
        correlator_transaction,
    )


try:
    from simulator.runner import run_scenario
except ImportError:
    run_scenario = None

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tokenline.collector")

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend")

# Load schema
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "schema", "event.schema.json")
try:
    with open(SCHEMA_PATH, "r") as f:
        event_schema = json.load(f)
except Exception as e:
    logger.error(f"Error loading event schema from {SCHEMA_PATH}: {e}")
    event_schema = None

# ==============================================================================
# ISSUE #9: THREE-LAYER RAW CREDENTIAL PROTECTION BEFORE STORAGE
# ==============================================================================

# Layer 1: Structural Hash Validation
# Enforces that fields representing hashes strictly conform to TokenLine's hash representations:
# - Hex string between 12 and 64 characters (HMAC-SHA256 digests or test fixture hashes)
# - Or 'hash_' followed by 12 hex characters (used by the simulator/synthetic datasets)
HASH_STRUCTURAL_PATTERN = re.compile(r"^(hash_)?[0-9a-fA-F]{12,64}$")

def validate_hash_structure(val, allow_null=False):
    """
    Layer 1: Structural Hash Validation.
    Validates that a field intended to contain a hash conforms strictly to
    TokenLine's established hash representation.
    """
    if val is None:
        return allow_null
    if not isinstance(val, str):
        return False
    return bool(HASH_STRUCTURAL_PATTERN.match(val.strip()))

# Layer 2: Credential-Pattern Detection
# Detects known credential formats (JWTs, auth schemes, token assignments) anywhere in strings.
# Unanchored to catch credentials placed in unexpected locations or surrounded by text.
JWT_PATTERN = re.compile(
    r"(?:ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?|"
    r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)",
    re.IGNORECASE
)
BEARER_PATTERN = re.compile(
    r"(?:Bearer|Basic|Token|ApiKey|Secret|JWT)\s+[A-Za-z0-9_.\-+/=]{8,}",
    re.IGNORECASE
)
CREDENTIAL_ASSIGN_PATTERN = re.compile(
    r"(?:token|access_token|refresh_token|id_token|api_key|apikey|secret|passwd|password|authorization)[\s:=]+([A-Za-z0-9_.\-+/=]{10,})",
    re.IGNORECASE
)

# Layer 3: High-Entropy Token Detection
# Detects suspicious high-entropy credential-like values that could bypass pattern regexes.
TOKEN_CHUNK_PATTERN = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")

def calculate_shannon_entropy(s):
    """Calculates Shannon entropy in bits per character for string s."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def is_suspicious_high_entropy_token(token):
    """
    Layer 3: High-Entropy Token Detection.
    Detects credential-like tokens with suspicious high Shannon entropy that could bypass pattern regexes.
    - Pure hexadecimal strings and 'hash_' prefixed hex strings are excluded since their theoretical
      maximum entropy is capped at 4.0 bits/char and they represent legitimate hashes or IDs.
    - Continuous strings of length >= 20 with mixed character classes (upper, lower, digits, symbols)
      and Shannon entropy >= 4.0 (or >= 4.3) are flagged as suspicious raw credentials.
    """
    if re.match(r"^(hash_)?[0-9a-fA-F]+$", token):
        return False

    if len(token) >= 20:
        has_upper = bool(re.search(r"[A-Z]", token))
        has_lower = bool(re.search(r"[a-z]", token))
        has_digit = bool(re.search(r"[0-9]", token))
        has_symbol = bool(re.search(r"[-_+/=]", token))
        char_classes = sum([has_upper, has_lower, has_digit, has_symbol])

        ent = calculate_shannon_entropy(token)
        # Mixed character classes (e.g. base64 / alphanumeric) with high entropy
        if char_classes >= 3 and ent >= 4.0:
            return True
        if ent >= 4.3:
            return True

    return False

def check_value_for_credentials(val):
    """
    Inspects a single string value (including URL-unquoted representations) for:
    - Layer 2: Credential patterns (JWTs, auth schemes, credential assignments)
    - Layer 3: High-entropy tokens
    Returns (True, reason) if a credential is detected, else (False, None).
    """
    if not isinstance(val, str):
        return False, None

    # Check both original and URL-unquoted representations to defeat encoding bypasses
    candidates = [val]
    try:
        unquoted = urllib.parse.unquote(val)
        if unquoted != val:
            candidates.append(unquoted)
        unquoted_plus = urllib.parse.unquote_plus(val)
        if unquoted_plus not in candidates:
            candidates.append(unquoted_plus)
    except Exception:
        pass

    for cand in candidates:
        cand_clean = cand.strip()

        # Layer 2: JWT pattern anywhere in string
        if JWT_PATTERN.search(cand_clean):
            return True, "Raw JWT credential detected"

        # Layer 2: Authorization credential schemes (Bearer, Basic, Token, etc.)
        if BEARER_PATTERN.search(cand_clean):
            return True, "Authorization credential scheme detected"

        # Layer 2: Key-value credential assignment
        if CREDENTIAL_ASSIGN_PATTERN.search(cand_clean):
            return True, "Credential assignment detected"

        # Layer 3: High-entropy token chunks
        for chunk in TOKEN_CHUNK_PATTERN.findall(cand_clean):
            if is_suspicious_high_entropy_token(chunk):
                return True, "Suspicious high-entropy credential token detected"

    return False, None

def contains_raw_credentials(data):
    """
    Recursively scans data structures for raw credentials using Layer 2 and Layer 3 protection.
    Returns:
    - A descriptive string (truthy) if raw credentials are found.
    - False (falsy) if no raw credentials are found.
    """
    if isinstance(data, dict):
        for k, v in data.items():
            result = contains_raw_credentials(v)
            if result:
                return result
    elif isinstance(data, list):
        for item in data:
            result = contains_raw_credentials(item)
            if result:
                return result
    elif isinstance(data, str):
        found, reason = check_value_for_credentials(data)
        if found:
            return reason
    return False

# Hard upper bound on pagination
DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 100

def get_pagination_params():
    """
    Extracts and validates pagination parameters.
    - Enforces hard upper bound of MAX_PAGE_LIMIT (100).
    - Safely handles negative limits by defaulting to DEFAULT_PAGE_LIMIT (100),
      preventing unbounded queries and SQLite LIMIT -1 bypass.
    - Safely handles non-numeric or missing limits.
    - Sanitizes non-negative offset.
    """
    raw_limit = request.args.get("limit")
    if raw_limit is None:
        limit = DEFAULT_PAGE_LIMIT
    else:
        try:
            val = int(raw_limit)
            if val <= 0:
                limit = DEFAULT_PAGE_LIMIT
            elif val > MAX_PAGE_LIMIT:
                limit = MAX_PAGE_LIMIT
            else:
                limit = val
        except (ValueError, TypeError):
            limit = DEFAULT_PAGE_LIMIT

    raw_offset = request.args.get("offset")
    if raw_offset is None:
        offset = 0
    else:
        try:
            val = int(raw_offset)
            offset = max(0, val)
        except (ValueError, TypeError):
            offset = 0

    return limit, offset

# --- AUTHENTICATION & AUTHORIZATION ---

def get_auth_token():
    """Extracts authentication token from Authorization or X-API-Key header."""
    auth_header = request.headers.get("Authorization")
    if auth_header:
        parts = auth_header.strip().split()
        if len(parts) == 2 and parts[0].lower() in ("bearer", "apikey", "token"):
            return parts[1]
        elif len(parts) == 1 and parts[0].lower() not in ("bearer", "apikey", "token"):
            return parts[0]
    api_key_header = request.headers.get("X-API-Key")
    if api_key_header:
        key = api_key_header.strip()
        if key:
            return key
    return None

SUPPORTED_ROLES = {"admin", "ingest", "read"}

PUBLISHED_DEFAULT_KEYS = {
    "tokenline-admin-secret",
    "tokenline-ingest-secret",
    "tokenline-read-secret",
    "default",
    "secret",
    "admin",
    "password",
    "changeme",
    "123456",
}


def get_environment_mode(app_config=None):
    """
    Returns the resolved execution mode: 'production', 'development', 'test', or 'invalid'.
    Explicit dev/test mode must be enabled to allow safe fallbacks.
    """
    if app_config and app_config.get("TESTING"):
        return "test"

    raw = (
        (app_config and app_config.get("TOKENLINE_ENV"))
        or os.environ.get("TOKENLINE_ENV")
        or os.environ.get("FLASK_ENV")
        or os.environ.get("ENV")
        or os.environ.get("APP_ENV")
    )
    if raw:
        s = str(raw).strip().lower()
        if s in ("development", "dev", "local"):
            return "development"
        if s in ("test", "testing"):
            return "test"
        if s in ("production", "prod"):
            return "production"
        return "invalid"

    if "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules:
        return "test"

    return "production"


def validate_origin(origin_str):
    """
    Validates that origin_str conforms to RFC 6454 (scheme://host[:port]).
    Rejects wildcards, paths (other than optional root /), query strings, and fragments.
    """
    if not origin_str or not isinstance(origin_str, str):
        return False
    s = origin_str.strip()
    if s == "*":
        return False
    try:
        parsed = urllib.parse.urlparse(s)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        if parsed.path and parsed.path != "/":
            return False
        if parsed.query or parsed.fragment:
            return False
        if parsed.username or parsed.password:
            return False
        return True
    except Exception:
        return False


def parse_cors_origins(raw):
    """Parses raw CORS allowed origins string or iterable into a list of strings."""
    if not raw:
        return []
    if isinstance(raw, (list, set, tuple)):
        return [str(o).strip() for o in raw if str(o).strip()]
    s = str(raw).strip()
    if s.startswith("[") and s.endswith("]"):
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [str(o).strip() for o in parsed if str(o).strip()]
        except Exception:
            pass
    return [o.strip() for o in s.split(",") if o.strip()]


def validate_and_load_cors_origins(mode, app_config=None):
    """
    Validates and resolves the allowlist of CORS origins.
    In production mode:
      - Requires explicitly configured origins.
      - Rejects wildcards ('*').
      - Rejects malformed origin URLs.
    In test/development mode:
      - Defaults to local origins if unset.
    """
    raw = (app_config and app_config.get("CORS_ALLOWED_ORIGINS")) or os.environ.get("CORS_ALLOWED_ORIGINS")
    origins = parse_cors_origins(raw)

    is_dev_or_test = mode in ("development", "test")

    if not is_dev_or_test:
        if not origins:
            raise ValueError(
                "Collector configuration error: CORS_ALLOWED_ORIGINS must be explicitly configured in production."
            )
        for o in origins:
            if o == "*":
                raise ValueError(
                    "Collector configuration error: Wildcard CORS origins ('*') are forbidden in production."
                )
            if not validate_origin(o):
                raise ValueError(
                    f"Collector configuration error: Malformed CORS origin '{o}'. Must be a valid http/https URL without path or query."
                )
    else:
        if not origins:
            origins = [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:5000",
                "http://127.0.0.1:5000",
            ]
        else:
            for o in origins:
                if o != "*" and not validate_origin(o):
                    raise ValueError(
                        f"Collector configuration error: Malformed CORS origin '{o}'."
                    )

    return {o.rstrip("/") for o in origins}


def validate_and_load_api_keys(mode, app_config=None):
    """
    Validates and resolves the mapping of API Key -> Role.
    In production mode:
      - Requires explicitly configured, valid credentials.
      - Rejects published or hardcoded default keys.
      - Rejects weak keys (< 16 characters).
      - Validates roles against SUPPORTED_ROLES.
      - Rejects malformed JSON in COLLECTOR_API_KEYS.
    In test/development mode:
      - Allows safe fallback test credentials if none are configured.
    """
    keys = {}
    is_dev_or_test = mode in ("development", "test")

    # 1. JSON mapping from COLLECTOR_API_KEYS
    env_keys_raw = (app_config and app_config.get("COLLECTOR_API_KEYS")) or os.environ.get("COLLECTOR_API_KEYS")
    if env_keys_raw is not None:
        if isinstance(env_keys_raw, dict):
            parsed = env_keys_raw
        elif isinstance(env_keys_raw, str):
            if not env_keys_raw.strip():
                if not is_dev_or_test:
                    raise ValueError("Collector configuration error: COLLECTOR_API_KEYS cannot be empty in production.")
                parsed = {}
            else:
                try:
                    parsed = json.loads(env_keys_raw)
                except Exception as e:
                    raise ValueError("Collector configuration error: COLLECTOR_API_KEYS contains malformed JSON.") from e
        else:
            raise ValueError("Collector configuration error: COLLECTOR_API_KEYS must be a JSON object mapping keys to roles.")

        if not isinstance(parsed, dict):
            raise ValueError("Collector configuration error: COLLECTOR_API_KEYS must be a JSON object mapping keys to roles.")

        for raw_key, role in parsed.items():
            if not isinstance(raw_key, str) or not raw_key.strip():
                raise ValueError("Collector configuration error: API key must be a non-empty string.")
            if not isinstance(role, str) or role.strip().lower() not in SUPPORTED_ROLES:
                raise ValueError(
                    f"Collector configuration error: Unsupported role '{role}'. Supported roles are: {', '.join(sorted(SUPPORTED_ROLES))}."
                )
            keys[raw_key.strip()] = role.strip().lower()

    # 2. Individual environment variables
    admin_key = (
        (app_config and app_config.get("COLLECTOR_ADMIN_API_KEY"))
        or os.environ.get("COLLECTOR_ADMIN_API_KEY")
        or os.environ.get("ADMIN_API_KEY")
        or os.environ.get("TOKENLINE_ADMIN_KEY")
    )
    if admin_key is not None:
        if not str(admin_key).strip():
            raise ValueError("Collector configuration error: Admin API key cannot be empty.")
        keys[str(admin_key).strip()] = "admin"

    ingest_key = (
        (app_config and app_config.get("COLLECTOR_INGEST_API_KEY"))
        or os.environ.get("COLLECTOR_INGEST_API_KEY")
        or os.environ.get("INGEST_API_KEY")
        or os.environ.get("TOKENLINE_INGEST_KEY")
    )
    if ingest_key is not None:
        if not str(ingest_key).strip():
            raise ValueError("Collector configuration error: Ingest API key cannot be empty.")
        keys[str(ingest_key).strip()] = "ingest"

    read_key = (
        (app_config and app_config.get("COLLECTOR_READ_API_KEY"))
        or os.environ.get("COLLECTOR_READ_API_KEY")
        or os.environ.get("READ_API_KEY")
        or os.environ.get("TOKENLINE_READ_KEY")
    )
    if read_key is not None:
        if not str(read_key).strip():
            raise ValueError("Collector configuration error: Read API key cannot be empty.")
        keys[str(read_key).strip()] = "read"

    if mode == "invalid":
        raise ValueError(
            "Collector configuration error: Unrecognized environment mode setting. Production mode required or explicitly set to development/test."
        )

    if not is_dev_or_test:
        if not keys:
            raise ValueError("Collector configuration error: Missing required collector API credentials in production.")

        for k, role in list(keys.items()):
            if k.lower() in PUBLISHED_DEFAULT_KEYS:
                raise ValueError("Collector configuration error: Published default credentials cannot be used in production.")
            if len(k) < 16:
                raise ValueError("Collector configuration error: Collector API keys must be at least 16 characters long in production.")
    else:
        if not keys:
            keys = {
                "tokenline-admin-secret": "admin",
                "tokenline-ingest-secret": "ingest",
                "tokenline-read-secret": "read",
            }

    return keys


def get_configured_api_keys():
    """Returns mapping of token -> role configured from application context or environment."""
    if has_app_context() and "COLLECTOR_API_KEYS_MAP" in current_app.config:
        return current_app.config["COLLECTOR_API_KEYS_MAP"]
    mode = get_environment_mode()
    return validate_and_load_api_keys(mode)


def authenticate_request():
    """
    Authenticates the incoming request against configured credentials using constant-time comparison.
    Returns (user_role, None) on success or (None, (json_error, status_code)) on failure.
    """
    token = get_auth_token()
    if not token:
        return None, (jsonify({
            "error": "Unauthorized",
            "message": "Missing authentication credentials"
        }), 401)

    keys_map = get_configured_api_keys()

    user_role = None
    for valid_key, role in keys_map.items():
        if hmac.compare_digest(token, valid_key):
            user_role = role
            break

    if not user_role:
        return None, (jsonify({
            "error": "Unauthorized",
            "message": "Invalid authentication credentials"
        }), 401)

    return user_role, None


def require_auth(allowed_roles=None):
    """
    Decorator enforcing authentication and role-based authorization.
    - Returns HTTP 401 if unauthenticated or invalid credentials.
    - Returns HTTP 403 if authenticated but lacking required privileges.
    - Allows authorized requests to proceed normally.
    """
    if allowed_roles is None:
        allowed_roles = {"read", "ingest", "admin"}
    elif isinstance(allowed_roles, str):
        allowed_roles = {allowed_roles}
    else:
        allowed_roles = set(allowed_roles)

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.method == "OPTIONS":
                origin = request.headers.get("Origin")
                if origin and has_app_context():
                    allowed = current_app.config.get("CORS_ALLOWED_ORIGINS_SET", set())
                    is_dev_or_test = current_app.config.get("TOKENLINE_ENV_MODE") in ("development", "test")
                    norm_origin = origin.rstrip("/")
                    if norm_origin not in allowed and not (is_dev_or_test and "*" in allowed):
                        return jsonify({"error": "Forbidden", "message": "CORS origin not allowed"}), 403
                return f(*args, **kwargs)

            role, error_response = authenticate_request()
            if error_response:
                return error_response

            # Admin role possesses all privileges
            if role == "admin":
                return f(*args, **kwargs)

            if role not in allowed_roles:
                return jsonify({
                    "error": "Forbidden",
                    "message": "Insufficient privileges for this operation"
                }), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator


def create_app(test_config=None):
    """Application factory for TokenLine Event Collector."""
    app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
    if test_config:
        app.config.update(test_config)

    mode = get_environment_mode(app.config)
    api_keys = validate_and_load_api_keys(mode, app.config)
    allowed_origins = validate_and_load_cors_origins(mode, app.config)

    app.config["TOKENLINE_ENV_MODE"] = mode
    app.config["COLLECTOR_API_KEYS_MAP"] = api_keys
    app.config["CORS_ALLOWED_ORIGINS_SET"] = allowed_origins

    # Maximum request body size: 10 MB (10 * 1024 * 1024 bytes)
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    @app.before_request
    def check_request_size():
        """Reject payloads that are 10 MB or larger."""
        if request.content_length is not None and request.content_length >= app.config["MAX_CONTENT_LENGTH"]:
            return jsonify({
                "error": "Payload too large",
                "message": f"Request body exceeds maximum allowed size of {app.config['MAX_CONTENT_LENGTH']} bytes"
            }), 413

    @app.errorhandler(413)
    @app.errorhandler(RequestEntityTooLarge)
    def handle_payload_too_large(error):
        return jsonify({
            "error": "Payload too large",
            "message": "Request body exceeds maximum allowed size"
        }), 413

    @app.route("/events", methods=["POST", "OPTIONS"])
    @app.route("/api/events", methods=["POST", "OPTIONS"])
    @require_auth({"ingest", "admin"})
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

        # Ensure payload is a JSON object
        if not isinstance(data, dict):
            return jsonify({"error": "Event payload must be a JSON object"}), 400

        # --- LAYER 2 & LAYER 3: Credential-pattern and High-Entropy Token Detection ---
        # Scan entire payload recursively across all fields for raw credentials
        cred_reason = contains_raw_credentials(data)
        if cred_reason:
            return jsonify({
                "error": "Security validation failed",
                "message": f"Raw credentials (such as JWTs or authorization headers) are not allowed in event payloads: {cred_reason}."
            }), 400

        # Validate against JSON schema (including format, hash patterns, and field length limits)
        try:
            validate(instance=data, schema=event_schema, format_checker=format_checker)
        except ValidationError as ve:
            return jsonify({
                "error": "Schema validation failed",
                "message": ve.message,
                "path": list(ve.path)
            }), 400
        except Exception as e:
            return jsonify({"error": f"Validation error: {str(e)}"}), 400

        # Store event in the database within a single atomic transaction
        db_sess = get_session()
        try:
            existing_event = db_sess.query(Event).filter(Event.event_id == data["event_id"]).first()
            if existing_event:
                return jsonify({"status": "event already exists"}), 200

            try:
                with correlator_transaction():
                    db_event = insert_event(data, session=db_sess)
                    if not getattr(db_event, "_is_new", True):
                        db_sess.commit()
                        return jsonify({"status": "event already exists"}), 200

                    try:
                        process_event(data, db_sess)
                    except Exception as corr_err:
                        logger.error(f"Correlation failed for event {data.get('event_id')}: {corr_err}", exc_info=True)
                        raise corr_err
                    db_sess.commit()
            except IntegrityError:
                raise
            except Exception as e:
                db_sess.rollback()
                return jsonify({
                    "error": "Correlation error",
                    "message": f"Correlation failed: {str(e)}"
                }), 500

            return jsonify({"status": "event persisted"}), 201
        except IntegrityError:
            db_sess.rollback()
            existing_event = db_sess.query(Event).filter(Event.event_id == data["event_id"]).first()
            if existing_event:
                return jsonify({"status": "event already exists"}), 200
            logger.error(f"Integrity violation storing event {data.get('event_id')}", exc_info=True)
            return jsonify({
                "error": "Database error",
                "message": "Failed to store event in the database"
            }), 500
        except Exception as e:
            db_sess.rollback()
            logger.error(f"Database error storing event {data.get('event_id')}: {e}", exc_info=True)
            return jsonify({
                "error": "Database error",
                "message": "Failed to store event in the database"
            }), 500
        finally:
            db_sess.close()


    # --- READ-ONLY API ROUTES FOR FRONTEND & CLIENTS ---

    @app.route("/events", methods=["GET", "OPTIONS"])
    @app.route("/api/events", methods=["GET", "OPTIONS"])
    @require_auth({"read", "ingest", "admin"})
    def get_events():
        if request.method == "OPTIONS":
            return jsonify({}), 200

        limit, offset = get_pagination_params()
        db = get_session()
        try:
            events = db.query(Event).order_by(Event.time.desc()).offset(offset).limit(limit).all()
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
                    "result": ev.result,
                    "schema_version": ev.schema_version,
                    "source": ev.source,
                    "is_simulation": bool(ev.is_simulation) if ev.is_simulation is not None else False
                })
            return jsonify(result), 200
        except Exception as e:
            logger.error(f"Failed to fetch events: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
        finally:
            db.close()

    @app.route("/api/families", methods=["GET", "OPTIONS"])
    @require_auth({"read", "ingest", "admin"})
    def get_families():
        if request.method == "OPTIONS":
            return jsonify({}), 200

        limit, offset = get_pagination_params()
        db = get_session()
        try:
            family_rows = db.query(TokenFamilyMember.token_family).distinct().offset(offset).limit(limit).all()
            family_ids = [row[0] for row in family_rows]

            if not family_ids:
                return jsonify({}), 200

            members = db.query(TokenFamilyMember).filter(TokenFamilyMember.token_family.in_(family_ids)).all()
            families_dict = {fam_id: [] for fam_id in family_ids}
            for m in members:
                fam_id = m.token_family
                if fam_id in families_dict:
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
            reuse_records = db.query(TokenReuseRecord).filter(TokenReuseRecord.token_family.in_(family_ids)).all()
            reused_hashes = {r.token_hash for r in reuse_records}
            for fam_id, token_list in families_dict.items():
                for tok in token_list:
                    if tok["token_hash"] in reused_hashes:
                        tok["status"] = "reused"

            return jsonify(families_dict), 200
        except Exception as e:
            logger.error(f"Failed to fetch token families: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
        finally:
            db.close()

    @app.route("/api/families/<family_id>", methods=["GET", "OPTIONS"])
    @require_auth({"read", "ingest", "admin"})
    def get_family_detail(family_id):
        if request.method == "OPTIONS":
            return jsonify({}), 200

        if len(family_id) > 128:
            return jsonify({"error": "family_id exceeds maximum allowed length of 128 characters"}), 400

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
        except Exception as e:
            logger.error(f"Failed to fetch family detail '{family_id}': {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
        finally:
            db.close()

    @app.route("/api/reuse-records", methods=["GET", "OPTIONS"])
    @require_auth({"read", "ingest", "admin"})
    def get_reuse_records():
        if request.method == "OPTIONS":
            return jsonify({}), 200

        limit, offset = get_pagination_params()
        db = get_session()
        try:
            records = db.query(TokenReuseRecord).order_by(TokenReuseRecord.id.desc()).offset(offset).limit(limit).all()
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
        except Exception as e:
            logger.error(f"Failed to fetch reuse records: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
        finally:
            db.close()

    @app.route("/api/scenarios", methods=["GET", "OPTIONS"])
    @require_auth({"read", "ingest", "admin"})
    def get_scenarios():
        if request.method == "OPTIONS":
            return jsonify({}), 200

        limit, offset = get_pagination_params()
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
        return jsonify(scenarios[offset:offset + limit]), 200

    @app.route("/api/scenarios/<scenario_name>/run", methods=["POST", "OPTIONS"])
    @require_auth({"admin"})
    def run_simulator_scenario(scenario_name):
        if request.method == "OPTIONS":
            return jsonify({}), 200
        if len(scenario_name) > 64:
            return jsonify({"error": "scenario_name exceeds maximum allowed length of 64 characters"}), 400

        nonlocal_run_scenario = run_scenario
        if nonlocal_run_scenario is None:
            from simulator.runner import run_scenario as nonlocal_run_scenario

        try:
            events = nonlocal_run_scenario(scenario_name)
        except Exception as e:
            logger.error(f"Failed to run scenario '{scenario_name}': {e}", exc_info=True)
            return jsonify({"error": f"Failed to run scenario: {str(e)}"}), 400

        exec_id = f"exec-{uuid.uuid4().hex}"
        now_utc = datetime.now(timezone.utc)

        # Track execution initiation in scenario_executions
        db_sess = get_session()
        try:
            exec_record = ScenarioExecution(
                id=exec_id,
                scenario_name=scenario_name,
                started_at=now_utc,
                status="running",
                event_count=0
            )
            db_sess.add(exec_record)
            db_sess.commit()
        except Exception as e:
            logger.warning(f"Could not record ScenarioExecution start for {scenario_name}: {e}")
            db_sess.rollback()
        finally:
            db_sess.close()

        # Atomic scenario execution & correlation
        db_sess = get_session()
        try:
            with correlator_transaction():
                for evt in events:
                    insert_event(evt, session=db_sess)
                    try:
                        process_event(evt, db_sess)
                    except Exception as corr_err:
                        logger.error(f"Correlation failed during scenario '{scenario_name}': {corr_err}", exc_info=True)
                        raise corr_err
                db_sess.commit()

            # Record success in ScenarioExecution
            try:
                db_exec = db_sess.query(ScenarioExecution).filter(ScenarioExecution.id == exec_id).first()
                if db_exec:
                    db_exec.status = "success"
                    db_exec.completed_at = datetime.now(timezone.utc)
                    db_exec.event_count = len(events)
                    db_sess.commit()
            except Exception as e:
                logger.warning(f"Failed to update ScenarioExecution status for {exec_id}: {e}")

            return jsonify({
                "scenario": scenario_name,
                "execution_id": exec_id,
                "event_count": len(events),
                "events": events
            }), 200
        except Exception as e:
            db_sess.rollback()
            # Update ScenarioExecution as failed
            try:
                fail_sess = get_session()
                try:
                    db_exec = fail_sess.query(ScenarioExecution).filter(ScenarioExecution.id == exec_id).first()
                    if db_exec:
                        db_exec.status = "failed"
                        db_exec.completed_at = datetime.now(timezone.utc)
                        db_exec.error_message = str(e)
                        fail_sess.commit()
                finally:
                    fail_sess.close()
            except Exception as err:
                logger.warning(f"Failed to mark ScenarioExecution failed for {exec_id}: {err}")

            logger.error(f"Correlation failed during scenario '{scenario_name}': {e}", exc_info=True)
            return jsonify({
                "error": "Correlation error",
                "execution_id": exec_id,
                "message": f"Failed to persist and correlate scenario event: {str(e)}"
            }), 500
        finally:
            db_sess.close()

    @app.route("/api/scenarios/executions", methods=["GET", "OPTIONS"])
    @require_auth({"read", "ingest", "admin"})
    def get_scenario_executions():
        if request.method == "OPTIONS":
            return jsonify({}), 200

        limit, offset = get_pagination_params()
        db = get_session()
        try:
            records = db.query(ScenarioExecution).order_by(ScenarioExecution.started_at.desc()).offset(offset).limit(limit).all()
            result = []
            for r in records:
                result.append({
                    "id": r.id,
                    "scenario_name": r.scenario_name,
                    "started_at": r.started_at.isoformat() if hasattr(r.started_at, "isoformat") else str(r.started_at),
                    "completed_at": r.completed_at.isoformat() if r.completed_at and hasattr(r.completed_at, "isoformat") else (str(r.completed_at) if r.completed_at else None),
                    "status": r.status,
                    "event_count": r.event_count,
                    "error_message": r.error_message
                })
            return jsonify(result), 200
        finally:
            db.close()


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
        origin = request.headers.get("Origin")
        if origin:
            norm_origin = origin.rstrip("/")
            allowed = app.config.get("CORS_ALLOWED_ORIGINS_SET", set())
            is_dev_or_test = app.config.get("TOKENLINE_ENV_MODE") in ("development", "test")
            if norm_origin in allowed or (is_dev_or_test and "*" in allowed):
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = (
                    "Content-Type, Authorization, X-API-Key, X-Request-ID, X-Correlation-ID"
                )
                response.headers["Access-Control-Max-Age"] = "86400"
                existing_vary = response.headers.get("Vary")
                if existing_vary:
                    if "Origin" not in existing_vary:
                        response.headers["Vary"] = f"{existing_vary}, Origin"
                else:
                    response.headers["Vary"] = "Origin"
        return response

    return app

app = create_app()

if __name__ == "__main__":
    init_db()
    # Read port from env or default to 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
