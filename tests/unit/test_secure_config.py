import os
import json
import pytest
import tempfile
from backend.collector.app import (
    create_app,
    get_environment_mode,
    validate_origin,
    validate_and_load_api_keys,
    validate_and_load_cors_origins,
    SUPPORTED_ROLES,
    PUBLISHED_DEFAULT_KEYS,
)
from backend.collector.db import init_db


class TestCollectorSecurityConfig:
    VALID_ADMIN_KEY = "strong-admin-key-production-32chars"
    VALID_INGEST_KEY = "strong-ingest-key-production-32chars"
    VALID_READ_KEY = "strong-read-key-production-32chars"
    VALID_ORIGIN = "https://dashboard.tokenline.io"

    def test_environment_mode_detection(self):
        # Explicit development
        assert get_environment_mode({"TOKENLINE_ENV": "development"}) == "development"
        assert get_environment_mode({"TOKENLINE_ENV": "dev"}) == "development"
        assert get_environment_mode({"TOKENLINE_ENV": "local"}) == "development"

        # Explicit test
        assert get_environment_mode({"TESTING": True}) == "test"
        assert get_environment_mode({"TOKENLINE_ENV": "test"}) == "test"
        assert get_environment_mode({"TOKENLINE_ENV": "testing"}) == "test"

        # Production
        assert get_environment_mode({"TOKENLINE_ENV": "production"}) == "production"
        assert get_environment_mode({"TOKENLINE_ENV": "prod"}) == "production"

        # Misspelled mode must be flagged as invalid
        assert get_environment_mode({"TOKENLINE_ENV": "prdouction"}) == "invalid"
        assert get_environment_mode({"TOKENLINE_ENV": "staging"}) == "invalid"

    def test_startup_fails_missing_production_api_credentials(self):
        with pytest.raises(ValueError) as excinfo:
            validate_and_load_api_keys("production", app_config={})
        assert "Missing required collector API credentials in production" in str(excinfo.value)

    def test_startup_fails_empty_api_key(self):
        with pytest.raises(ValueError) as excinfo:
            validate_and_load_api_keys(
                "production",
                app_config={"COLLECTOR_ADMIN_API_KEY": "   "}
            )
        assert "cannot be empty" in str(excinfo.value)

    def test_startup_rejects_published_default_credentials_in_production(self):
        for pub_key in ["tokenline-admin-secret", "tokenline-ingest-secret", "tokenline-read-secret", "admin"]:
            with pytest.raises(ValueError) as excinfo:
                validate_and_load_api_keys(
                    "production",
                    app_config={"COLLECTOR_ADMIN_API_KEY": pub_key}
                )
            assert "Published default credentials cannot be used in production" in str(excinfo.value)

    def test_startup_rejects_insufficiently_strong_credentials_in_production(self):
        with pytest.raises(ValueError) as excinfo:
            validate_and_load_api_keys(
                "production",
                app_config={"COLLECTOR_ADMIN_API_KEY": "short-key-123"}
            )
        assert "must be at least 16 characters long in production" in str(excinfo.value)

    def test_startup_rejects_malformed_json_in_api_keys_mapping(self):
        with pytest.raises(ValueError) as excinfo:
            validate_and_load_api_keys(
                "production",
                app_config={"COLLECTOR_API_KEYS": "{malformed-json: true"}
            )
        assert "contains malformed JSON" in str(excinfo.value)

    def test_startup_rejects_non_dict_json_in_api_keys_mapping(self):
        with pytest.raises(ValueError) as excinfo:
            validate_and_load_api_keys(
                "production",
                app_config={"COLLECTOR_API_KEYS": json.dumps(["admin", "ingest"])}
            )
        assert "must be a JSON object mapping keys to roles" in str(excinfo.value)

    def test_startup_rejects_unknown_credential_roles(self):
        bad_mapping = {
            "valid-strong-key-1234567890": "superuser"
        }
        with pytest.raises(ValueError) as excinfo:
            validate_and_load_api_keys(
                "production",
                app_config={"COLLECTOR_API_KEYS": json.dumps(bad_mapping)}
            )
        assert "Unsupported role 'superuser'" in str(excinfo.value)

    def test_startup_rejects_misspelled_environment_mode(self):
        with pytest.raises(ValueError) as excinfo:
            validate_and_load_api_keys(
                "invalid",
                app_config={"COLLECTOR_ADMIN_API_KEY": self.VALID_ADMIN_KEY}
            )
        assert "Unrecognized environment mode setting" in str(excinfo.value)

    def test_secret_values_never_disclosed_in_error_messages(self):
        sensitive_key = "super-secret-production-admin-key-do-not-leak"
        try:
            validate_and_load_api_keys(
                "production",
                app_config={"COLLECTOR_API_KEYS": json.dumps({sensitive_key: "invalid_role"})}
            )
        except ValueError as e:
            assert sensitive_key not in str(e)

    def test_startup_fails_missing_production_cors_origins(self):
        with pytest.raises(ValueError) as excinfo:
            validate_and_load_cors_origins("production", app_config={})
        assert "CORS_ALLOWED_ORIGINS must be explicitly configured in production" in str(excinfo.value)

    def test_startup_fails_empty_production_cors_origins(self):
        with pytest.raises(ValueError) as excinfo:
            validate_and_load_cors_origins("production", app_config={"CORS_ALLOWED_ORIGINS": "  "})
        assert "CORS_ALLOWED_ORIGINS must be explicitly configured in production" in str(excinfo.value)

    def test_startup_rejects_wildcard_cors_in_production(self):
        for wildcard_expr in ["*", "https://dashboard.tokenline.io, *", json.dumps(["https://app.io", "*"])]:
            with pytest.raises(ValueError) as excinfo:
                validate_and_load_cors_origins(
                    "production",
                    app_config={"CORS_ALLOWED_ORIGINS": wildcard_expr}
                )
            assert "Wildcard CORS origins ('*') are forbidden in production" in str(excinfo.value)

    def test_startup_rejects_malformed_cors_origins(self):
        malformed_origins = [
            "not-a-url",
            "ftp://dashboard.tokenline.io",
            "https://dashboard.tokenline.io/path/to/page",
            "https://dashboard.tokenline.io?query=param",
            "javascript:alert(1)",
        ]
        for mo in malformed_origins:
            with pytest.raises(ValueError) as excinfo:
                validate_and_load_cors_origins(
                    "production",
                    app_config={"CORS_ALLOWED_ORIGINS": mo}
                )
            assert "Malformed CORS origin" in str(excinfo.value)

    def test_valid_production_startup_succeeds(self):
        prod_config = {
            "TOKENLINE_ENV": "production",
            "COLLECTOR_ADMIN_API_KEY": self.VALID_ADMIN_KEY,
            "COLLECTOR_INGEST_API_KEY": self.VALID_INGEST_KEY,
            "COLLECTOR_READ_API_KEY": self.VALID_READ_KEY,
            "CORS_ALLOWED_ORIGINS": "https://dashboard.tokenline.io, https://app.tokenline.io:8443",
        }
        app = create_app(test_config=prod_config)
        assert app.config["TOKENLINE_ENV_MODE"] == "production"
        assert self.VALID_ADMIN_KEY in app.config["COLLECTOR_API_KEYS_MAP"]
        assert app.config["COLLECTOR_API_KEYS_MAP"][self.VALID_ADMIN_KEY] == "admin"
        assert "https://dashboard.tokenline.io" in app.config["CORS_ALLOWED_ORIGINS_SET"]
        assert "https://app.tokenline.io:8443" in app.config["CORS_ALLOWED_ORIGINS_SET"]


class TestProductionCollectorRuntimeAndCORS:
    VALID_ADMIN_KEY = "strong-admin-key-production-32chars"
    VALID_INGEST_KEY = "strong-ingest-key-production-32chars"
    VALID_READ_KEY = "strong-read-key-production-32chars"
    ALLOWED_ORIGIN = "https://dashboard.tokenline.io"
    UNTRUSTED_ORIGIN = "https://untrusted-attacker.com"

    @pytest.fixture
    def prod_client(self):
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

        prod_config = {
            "TESTING": False,
            "TOKENLINE_ENV": "production",
            "COLLECTOR_ADMIN_API_KEY": self.VALID_ADMIN_KEY,
            "COLLECTOR_INGEST_API_KEY": self.VALID_INGEST_KEY,
            "COLLECTOR_READ_API_KEY": self.VALID_READ_KEY,
            "CORS_ALLOWED_ORIGINS": self.ALLOWED_ORIGIN,
        }

        app = create_app(test_config=prod_config)
        with app.app_context():
            init_db()

        with app.test_client() as client:
            yield client

        os.close(db_fd)
        try:
            os.unlink(db_path)
        except OSError:
            pass

    def test_production_authentication_with_valid_credentials(self, prod_client):
        valid_event = {
            "event_id": "evt-prod-auth-1",
            "event_type": "token_issued",
            "time": "2026-08-07T12:20:00Z",
            "user_id": "user-prod",
            "token_hash": "a4d3b8f1c29e",
            "token_family": "family-prod",
            "ip_hash": "f3b29c9e8d1a",
            "country": "US",
            "device_id": "device-1",
            "result": "accepted"
        }

        # 1. Valid ingest credentials allow event ingestion
        res = prod_client.post(
            "/events",
            json=valid_event,
            headers={"Authorization": f"Bearer {self.VALID_INGEST_KEY}"}
        )
        assert res.status_code == 201

        # 2. Valid admin credentials allow event ingestion
        valid_event_2 = dict(valid_event, event_id="evt-prod-auth-2", token_hash="b5e4c9f2d30f")
        res_admin = prod_client.post(
            "/events",
            json=valid_event_2,
            headers={"X-API-Key": self.VALID_ADMIN_KEY}
        )
        assert res_admin.status_code == 201

        # 3. Read-only credentials cannot ingest events (403)
        valid_event_3 = dict(valid_event, event_id="evt-prod-auth-3")
        res_read = prod_client.post(
            "/events",
            json=valid_event_3,
            headers={"Authorization": f"Bearer {self.VALID_READ_KEY}"}
        )
        assert res_read.status_code == 403

        # 4. Read credentials CAN read events
        res_get = prod_client.get(
            "/events",
            headers={"Authorization": f"Bearer {self.VALID_READ_KEY}"}
        )
        assert res_get.status_code == 200

    def test_published_default_credentials_rejected_in_production(self, prod_client):
        valid_event = {
            "event_id": "evt-prod-auth-fail",
            "event_type": "token_issued",
            "time": "2026-08-07T12:20:00Z",
            "user_id": "user-prod",
            "token_hash": "a4d3b8f1c29e",
            "token_family": "family-prod",
            "ip_hash": "f3b29c9e8d1a",
            "country": "US",
            "device_id": "device-1",
            "result": "accepted"
        }

        # Attempt to use published default admin key in production
        res = prod_client.post(
            "/events",
            json=valid_event,
            headers={"Authorization": "Bearer tokenline-admin-secret"}
        )
        assert res.status_code == 401
        assert res.get_json()["error"] == "Unauthorized"

        # Attempt to use published default ingest key in production
        res_ingest = prod_client.post(
            "/events",
            json=valid_event,
            headers={"X-API-Key": "tokenline-ingest-secret"}
        )
        assert res_ingest.status_code == 401
        assert res_ingest.get_json()["error"] == "Unauthorized"

    def test_cors_grants_access_to_configured_frontend_origin(self, prod_client):
        res = prod_client.get(
            "/events",
            headers={
                "Origin": self.ALLOWED_ORIGIN,
                "Authorization": f"Bearer {self.VALID_READ_KEY}"
            }
        )
        assert res.status_code == 200
        assert res.headers.get("Access-Control-Allow-Origin") == self.ALLOWED_ORIGIN
        assert "GET, POST, OPTIONS" in res.headers.get("Access-Control-Allow-Methods", "")
        headers = res.headers.get("Access-Control-Allow-Headers", "")
        assert "Content-Type" in headers
        assert "Authorization" in headers
        assert "X-API-Key" in headers
        assert "X-Request-ID" in headers
        assert "X-Correlation-ID" in headers

    def test_cors_denies_access_to_unconfigured_origins(self, prod_client):
        res = prod_client.get(
            "/events",
            headers={
                "Origin": self.UNTRUSTED_ORIGIN,
                "Authorization": f"Bearer {self.VALID_READ_KEY}"
            }
        )
        assert res.status_code == 200
        assert "Access-Control-Allow-Origin" not in res.headers

    def test_cors_preflight_options_for_allowed_origin(self, prod_client):
        res = prod_client.open(
            "/events",
            method="OPTIONS",
            headers={
                "Origin": self.ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization, X-API-Key"
            }
        )
        assert res.status_code == 200
        assert res.headers.get("Access-Control-Allow-Origin") == self.ALLOWED_ORIGIN
        assert "POST" in res.headers.get("Access-Control-Allow-Methods", "")
        assert "Authorization" in res.headers.get("Access-Control-Allow-Headers", "")

    def test_cors_preflight_options_for_untrusted_origin_rejected(self, prod_client):
        res = prod_client.open(
            "/events",
            method="OPTIONS",
            headers={
                "Origin": self.UNTRUSTED_ORIGIN,
                "Access-Control-Request-Method": "POST"
            }
        )
        assert res.status_code == 403
        assert "Access-Control-Allow-Origin" not in res.headers
        assert res.get_json()["error"] == "Forbidden"
