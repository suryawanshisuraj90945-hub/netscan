import re
import pytest
from fastapi.testclient import TestClient
from netscan.main import app
from netscan.models import Subnet


def _get_csrf_token(client: TestClient) -> str:
    """Extract the CSRF token from the login page."""
    res = client.get("/login")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', res.text)
    assert match, "CSRF token not found in login page"
    return match.group(1)


def _login(client: TestClient, password: str = "admin", api_key: str | None = None) -> str:
    """Login to dashboard. If no api_key given, bootstraps one. Returns raw_key."""
    if api_key is None:
        res = client.post("/api/v1/auth/keys/bootstrap", json={"name": "test-key"})
        assert res.status_code == 201, res.text
        api_key = res.json()["raw_key"]
    csrf_token = _get_csrf_token(client)
    res = client.post(
        "/login",
        data={"password": password, "api_key": api_key, "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert res.status_code == 303, f"Login failed: {res.status_code}"
    return api_key


# ---------------------------------------------------------------------------
# Unauthenticated access tests
# ---------------------------------------------------------------------------

def test_unauthenticated_redirects_to_login(client: TestClient):
    for path in ["/", "/provision", "/scans", "/settings"]:
        res = client.get(path, follow_redirects=False)
        assert res.status_code == 303, f"{path} should redirect when unauthenticated"
        assert "/login" in res.headers["location"]


def test_unauthenticated_drawer_redirects(client: TestClient):
    """Unauthenticated access to /web/ips/{ip}/drawer must be redirected."""
    res = client.get("/web/ips/10.0.0.1/drawer", follow_redirects=False)
    assert res.status_code == 303
    assert "/login" in res.headers["location"]


def test_unauthenticated_provision_redirects(client: TestClient):
    res = client.get("/provision", follow_redirects=False)
    assert res.status_code == 303
    assert "/login" in res.headers["location"]


def test_unauthenticated_scans_redirects(client: TestClient):
    res = client.get("/scans", follow_redirects=False)
    assert res.status_code == 303
    assert "/login" in res.headers["location"]


def test_unauthenticated_settings_redirects(client: TestClient):
    res = client.get("/settings", follow_redirects=False)
    assert res.status_code == 303
    assert "/login" in res.headers["location"]


def test_unauthenticated_matrix_redirects(client: TestClient):
    import uuid
    fake_id = uuid.uuid4()
    res = client.get(f"/subnets/{fake_id}/matrix", follow_redirects=False)
    assert res.status_code == 303
    assert "/login" in res.headers["location"]


# ---------------------------------------------------------------------------
# Login flow tests
# ---------------------------------------------------------------------------

def test_login_page_loads(client: TestClient):
    res = client.get("/login")
    assert res.status_code == 200
    assert "Sign in to the dashboard" in res.text
    assert "csrf_token" in res.text


def test_login_csrf_token_present(client: TestClient):
    """Login page must contain a hidden CSRF token field."""
    res = client.get("/login")
    assert 'name="csrf_token"' in res.text
    assert 'type="hidden"' in res.text


def test_login_wrong_password(client: TestClient):
    csrf_token = _get_csrf_token(client)
    res = client.post(
        "/login",
        data={"password": "wrong", "api_key": "ns_live_fake", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert res.status_code == 200
    assert "Invalid password" in res.text


def test_login_invalid_api_key(client: TestClient):
    csrf_token = _get_csrf_token(client)
    res = client.post(
        "/login",
        data={"password": "admin", "api_key": "ns_live_fake", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert res.status_code == 200
    assert "Invalid or revoked API key" in res.text


def test_login_success_redirects(client: TestClient):
    _login(client)
    res = client.get("/", follow_redirects=False)
    assert res.status_code == 200


def test_login_already_authenticated_redirects(client: TestClient):
    _login(client)
    res = client.get("/login", follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/"


def test_login_rejected_api_key(client: TestClient):
    """Create a key, login, then revoke it and try login again."""
    res = client.post("/api/v1/auth/keys/bootstrap", json={"name": "test-key"})
    raw_key = res.json()["raw_key"]
    key_id = res.json()["id"]

    client.delete(f"/api/v1/auth/keys/{key_id}", headers={"X-API-Key": raw_key})

    csrf_token = _get_csrf_token(client)
    res = client.post(
        "/login",
        data={"password": "admin", "api_key": raw_key, "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert res.status_code == 200
    assert "Invalid or revoked API key" in res.text


# ---------------------------------------------------------------------------
# CSRF protection tests
# ---------------------------------------------------------------------------

def test_login_without_csrf_token_rejected(client: TestClient):
    """Login POST without CSRF token must be rejected."""
    res = client.post(
        "/login",
        data={"password": "admin", "api_key": "ns_live_fake"},
        follow_redirects=False,
    )
    assert res.status_code == 200
    assert "Invalid or expired form token" in res.text


def test_login_with_invalid_csrf_token_rejected(client: TestClient):
    """Login POST with a bogus CSRF token must be rejected."""
    res = client.post(
        "/login",
        data={"password": "admin", "api_key": "ns_live_fake", "csrf_token": "bogus-token"},
        follow_redirects=False,
    )
    assert res.status_code == 200
    assert "Invalid or expired form token" in res.text


def test_login_with_valid_csrf_token_succeeds(client: TestClient):
    """Login POST with a valid CSRF token must succeed."""
    csrf_token = _get_csrf_token(client)
    res = client.post(
        "/login",
        data={"password": "admin", "api_key": "ns_live_fake", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    # Should NOT get CSRF error — gets API key error instead (which means CSRF passed)
    assert res.status_code == 200
    assert "Invalid or expired form token" not in res.text


# ---------------------------------------------------------------------------
# Logout tests (POST only)
# ---------------------------------------------------------------------------

def test_get_logout_does_not_perform_logout(client: TestClient):
    """GET /logout must not clear the session (CSRF protection)."""
    _login(client)
    res = client.get("/", follow_redirects=False)
    assert res.status_code == 200

    # GET /logout should not be a valid route (405 Method Not Allowed)
    res = client.get("/logout", follow_redirects=False)
    assert res.status_code == 405

    # Session should still be valid
    res = client.get("/", follow_redirects=False)
    assert res.status_code == 200


def test_post_logout_clears_session(client: TestClient):
    """POST /logout must clear the session and redirect to /login."""
    _login(client)

    # Verify access
    res = client.get("/")
    assert res.status_code == 200

    # POST Logout
    res = client.post("/logout", follow_redirects=False)
    assert res.status_code == 303
    assert "/login" in res.headers["location"]

    # Verify access denied after logout
    res = client.get("/", follow_redirects=False)
    assert res.status_code == 303


# ---------------------------------------------------------------------------
# Dashboard view tests (updated for POST logout)
# ---------------------------------------------------------------------------

def test_dashboard_views(client: TestClient):
    _login(client)

    res = client.get("/")
    assert res.status_code == 200
    assert "Network Subnets & IP Pools" in res.text

    prov_res = client.get("/provision")
    assert prov_res.status_code == 200
    assert "Available IP Provisioner" in prov_res.text

    scans_res = client.get("/scans")
    assert scans_res.status_code == 200
    assert "Scan Job History" in scans_res.text

    settings_res = client.get("/settings")
    assert settings_res.status_code == 200
    assert "API Keys" in settings_res.text


def test_matrix_and_drawer_views(auth_client):
    client, headers = auth_client
    _login(client, api_key=headers["X-API-Key"])

    res = client.post("/api/v1/subnets", json={"cidr": "172.16.10.0/29", "name": "Lab"}, headers=headers)
    subnet_id = res.json()["id"]

    matrix_res = client.get(f"/subnets/{subnet_id}/matrix")
    assert matrix_res.status_code == 200
    assert "172.16.10.0/29" in matrix_res.text

    drawer_res = client.get("/web/ips/172.16.10.1/drawer")
    assert drawer_res.status_code == 404


def test_api_keys_in_settings_template(client: TestClient):
    _login(client)
    res = client.get("/settings")
    assert res.status_code == 200
    assert "test-key" in res.text


def test_dashboard_password_injected_in_template(client: TestClient):
    _login(client)
    res = client.get("/")
    assert res.status_code == 200
    assert "NETSCAN_API_KEY" in res.text


def test_logout_button_is_post_form(client: TestClient):
    """The logout button in the navbar must submit via POST form."""
    _login(client)
    res = client.get("/")
    assert res.status_code == 200
    assert 'method="POST"' in res.text
    assert 'action="/logout"' in res.text


# ---------------------------------------------------------------------------
# SECRET_KEY fallback test
# ---------------------------------------------------------------------------

def test_session_middleware_uses_configured_secret_key():
    """SessionMiddleware must use SECRET_KEY from config, not a hardcoded fallback."""
    from netscan.config import settings
    # Verify the config does not contain the fallback value
    assert settings.SECRET_KEY != "dev-fallback-secret", \
        "SECRET_KEY must not be the hardcoded fallback"
    # Verify the app was constructed with the config value (not the fallback string)
    # by checking that main.py passes settings.SECRET_KEY directly
    import inspect
    import netscan.main as main_module
    source = inspect.getsource(main_module)
    assert '"dev-fallback-secret"' not in source, \
        "main.py must not contain the hardcoded fallback secret"


# ---------------------------------------------------------------------------
# Production password validation test
# ---------------------------------------------------------------------------

def test_production_rejects_default_dashboard_password():
    """validate_for_production must raise if DASHBOARD_PASSWORD is still 'admin'."""
    from netscan.config import Settings
    settings = Settings(DEBUG=False, SECRET_KEY="test-secret-key-12345", DASHBOARD_PASSWORD="admin")
    with pytest.raises(ValueError, match="DASHBOARD_PASSWORD must be changed"):
        settings.validate_for_production()


def test_production_allows_custom_dashboard_password():
    """validate_for_production must pass with a non-default DASHBOARD_PASSWORD."""
    from netscan.config import Settings
    settings = Settings(DEBUG=False, SECRET_KEY="test-secret-key-12345", DASHBOARD_PASSWORD="s3cure-p@ss!", ALLOWED_ORIGINS="https://example.com")
    settings.validate_for_production()  # Should not raise


def test_debug_mode_allows_default_dashboard_password():
    """DEBUG=True must allow the default DASHBOARD_PASSWORD (for tests)."""
    from netscan.config import Settings
    settings = Settings(DEBUG=True, DASHBOARD_PASSWORD="admin")
    settings.validate_for_production()  # Should not raise


# ---------------------------------------------------------------------------
# Health endpoint remains public
# ---------------------------------------------------------------------------

def test_health_endpoint_public(client: TestClient):
    """Health endpoint must be accessible without authentication."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["service"] == "NetScan"
