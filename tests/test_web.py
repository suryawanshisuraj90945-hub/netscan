import pytest
from fastapi.testclient import TestClient
from netscan.main import app
from netscan.models import Subnet


def _login(client: TestClient, password: str = "admin", api_key: str | None = None) -> str:
    """Login to dashboard. If no api_key given, bootstraps one. Returns raw_key."""
    if api_key is None:
        res = client.post("/api/v1/auth/keys/bootstrap", json={"name": "test-key"})
        assert res.status_code == 201, res.text
        api_key = res.json()["raw_key"]
    res = client.post(
        "/login",
        data={"password": password, "api_key": api_key},
        follow_redirects=False,
    )
    assert res.status_code == 303, f"Login failed: {res.status_code}"
    return api_key


def test_unauthenticated_redirects_to_login(client: TestClient):
    for path in ["/", "/provision", "/scans", "/settings"]:
        res = client.get(path, follow_redirects=False)
        assert res.status_code == 303, f"{path} should redirect when unauthenticated"
        assert "/login" in res.headers["location"]


def test_login_page_loads(client: TestClient):
    res = client.get("/login")
    assert res.status_code == 200
    assert "Sign in to the dashboard" in res.text


def test_login_wrong_password(client: TestClient):
    res = client.post("/login", data={"password": "wrong", "api_key": "ns_live_fake"}, follow_redirects=False)
    assert res.status_code == 200
    assert "Invalid password" in res.text


def test_login_invalid_api_key(client: TestClient):
    res = client.post("/login", data={"password": "admin", "api_key": "ns_live_fake"}, follow_redirects=False)
    assert res.status_code == 200
    assert "Invalid or revoked API key" in res.text


def test_login_success_redirects(client: TestClient):
    _login(client)
    res = client.get("/", follow_redirects=False)
    assert res.status_code == 200


def test_dashboard_views(client: TestClient):
    _login(client)

    # 1. Main Dashboard Index
    res = client.get("/")
    assert res.status_code == 200
    assert "Network Subnets & IP Pools" in res.text

    # 2. Provision View
    prov_res = client.get("/provision")
    assert prov_res.status_code == 200
    assert "Available IP Provisioner" in prov_res.text

    # 3. Scans View
    scans_res = client.get("/scans")
    assert scans_res.status_code == 200
    assert "Scan Job History" in scans_res.text

    # 4. Settings View
    settings_res = client.get("/settings")
    assert settings_res.status_code == 200
    assert "API Keys" in settings_res.text


def test_matrix_and_drawer_views(auth_client):
    client, headers = auth_client

    # Login to dashboard
    _login(client, api_key=headers["X-API-Key"])

    # Create Subnet via API
    res = client.post("/api/v1/subnets", json={"cidr": "172.16.10.0/29", "name": "Lab"}, headers=headers)
    subnet_id = res.json()["id"]

    # Matrix HTML view
    matrix_res = client.get(f"/subnets/{subnet_id}/matrix")
    assert matrix_res.status_code == 200
    assert "172.16.10.0/29" in matrix_res.text

    # IP Drawer for untracked IP should return 404 (no phantom IPs)
    drawer_res = client.get("/web/ips/172.16.10.1/drawer")
    assert drawer_res.status_code == 404


def test_logout_clears_session(client: TestClient):
    _login(client)

    # Verify access
    res = client.get("/")
    assert res.status_code == 200

    # Logout
    res = client.get("/logout", follow_redirects=False)
    assert res.status_code == 303
    assert "/login" in res.headers["location"]

    # Verify access denied after logout
    res = client.get("/", follow_redirects=False)
    assert res.status_code == 303


def test_login_already_authenticated_redirects(client: TestClient):
    _login(client)

    # Visiting login when already logged in should redirect to /
    res = client.get("/login", follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/"


def test_login_rejected_api_key(client: TestClient):
    """Create a key, login, then revoke it and try login again."""
    # Bootstrap a key
    res = client.post("/api/v1/auth/keys/bootstrap", json={"name": "test-key"})
    raw_key = res.json()["raw_key"]
    key_id = res.json()["id"]

    # Revoke it
    client.delete(f"/api/v1/auth/keys/{key_id}", headers={"X-API-Key": raw_key})

    # Try to login with revoked key
    res = client.post(
        "/login",
        data={"password": "admin", "api_key": raw_key},
        follow_redirects=False,
    )
    assert res.status_code == 200
    assert "Invalid or revoked API key" in res.text


def test_api_keys_in_settings_template(client: TestClient):
    """Verify that API key names are shown in settings after login."""
    _login(client)
    res = client.get("/settings")
    assert res.status_code == 200
    assert "test-key" in res.text


def test_dashboard_password_injected_in_template(client: TestClient):
    """Verify the api_key JS variable is present in the rendered HTML."""
    _login(client)
    res = client.get("/")
    assert res.status_code == 200
    assert "NETSCAN_API_KEY" in res.text


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
