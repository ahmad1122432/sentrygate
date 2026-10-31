"""Gateway pipeline tests: the backend is replaced by an in-process fake, no network needed."""
import httpx, pytest
from fastapi.testclient import TestClient
import gateway

TOKEN = "test-token"


@pytest.fixture()
def gw(monkeypatch):
    def fake_backend(request: httpx.Request):
        if request.url.path == "/login":
            return httpx.Response(401, json={"error": "bad"})
        return httpx.Response(200, json={"ok": True}, headers={"set-cookie": "a=1"})
    monkeypatch.setattr(gateway, "client", httpx.AsyncClient(transport=httpx.MockTransport(fake_backend)))
    monkeypatch.setenv("SENTRY_TOKEN", TOKEN)
    for d in (gateway.hits, gateway.fails, gateway.ids):
        d.clear()
    return TestClient(gateway.app)


def test_clean_request_forwarded_with_security_headers(gw):
    r = gw.get("/search?q=wallet")
    assert r.status_code == 200 and r.headers["x-frame-options"] == "DENY"


def test_attack_blocked_in_block_mode(gw, monkeypatch):
    monkeypatch.setattr(gateway, "MODE", "block")
    r = gw.get("/search?q=<script>alert(1)</script>")
    assert r.status_code == 403 and "reference" in r.json()


def test_attack_only_logged_in_monitor_mode(gw, monkeypatch):
    monkeypatch.setattr(gateway, "MODE", "monitor")
    assert gw.get("/search?q=<script>alert(1)</script>").status_code == 200
    ev = gw.get("/_sentry/api/events?threats=true", headers={"x-sentry-token": TOKEN}).json()
    assert ev[0]["action"] == "monitored"


def test_rate_limit(gw, monkeypatch):
    monkeypatch.setattr(gateway, "RATE_LIMIT", 5)
    codes = [gw.get("/").status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and 403 in codes[5:]


def test_bruteforce_lockout_after_failed_logins(gw):
    codes = [gw.post("/login", json={"u": "a", "p": str(i)}).status_code for i in range(8)]
    assert codes[:5] == [401] * 5 and codes[-1] == 403


def test_bola_enumeration_flagged(gw):
    codes = [gw.get(f"/api/users/{i}").status_code for i in range(1, 15)]
    assert 403 in codes


def test_dashboard_requires_token(gw):
    assert gw.get("/_sentry/").status_code == 403
    assert gw.get("/_sentry/?token=" + TOKEN).status_code == 200
    assert gw.get("/_sentry/api/stats").status_code == 403
    assert "total" in gw.get("/_sentry/api/stats", headers={"x-sentry-token": TOKEN}).json()
