from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from wacli_mcp.config import HttpConfig
from wacli_mcp.http import build_http_app
from wacli_mcp.server import build_server

TOKEN = "k" * 48
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
}
HEADERS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


@pytest.fixture
def client(fake):
    http = HttpConfig(host="127.0.0.1", port=8765, token=TOKEN)
    app = build_http_app(build_server(fake.config()), http)
    with TestClient(app, base_url="http://127.0.0.1:8765") as c:
        yield c


def test_missing_token_is_rejected(client):
    response = client.post("/mcp", json=INIT, headers=HEADERS)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


def test_wrong_token_is_rejected(client):
    response = client.post("/mcp", json=INIT, headers={**HEADERS, "authorization": "Bearer " + "x" * 48})
    assert response.status_code == 401


def test_valid_token_initializes(client):
    response = client.post("/mcp", json=INIT, headers={**HEADERS, "authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200, response.text


def test_unexpected_host_is_rejected(client):
    headers = {**HEADERS, "authorization": f"Bearer {TOKEN}", "host": "evil.example:8765"}
    response = client.post("/mcp", json=INIT, headers=headers)
    assert response.status_code in (400, 421)


def test_browser_origin_is_rejected(client):
    headers = {**HEADERS, "authorization": f"Bearer {TOKEN}", "origin": "http://evil.example"}
    response = client.post("/mcp", json=INIT, headers=headers)
    assert response.status_code == 403


def test_localhost_is_accepted_on_a_loopback_listener(client):
    headers = {**HEADERS, "authorization": f"Bearer {TOKEN}", "host": "localhost:8765"}
    response = client.post("/mcp", json=INIT, headers=headers)
    assert response.status_code == 200


def test_localhost_is_not_added_for_a_tailnet_listener(fake):
    http = HttpConfig(host="100.100.1.2", port=8765, token=TOKEN)
    app = build_http_app(build_server(fake.config()), http)
    with TestClient(app, base_url="http://100.100.1.2:8765") as c:
        headers = {**HEADERS, "authorization": f"Bearer {TOKEN}", "host": "localhost:8765"}
        assert c.post("/mcp", json=INIT, headers=headers).status_code in (400, 421)
        headers["host"] = "100.100.1.2:8765"
        assert c.post("/mcp", json=INIT, headers=headers).status_code == 200
