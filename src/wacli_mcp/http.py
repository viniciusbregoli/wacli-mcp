"""Optional Streamable HTTP transport for loopback or tailnet clients.

stdio is the default and preferred transport. HTTP exists for MCP clients on
another tailnet machine; it always requires a bearer token and only binds to
loopback or Tailscale addresses (enforced in HttpConfig).
"""

from __future__ import annotations

import hmac

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import HttpConfig


class BearerAuthMiddleware:
    """Rejects every HTTP request without the configured bearer token."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self._token = token.encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        supplied = b""
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                scheme, _, credential = value.partition(b" ")
                if scheme.lower() == b"bearer":
                    supplied = credential.strip()
                break
        if not hmac.compare_digest(supplied, self._token):
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b'Bearer realm="wacli-mcp"'),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
            return
        await self.app(scope, receive, send)


def _host_header(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def build_http_app(server: MCPServer, http: HttpConfig) -> ASGIApp:
    hosts = [_host_header(http.host, http.port)] + [f"{name}:{http.port}" for name in http.allowed_hostnames]
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        # MCP clients are not browsers; any request carrying a browser Origin is refused.
        allowed_origins=[],
    )
    app = server.streamable_http_app(
        transport_security=security,
        host=http.host,
        max_sessions=8,
        max_request_body_size=256 * 1024,
    )
    return BearerAuthMiddleware(app, http.token)


def run_http(server: MCPServer, http: HttpConfig) -> None:
    import uvicorn

    uvicorn.run(
        build_http_app(server, http),
        host=http.host,
        port=http.port,
        log_level="warning",
        access_log=False,
        server_header=False,
        proxy_headers=False,
        lifespan="on",
    )
