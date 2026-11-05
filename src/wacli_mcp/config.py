"""Operator configuration.

Everything security-relevant (which binary, which store, which chats) is fixed
here from environment variables at startup. Nothing in this module is reachable
from tool arguments, so a model cannot redirect the server to another store or
executable.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

NetworkIsolation = Literal["require", "auto", "off"]

ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
JID_RE = re.compile(r"^[0-9A-Za-z._:+-]{1,64}@(s\.whatsapp\.net|g\.us|lid|newsletter|broadcast|c\.us)$")

# Tailscale hands out addresses from these ranges. Binding the HTTP transport
# anywhere else (LAN, 0.0.0.0) is refused so the endpoint stays local or tailnet-only.
TAILNET_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
)

MIN_TOKEN_LENGTH = 32


class ConfigError(ValueError):
    """Raised when the operator configuration is unsafe or invalid."""


def _int(env: Mapping[str, str], key: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{key} must be between {lo} and {hi}")
    return value


def _float(env: Mapping[str, str], key: str, default: float, lo: float, hi: float) -> float:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a number") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{key} must be between {lo} and {hi}")
    return value


def _jid_set(env: Mapping[str, str], key: str) -> frozenset[str]:
    raw = env.get(key, "")
    items = [item.strip() for item in raw.split(",") if item.strip()]
    for item in items:
        if not JID_RE.match(item):
            raise ConfigError(f"{key} entries must be full JIDs (for example 15551234567@s.whatsapp.net), got {item!r}")
    return frozenset(items)


def _check_not_writable_by_others(path: Path, what: str) -> os.stat_result:
    st = path.stat()
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(f"{what} {path} is writable by group or others")
    if st.st_uid not in (os.getuid(), 0):
        raise ConfigError(f"{what} {path} is owned by uid {st.st_uid}, expected the current user or root")
    return st


def validate_executable(path: Path, *, sha256: str | None = None) -> Path:
    """Resolve and vet an executable the server will spawn."""
    if not path.is_absolute():
        raise ConfigError(f"executable path must be absolute: {path}")
    resolved = path.resolve(strict=False)
    if not resolved.is_file():
        raise ConfigError(f"executable not found: {path}")
    if not os.access(resolved, os.X_OK):
        raise ConfigError(f"not executable: {resolved}")
    # A writable binary or parent directory would let another local user swap
    # the program we run with the owner's WhatsApp data in reach.
    _check_not_writable_by_others(resolved, "executable")
    _check_not_writable_by_others(resolved.parent, "executable directory")
    if sha256:
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if digest.lower() != sha256.strip().lower():
            raise ConfigError(f"sha256 mismatch for {resolved}")
    return resolved


def probe_network_isolation(unshare: Path) -> bool:
    """Return True if an unprivileged empty network namespace can be created."""
    try:
        result = subprocess.run(
            [str(unshare), "-rn", "true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            env={"PATH": "/usr/bin:/bin"},
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


@dataclass(frozen=True)
class Config:
    wacli_bin: Path
    home: Path
    store_dir: Path | None = None
    account: str | None = None
    timeout_s: float = 20.0
    max_output_bytes: int = 2 * 1024 * 1024
    max_concurrency: int = 2
    rate_limit_per_minute: int = 60
    max_text_chars: int = 4000
    allowed_chats: frozenset[str] = field(default_factory=frozenset)
    denied_chats: frozenset[str] = field(default_factory=frozenset)
    audit_log: Path | None = None
    # Command prefix that puts every wacli call in an empty network namespace.
    # Empty tuple means no isolation.
    sandbox_prefix: tuple[str, ...] = ()

    @property
    def network_isolated(self) -> bool:
        return bool(self.sandbox_prefix)

    def chat_visible(self, jid: str | None) -> bool:
        if not jid:
            # Rows without a chat identity cannot be checked against an allowlist.
            return not self.allowed_chats
        if jid in self.denied_chats:
            return False
        if self.allowed_chats and jid not in self.allowed_chats:
            return False
        return True

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        env = os.environ if env is None else env

        home = Path(env.get("WACLI_MCP_HOME") or env.get("HOME") or str(Path.home()))
        if not home.is_absolute():
            raise ConfigError("HOME must be absolute")

        bin_raw = env.get("WACLI_MCP_BIN", "").strip()
        if bin_raw:
            bin_path = Path(bin_raw)
        else:
            default = home / ".local" / "bin" / "wacli"
            found = shutil.which("wacli")
            bin_path = default if default.exists() else Path(found) if found else default
        wacli_bin = validate_executable(bin_path, sha256=env.get("WACLI_MCP_BIN_SHA256") or None)

        store_raw = env.get("WACLI_MCP_STORE", "").strip()
        account_raw = env.get("WACLI_MCP_ACCOUNT", "").strip()
        if store_raw and account_raw:
            raise ConfigError("set WACLI_MCP_STORE or WACLI_MCP_ACCOUNT, not both")
        store_dir = None
        if store_raw:
            store_dir = Path(store_raw)
            if not store_dir.is_absolute():
                raise ConfigError("WACLI_MCP_STORE must be absolute")
            if not store_dir.is_dir():
                raise ConfigError(f"WACLI_MCP_STORE does not exist: {store_dir}")
        account = None
        if account_raw:
            if not ACCOUNT_RE.match(account_raw):
                raise ConfigError("WACLI_MCP_ACCOUNT has invalid characters")
            account = account_raw

        allowed = _jid_set(env, "WACLI_MCP_ALLOWED_CHATS")
        denied = _jid_set(env, "WACLI_MCP_DENIED_CHATS")
        if allowed & denied:
            raise ConfigError("a JID cannot be both allowed and denied")

        audit_raw = env.get("WACLI_MCP_AUDIT_LOG", "").strip()
        audit_log = Path(audit_raw) if audit_raw else None
        if audit_log and not audit_log.is_absolute():
            raise ConfigError("WACLI_MCP_AUDIT_LOG must be absolute")
        if audit_log and not audit_log.parent.is_dir():
            raise ConfigError(f"directory for WACLI_MCP_AUDIT_LOG does not exist: {audit_log.parent}")

        mode = env.get("WACLI_MCP_NETWORK_ISOLATION", "require").strip().lower() or "require"
        if mode not in ("require", "auto", "off"):
            raise ConfigError("WACLI_MCP_NETWORK_ISOLATION must be require, auto, or off")
        sandbox_prefix: tuple[str, ...] = ()
        if mode != "off":
            unshare = Path(env.get("WACLI_MCP_UNSHARE", "/usr/bin/unshare"))
            usable = False
            try:
                unshare = validate_executable(unshare)
                usable = probe_network_isolation(unshare)
            except ConfigError:
                usable = False
            if usable:
                sandbox_prefix = (str(unshare), "-rn", "--")
            elif mode == "require":
                raise ConfigError(
                    "network isolation is required but `unshare -rn` is unavailable; "
                    "set WACLI_MCP_NETWORK_ISOLATION=auto or off to run without it"
                )

        return cls(
            wacli_bin=wacli_bin,
            home=home,
            store_dir=store_dir,
            account=account,
            timeout_s=_float(env, "WACLI_MCP_TIMEOUT_S", 20.0, 1.0, 120.0),
            max_output_bytes=_int(env, "WACLI_MCP_MAX_OUTPUT_BYTES", 2 * 1024 * 1024, 64 * 1024, 32 * 1024 * 1024),
            max_concurrency=_int(env, "WACLI_MCP_MAX_CONCURRENCY", 2, 1, 8),
            rate_limit_per_minute=_int(env, "WACLI_MCP_RATE_LIMIT_PER_MIN", 60, 1, 600),
            max_text_chars=_int(env, "WACLI_MCP_MAX_TEXT_CHARS", 4000, 200, 100_000),
            allowed_chats=allowed,
            denied_chats=denied,
            audit_log=audit_log,
            sandbox_prefix=sandbox_prefix,
        )


@dataclass(frozen=True)
class HttpConfig:
    host: str
    port: int
    token: str
    allowed_hostnames: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> HttpConfig:
        env = os.environ if env is None else env
        host = env.get("WACLI_MCP_HTTP_HOST", "127.0.0.1").strip()
        try:
            addr = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ConfigError("WACLI_MCP_HTTP_HOST must be an IP address (loopback or Tailscale)") from exc
        if not (addr.is_loopback or any(addr in net for net in TAILNET_NETWORKS)):
            raise ConfigError(
                f"refusing to bind {host}: only loopback or Tailscale addresses "
                "(100.64.0.0/10, fd7a:115c:a1e0::/48) are allowed"
            )
        port = _int(env, "WACLI_MCP_HTTP_PORT", 8765, 1024, 65535)

        token_file = env.get("WACLI_MCP_TOKEN_FILE", "").strip()
        if not token_file:
            raise ConfigError("HTTP transport requires WACLI_MCP_TOKEN_FILE (a mode 600 file holding a bearer token)")
        path = Path(token_file)
        if not path.is_absolute() or not path.is_file():
            raise ConfigError("WACLI_MCP_TOKEN_FILE must be an absolute path to an existing file")
        st = path.stat()
        if st.st_mode & 0o077:
            raise ConfigError(f"{path} must not be readable or writable by group or others (chmod 600)")
        if st.st_uid != os.getuid():
            raise ConfigError(f"{path} must be owned by the current user")
        token = path.read_text(encoding="utf-8").strip()
        if len(token) < MIN_TOKEN_LENGTH:
            raise ConfigError(f"bearer token must be at least {MIN_TOKEN_LENGTH} characters")

        hostnames = tuple(h.strip() for h in env.get("WACLI_MCP_ALLOWED_HOSTNAMES", "").split(",") if h.strip())
        for name in hostnames:
            if not re.match(r"^[A-Za-z0-9.-]{1,253}$", name):
                raise ConfigError(f"invalid hostname in WACLI_MCP_ALLOWED_HOSTNAMES: {name!r}")
        return cls(host=host, port=port, token=token, allowed_hostnames=hostnames)
