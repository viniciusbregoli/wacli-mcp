from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from wacli_mcp.config import Config, ConfigError, HttpConfig, validate_executable


def env_for(fake, **extra) -> dict[str, str]:
    env = {
        "HOME": str(fake.home),
        "WACLI_MCP_BIN": str(fake.path),
        "WACLI_MCP_NETWORK_ISOLATION": "off",
    }
    env.update(extra)
    return env


def test_defaults_from_env(fake):
    cfg = Config.from_env(env_for(fake))
    assert cfg.wacli_bin == fake.path
    assert cfg.store_dir is None and cfg.account is None
    assert cfg.sandbox_prefix == ()
    assert cfg.rate_limit_per_minute == 60


def test_relative_binary_rejected():
    with pytest.raises(ConfigError, match="absolute"):
        validate_executable(Path("wacli"))


def test_group_writable_binary_rejected(fake):
    fake.path.chmod(0o770)
    with pytest.raises(ConfigError, match="writable by group or others"):
        validate_executable(fake.path)


def test_world_writable_directory_rejected(fake):
    fake.path.parent.chmod(0o777)
    try:
        with pytest.raises(ConfigError, match="directory"):
            validate_executable(fake.path)
    finally:
        fake.path.parent.chmod(0o700)


def test_sha256_pin(fake):
    digest = hashlib.sha256(fake.path.read_bytes()).hexdigest()
    assert validate_executable(fake.path, sha256=digest) == fake.path.resolve()
    with pytest.raises(ConfigError, match="sha256 mismatch"):
        validate_executable(fake.path, sha256="0" * 64)


def test_store_and_account_are_exclusive(fake):
    with pytest.raises(ConfigError, match="not both"):
        Config.from_env(env_for(fake, WACLI_MCP_STORE=str(fake.home), WACLI_MCP_ACCOUNT="work"))


def test_bad_account_name(fake):
    with pytest.raises(ConfigError, match="invalid characters"):
        Config.from_env(env_for(fake, WACLI_MCP_ACCOUNT="../etc"))


def test_chat_lists_require_full_jids(fake):
    with pytest.raises(ConfigError, match="full JIDs"):
        Config.from_env(env_for(fake, WACLI_MCP_ALLOWED_CHATS="Ada Lovelace"))
    with pytest.raises(ConfigError, match="both allowed and denied"):
        jid = "15550000001@s.whatsapp.net"
        Config.from_env(env_for(fake, WACLI_MCP_ALLOWED_CHATS=jid, WACLI_MCP_DENIED_CHATS=jid))


def test_audit_log_directory_must_exist(fake, tmp_path):
    with pytest.raises(ConfigError, match="does not exist"):
        Config.from_env(env_for(fake, WACLI_MCP_AUDIT_LOG=str(tmp_path / "missing" / "audit.jsonl")))


def test_limits_are_bounded(fake):
    with pytest.raises(ConfigError, match="between"):
        Config.from_env(env_for(fake, WACLI_MCP_TIMEOUT_S="9999"))


def test_isolation_required_but_unavailable(fake):
    env = env_for(fake, WACLI_MCP_NETWORK_ISOLATION="require", WACLI_MCP_UNSHARE="/nonexistent/unshare")
    with pytest.raises(ConfigError, match="network isolation is required"):
        Config.from_env(env)
    env["WACLI_MCP_NETWORK_ISOLATION"] = "auto"
    assert Config.from_env(env).sandbox_prefix == ()


def test_chat_visibility():
    cfg = Config(wacli_bin=Path("/bin/true"), home=Path("/tmp"), denied_chats=frozenset({"1@s.whatsapp.net"}))
    assert not cfg.chat_visible("1@s.whatsapp.net")
    assert cfg.chat_visible("2@s.whatsapp.net")
    cfg = Config(wacli_bin=Path("/bin/true"), home=Path("/tmp"), allowed_chats=frozenset({"2@s.whatsapp.net"}))
    assert cfg.chat_visible("2@s.whatsapp.net")
    assert not cfg.chat_visible("3@s.whatsapp.net")
    assert not cfg.chat_visible(None)


def token_file(tmp_path: Path, token: str = "t" * 40, mode: int = 0o600) -> Path:
    path = tmp_path / "token"
    path.write_text(token)
    path.chmod(mode)
    return path


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::", "8.8.8.8"])
def test_http_refuses_non_local_hosts(tmp_path, host):
    with pytest.raises(ConfigError, match="refusing to bind|must be an IP"):
        HttpConfig.from_env({"WACLI_MCP_HTTP_HOST": host, "WACLI_MCP_TOKEN_FILE": str(token_file(tmp_path))})


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "100.100.100.100", "fd7a:115c:a1e0::1"])
def test_http_accepts_loopback_and_tailnet(tmp_path, host):
    cfg = HttpConfig.from_env({"WACLI_MCP_HTTP_HOST": host, "WACLI_MCP_TOKEN_FILE": str(token_file(tmp_path))})
    assert cfg.host == host and cfg.port == 8765


def test_http_requires_private_strong_token(tmp_path):
    with pytest.raises(ConfigError, match="requires WACLI_MCP_TOKEN_FILE"):
        HttpConfig.from_env({})
    with pytest.raises(ConfigError, match="chmod 600"):
        HttpConfig.from_env({"WACLI_MCP_TOKEN_FILE": str(token_file(tmp_path, mode=0o644))})
    with pytest.raises(ConfigError, match="at least"):
        HttpConfig.from_env({"WACLI_MCP_TOKEN_FILE": str(token_file(tmp_path, token="short"))})
