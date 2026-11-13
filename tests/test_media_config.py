"""Media configuration, and proof that adding group media leaves the existing tools as they were."""

from __future__ import annotations

import pytest
from conftest import ADA, GROUP, OTHER_GROUP
from mcp import Client

from wacli_mcp.config import Config, ConfigError
from wacli_mcp.server import build_server


def env_for(fake, **extra) -> dict[str, str]:
    return {
        "HOME": str(fake.home),
        "WACLI_MCP_BIN": str(fake.path),
        "WACLI_MCP_NETWORK_ISOLATION": "off",
        **extra,
    }


def test_media_dir_defaults_to_store_media_and_is_vetted(fake, tmp_path):
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    (store / "media").mkdir(mode=0o700)
    assert Config.from_env(env_for(fake, WACLI_MCP_STORE=str(store))).media_dir == (store / "media").resolve()
    assert Config.from_env(env_for(fake)).media_dir is None

    explicit = tmp_path / "explicit"
    explicit.mkdir(mode=0o700)
    assert Config.from_env(env_for(fake, WACLI_MCP_MEDIA_DIR=str(explicit))).media_dir == explicit.resolve()
    with pytest.raises(ConfigError, match="WACLI_MCP_MEDIA_DIR must be absolute"):
        Config.from_env(env_for(fake, WACLI_MCP_MEDIA_DIR="media"))
    with pytest.raises(ConfigError, match="does not exist"):
        Config.from_env(env_for(fake, WACLI_MCP_MEDIA_DIR=str(tmp_path / "missing")))
    explicit.chmod(0o777)
    try:
        with pytest.raises(ConfigError, match="writable by group or others"):
            Config.from_env(env_for(fake, WACLI_MCP_MEDIA_DIR=str(explicit)))
    finally:
        explicit.chmod(0o700)


def test_unsafe_auto_detected_media_dir_disables_media_instead_of_failing(fake, tmp_path):
    # Upgrading must not stop the text tools from starting because of the store's media directory.
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    (store / "media").mkdir()
    (store / "media").chmod(0o777)
    try:
        cfg = Config.from_env(env_for(fake, WACLI_MCP_STORE=str(store)))
        assert cfg.media_dir is None
        with pytest.raises(ConfigError, match="writable by group or others"):
            Config.from_env(env_for(fake, WACLI_MCP_STORE=str(store), WACLI_MCP_MEDIA_DIR=str(store / "media")))
    finally:
        (store / "media").chmod(0o700)


def test_unusable_auto_detected_media_dir_disables_media(fake, tmp_path):
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    (store / "media").symlink_to(store / "media")  # a loop: resolving it fails
    assert Config.from_env(env_for(fake, WACLI_MCP_STORE=str(store))).media_dir is None


def test_store_that_cannot_be_searched_disables_media_instead_of_failing(fake, tmp_path):
    # Probing <store>/media raises PermissionError on Python 3.12 when the store has no search permission.
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    (store / "media").mkdir(mode=0o700)
    store.chmod(0o600)
    try:
        assert Config.from_env(env_for(fake, WACLI_MCP_STORE=str(store))).media_dir is None
    finally:
        store.chmod(0o700)


def test_media_size_limit_is_bounded(fake):
    # 3 MiB keeps base64 below the 5 MB per-image limit of common model APIs.
    assert Config.from_env(env_for(fake)).max_media_bytes == 3 * 1024 * 1024
    with pytest.raises(ConfigError, match="between"):
        Config.from_env(env_for(fake, WACLI_MCP_MAX_MEDIA_BYTES=str(1024 * 1024 * 1024)))


def test_existing_policies_are_unchanged(fake):
    # Direct chats stay allowed, and an allowlist may still name any chat kind.
    cfg = Config.from_env(env_for(fake, WACLI_MCP_ALLOWED_CHATS=f"{ADA},{GROUP}"))
    assert cfg.chat_visible(ADA) and cfg.chat_visible(GROUP)
    assert not cfg.chat_visible(OTHER_GROUP)
    assert Config.from_env(env_for(fake)).chat_visible(ADA)


@pytest.mark.anyio
async def test_direct_chats_and_contact_search_still_work(fake):
    fake.respond({"messages": [{"ChatJID": ADA, "MsgID": "D1", "Text": "hi"}], "page": {}, "source": {}})
    async with Client(build_server(fake.config())) as client:
        dm = await client.call_tool("list_messages", {"chat": ADA, "sender": "Ada Lovelace"})
        fake.respond([{"jid": ADA, "name": "Ada Lovelace"}])
        contacts = await client.call_tool("search_contacts", {"query": "Ada"})
    assert not dm.is_error and [m["msg_id"] for m in dm.structured_content["messages"]] == ["D1"]
    assert f"--chat={ADA}" in fake.calls()[0]["argv"] and "--sender=Ada Lovelace" in fake.calls()[0]["argv"]
    assert [c["jid"] for c in contacts.structured_content["items"]] == [ADA]
    assert fake.calls()[1]["argv"][-4:] == ["search", "--limit=20", "--", "Ada"]


@pytest.mark.anyio
async def test_health_reports_media_settings(fake):
    fake.respond({"store": {"messages": 3}})
    async with Client(build_server(fake.config())) as client:
        data = (await client.call_tool("archive_health", {})).structured_content
    assert data["store_counts"] == {"messages": 3}
    assert data["mcp_policy"]["media_access_configured"] is True
    assert data["mcp_policy"]["max_media_bytes"] == 3 * 1024 * 1024
    assert data["mcp_policy"]["media_download_enabled"] is False
