"""Group media tools with several accounts: per-account media directory, policy and saved file names."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from conftest import ADA, GROUP, SYNTHETIC_JPEG
from mcp import Client
from test_accounts import call, env_for, multi_config, store_args, tools_of, two_accounts, write_accounts

from wacli_mcp import media
from wacli_mcp.config import Config, ConfigError
from wacli_mcp.server import build_server

pytestmark = pytest.mark.anyio

MSG = "3A15F8F14EEBB06CAB47"
MEDIA_TOOLS = ("get_group_media", "download_group_media")


@pytest.fixture
def stores(tmp_path: Path) -> dict[str, Path]:
    out = {}
    for name in ("personal", "work"):
        out[name] = tmp_path / "stores" / name
        out[name].mkdir(parents=True, mode=0o700)
        (out[name] / "media").mkdir(mode=0o700)
    return out


@pytest.fixture
def downloads(tmp_path: Path) -> Path:
    path = tmp_path / "downloads"
    path.mkdir(mode=0o700)
    return path


def download_env(downloads: Path, **extra) -> dict[str, str]:
    return {"WACLI_MCP_ALLOW_MEDIA_DOWNLOAD": "1", "WACLI_MCP_DOWNLOAD_DIR": str(downloads), **extra}


def show(local_path: Path | str = "", **extra) -> dict:
    return {
        "ChatJID": GROUP,
        "MsgID": MSG,
        "SenderJID": ADA,
        "Timestamp": "2026-01-01T00:00:00Z",
        "MediaType": "image",
        "MediaCaption": "flyer",
        "LocalPath": str(local_path),
        "DirectPath": "/v/t62/should-never-leak",
        "FileLength": len(SYNTHETIC_JPEG),
        **extra,
    }


def put(store: Path, name: str = "photo.jpg") -> Path:
    path = store / "media" / name
    path.write_bytes(SYNTHETIC_JPEG)
    path.chmod(0o600)
    return path


# Account argument


async def test_single_account_media_tools_have_no_account_argument(fake, downloads):
    cfg = fake.config(allow_media_download=True, download_dir=downloads)
    tools = await tools_of(cfg)
    for name in MEDIA_TOOLS:
        assert "account" not in tools[name].input_schema.get("properties", {})


async def test_both_media_tools_require_a_configured_account(fake, tmp_path, stores, downloads):
    cfg = multi_config(fake, tmp_path, stores, env=download_env(downloads))
    tools = await tools_of(cfg)
    for name in MEDIA_TOOLS:
        schema = tools[name].input_schema
        assert schema["properties"]["account"]["enum"] == ["personal", "work"]
        assert "account" in schema["required"]


@pytest.mark.parametrize("tool", MEDIA_TOOLS)
@pytest.mark.parametrize("account", [None, "other", "WORK", "../work"])
async def test_missing_or_unknown_account_runs_nothing(fake, tmp_path, stores, downloads, tool, account):
    cfg = multi_config(fake, tmp_path, stores, env=download_env(downloads))
    args = {"chat": GROUP, "message_id": MSG, **({} if account is None else {"account": account})}
    result = await call(cfg, tool, args)
    assert result.is_error
    assert fake.calls() == []


# Per-account media directory


def test_each_account_detects_its_own_media_directory(fake, tmp_path, stores):
    (stores["work"] / "media").rmdir()
    cfg = multi_config(fake, tmp_path, stores)
    assert cfg.account_view("personal").media_dir == (stores["personal"] / "media").resolve()
    assert cfg.account_view("work").media_dir is None
    assert cfg.media_dir is None


def test_an_unsafe_media_directory_disables_only_that_account(fake, tmp_path, stores):
    (stores["work"] / "media").chmod(0o777)
    try:
        cfg = multi_config(fake, tmp_path, stores)
    finally:
        (stores["work"] / "media").chmod(0o700)
    assert cfg.account_view("work").media_dir is None
    assert cfg.account_view("personal").media_dir == (stores["personal"] / "media").resolve()


def test_media_dir_setting_is_refused_with_an_accounts_file(fake, tmp_path, stores):
    path = write_accounts(tmp_path, two_accounts(stores))
    with pytest.raises(ConfigError, match="WACLI_MCP_MEDIA_DIR"):
        Config.from_env(env_for(fake, path, WACLI_MCP_MEDIA_DIR=str(stores["work"] / "media")))


async def test_get_group_media_serves_the_chosen_accounts_store(fake, tmp_path, stores):
    cfg = multi_config(fake, tmp_path, stores)
    fake.respond(show(put(stores["personal"])))
    result = await call(cfg, "get_group_media", {"account": "personal", "chat": GROUP, "message_id": MSG})
    assert not result.is_error, result.content
    (image,) = [c for c in result.content if c.type == "image"]
    assert base64.b64decode(image.data) == SYNTHETIC_JPEG
    assert result.structured_content["account"] == "personal"
    assert store_args(fake) == [f"--store={stores['personal']}"]


async def test_one_account_cannot_read_the_other_accounts_files(fake, tmp_path, stores):
    cfg = multi_config(fake, tmp_path, stores)
    fake.respond(show(put(stores["personal"])))
    result = await call(cfg, "get_group_media", {"account": "work", "chat": GROUP, "message_id": MSG})
    assert result.is_error
    assert "outside the configured media directory" in result.content[0].text
    assert store_args(fake) == [f"--store={stores['work']}"]


async def test_account_without_a_media_directory_serves_nothing(fake, tmp_path, stores):
    (stores["work"] / "media").rmdir()
    cfg = multi_config(fake, tmp_path, stores)
    result = await call(cfg, "get_group_media", {"account": "work", "chat": GROUP, "message_id": MSG})
    assert result.is_error and "not configured" in result.content[0].text
    assert fake.calls() == []


def test_check_reports_media_per_account(fake, tmp_path, stores, capsys, monkeypatch):
    from wacli_mcp import cli

    (stores["work"] / "media").rmdir()
    path = write_accounts(tmp_path, two_accounts(stores))
    for key, value in env_for(fake, path).items():
        monkeypatch.setenv(key, value)
    fake.respond({"authenticated": True, "store": {"messages": 0}})
    assert cli.main(["check"]) == 0
    personal, work = json.loads(capsys.readouterr().out)["accounts"]
    assert personal["media_dir"] == str((stores["personal"] / "media").resolve())
    assert personal["mcp_policy"]["media_access_configured"] is True
    assert work["media_dir"] is None and work["mcp_policy"]["media_access_configured"] is False


# Chat policy of the selected account


@pytest.mark.parametrize("tool", MEDIA_TOOLS)
async def test_the_selected_accounts_chat_policy_applies(fake, tmp_path, stores, downloads, tool):
    cfg = multi_config(
        fake,
        tmp_path,
        stores,
        work_extra=f'denied_chats = ["{GROUP}"]',
        env=download_env(downloads),
    )
    denied = await call(cfg, tool, {"account": "work", "chat": GROUP, "message_id": MSG})
    assert denied.is_error and "not available" in denied.content[0].text
    assert fake.calls() == []

    fake.respond_download(show(put(stores["personal"])), {"x.jpg": SYNTHETIC_JPEG})
    allowed = await call(cfg, tool, {"account": "personal", "chat": GROUP, "message_id": MSG})
    assert not allowed.is_error, allowed.content


async def test_an_allowlist_on_one_account_does_not_hide_groups_on_the_other(fake, tmp_path, stores):
    other = "120363000000000099@g.us"
    cfg = multi_config(fake, tmp_path, stores, work_extra=f'allowed_chats = ["{other}"]')
    fake.respond(show(put(stores["personal"])))
    refused = await call(cfg, "get_group_media", {"account": "work", "chat": GROUP, "message_id": MSG})
    served = await call(cfg, "get_group_media", {"account": "personal", "chat": GROUP, "message_id": MSG})
    assert refused.is_error and not served.is_error


# Saved file names


def test_saved_stem_is_unchanged_without_an_account():
    assert media.saved_stem(GROUP, MSG) == f"{GROUP.split('@')[0]}.{MSG}"
    assert media.saved_stem(GROUP, MSG, "work") == f"work.{GROUP.split('@')[0]}.{MSG}"


async def test_single_account_download_keeps_the_unprefixed_name(fake, downloads):
    fake.respond_download(show(), {"x.jpg": SYNTHETIC_JPEG})
    cfg = fake.config(allow_media_download=True, download_dir=downloads)
    async with Client(build_server(cfg)) as client:
        result = await client.call_tool("download_group_media", {"chat": GROUP, "message_id": MSG})
    assert result.structured_content["saved_as"] == f"{GROUP.split('@')[0]}.{MSG}.jpg"
    assert "account" not in result.structured_content


async def test_multi_account_download_prefixes_the_alias_and_keeps_accounts_apart(fake, tmp_path, stores, downloads):
    cfg = multi_config(fake, tmp_path, stores, env=download_env(downloads))
    fake.respond_download(show(), {"x.jpg": SYNTHETIC_JPEG})
    stem = GROUP.split("@")[0]

    personal = await call(cfg, "download_group_media", {"account": "personal", "chat": GROUP, "message_id": MSG})
    assert personal.structured_content["saved_as"] == f"personal.{stem}.{MSG}.jpg"
    assert personal.structured_content["account"] == "personal"
    assert personal.structured_content["downloaded"] is True

    # The same message through the other account is a new download, not personal's copy.
    work = await call(cfg, "download_group_media", {"account": "work", "chat": GROUP, "message_id": MSG})
    assert work.structured_content["saved_as"] == f"work.{stem}.{MSG}.jpg"
    assert work.structured_content["downloaded"] is True
    assert sorted(p.name for p in downloads.iterdir() if p.name != ".capacity.lock") == [
        f"personal.{stem}.{MSG}.jpg",
        f"work.{stem}.{MSG}.jpg",
    ]

    # A repeat for the same account is served from its own copy without network access.
    again = await call(cfg, "download_group_media", {"account": "work", "chat": GROUP, "message_id": MSG})
    assert again.structured_content["downloaded"] is False
    downloads_run = [c for c in fake.calls() if "download" in c["argv"]]
    assert len(downloads_run) == 2
    assert all(f"--store={stores[a]}" in c["argv"] for a, c in zip(("personal", "work"), downloads_run, strict=True))


async def test_media_audit_records_name_the_account_and_hide_identifiers(fake, tmp_path, stores):
    log = tmp_path / "audit.jsonl"
    cfg = multi_config(fake, tmp_path, stores, env={"WACLI_MCP_AUDIT_LOG": str(log)})
    fake.respond(show(put(stores["work"])))
    await call(cfg, "get_group_media", {"account": "work", "chat": GROUP, "message_id": MSG})
    (entry,) = [json.loads(line) for line in log.read_text().splitlines()]
    assert entry["tool"] == "get_group_media" and entry["account"] == "work" and entry["ok"] is True
    text = log.read_text()
    assert MSG not in text and GROUP not in text and "photo.jpg" not in text


# Instructions


def test_instructions_match_the_registered_tools(fake, tmp_path, stores, downloads):
    read_only = build_server(fake.config()).instructions
    assert "nothing is fetched from WhatsApp" in read_only and "download_group_media" not in read_only
    assert "send_message" not in read_only

    downloads_on = build_server(fake.config(allow_media_download=True, download_dir=downloads)).instructions
    assert "download_group_media" in downloads_on and "nothing is fetched from WhatsApp" not in downloads_on

    send = build_server(
        fake.config(send_enabled=True, send_recipients=(("me", ADA),)),
    ).instructions
    assert "send_message" in send and "nothing is fetched from WhatsApp" in send
    assert "No tool can send" not in send

    both = build_server(
        fake.config(
            send_enabled=True, send_recipients=(("me", ADA),), allow_media_download=True, download_dir=downloads
        )
    ).instructions
    assert "send_message" in both and "download_group_media" in both

    multi = build_server(multi_config(fake, tmp_path, stores, env=download_env(downloads))).instructions
    assert "download_group_media" in multi and "every tool needs `account`" in multi
