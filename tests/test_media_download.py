"""download_group_media: opt-in, group-only fetch of one photo or video through `wacli media download`.

All files and replies come from the fake wacli; nothing here touches the network.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest
from conftest import ADA, GROUP, OTHER_GROUP
from mcp import Client

from wacli_mcp.config import Config, ConfigError
from wacli_mcp.runner import WacliError, WacliRunner
from wacli_mcp.server import ALLOWED_COMMANDS, NETWORK_COMMANDS, build_server

pytestmark = pytest.mark.anyio

JPEG = b"\xff\xd8\xff\xe0" + b"\x01" * 60
MP4 = b"\x00\x00\x00\x18ftypmp42" + b"\x01" * 60
MSG = "3A15F8F14EEBB06CAB47"
SAVED_JPEG = f"{GROUP.split('@')[0]}.{MSG}.jpg"


JPEG_LENGTH = len(JPEG)


def show(*, chat=GROUP, msg_id=MSG, media_type="image", length=JPEG_LENGTH, **extra):
    return {
        "ChatJID": chat,
        "MsgID": msg_id,
        "MediaType": media_type,
        "MimeType": "image/jpeg",
        "LocalPath": "",
        "DirectPath": "/v/t62/should-never-leak",
        "FileLength": length,
        "Timestamp": "2026-11-12T14:38:22Z",
        **extra,
    }


@pytest.fixture
def downloads(tmp_path) -> Path:
    path = tmp_path / "downloads"
    path.mkdir(mode=0o700)
    return path


def cfg(fake, downloads, **overrides):
    return fake.config(allow_media_download=True, download_dir=downloads, **overrides)


async def download(fake, downloads, args=None, **overrides):
    async with Client(build_server(cfg(fake, downloads, **overrides))) as client:
        return await client.call_tool("download_group_media", {"chat": GROUP, "message_id": MSG, **(args or {})})


def leftovers(downloads: Path) -> list[str]:
    # The capacity lock file is permanent by design (unlinking a flock file races with other processes).
    return sorted(p.name for p in downloads.iterdir() if p.name != ".capacity.lock")


# --- configuration -----------------------------------------------------------------------------


def env_for(fake, **extra):
    return {"HOME": str(fake.home), "WACLI_MCP_BIN": str(fake.path), "WACLI_MCP_NETWORK_ISOLATION": "off", **extra}


def test_download_is_off_by_default(fake):
    cfg_ = Config.from_env(env_for(fake))
    assert cfg_.allow_media_download is False and cfg_.download_dir is None


def test_enabling_download_requires_a_private_directory(fake, tmp_path):
    with pytest.raises(ConfigError, match="WACLI_MCP_DOWNLOAD_DIR"):
        Config.from_env(env_for(fake, WACLI_MCP_ALLOW_MEDIA_DOWNLOAD="1"))
    with pytest.raises(ConfigError, match="WACLI_MCP_ALLOW_MEDIA_DOWNLOAD"):
        Config.from_env(env_for(fake, WACLI_MCP_ALLOW_MEDIA_DOWNLOAD="yes please"))
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o770)
    shared.chmod(0o770)
    with pytest.raises(ConfigError, match="writable by group or others"):
        Config.from_env(env_for(fake, WACLI_MCP_ALLOW_MEDIA_DOWNLOAD="1", WACLI_MCP_DOWNLOAD_DIR=str(shared)))
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    ok = Config.from_env(env_for(fake, WACLI_MCP_ALLOW_MEDIA_DOWNLOAD="1", WACLI_MCP_DOWNLOAD_DIR=str(private)))
    assert ok.allow_media_download is True and ok.download_dir == private.resolve()


async def test_tool_is_absent_unless_enabled(fake, downloads):
    async with Client(build_server(fake.config())) as client:
        assert "download_group_media" not in {t.name for t in (await client.list_tools()).tools}
    async with Client(build_server(cfg(fake, downloads))) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    tool = tools["download_group_media"]
    assert tool.annotations.open_world_hint is True and tool.annotations.destructive_hint is False


def test_media_download_is_never_reachable_from_text_tools():
    assert ("media", "download") not in ALLOWED_COMMANDS
    assert NETWORK_COMMANDS == frozenset({("media", "download")})


def test_only_media_download_may_leave_the_network_sandbox(fake):
    runner = WacliRunner(fake.config(sandbox_prefix=("/usr/bin/unshare", "-rn", "--")))
    offline = runner.build_argv(["messages", "show", "--id=x"])
    online = runner.build_argv(["media", "download", "--id=x"], network=True, max_file_bytes=4096)
    assert offline[:3] == ["/usr/bin/unshare", "-rn", "--"]
    assert "/usr/bin/unshare" not in online and str(fake.path) in online and "--read-only" in online
    with pytest.raises(WacliError):
        runner.build_argv(["messages", "show", "--id=x"], network=True, max_file_bytes=4096)
    with pytest.raises(WacliError):
        runner.build_argv(["media", "download", "--id=x"], network=True)


# --- happy paths -------------------------------------------------------------------------------


async def test_photo_is_downloaded_validated_saved_and_returned(fake, downloads):
    fake.respond_download(show(), {"whatever-wacli-picks.jpg": JPEG})
    result = await download(fake, downloads)
    assert not result.is_error, result.content
    (image,) = [c for c in result.content if c.type == "image"]
    assert base64.b64decode(image.data) == JPEG
    meta = result.structured_content
    assert meta["chat_jid"] == GROUP and meta["msg_id"] == MSG and meta["mime_type"] == "image/jpeg"
    assert meta["saved_as"] == SAVED_JPEG and meta["downloaded"] is True
    assert "should-never-leak" not in str(meta) and str(downloads) not in str(meta)

    saved = downloads / SAVED_JPEG
    assert saved.read_bytes() == JPEG
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    assert leftovers(downloads) == [SAVED_JPEG]  # temporary directory removed

    show_call, dl_call = fake.calls()
    assert show_call["argv"][-4:] == ["messages", "show", f"--chat={GROUP}", f"--id={MSG}"]
    argv = dl_call["argv"]
    assert argv[:2] == ["--read-only", "--json"]
    assert argv[-5:-1] == ["media", "download", f"--chat={GROUP}", f"--id={MSG}"]
    assert argv[-1].startswith("--output=")
    assert Path(argv[-1].split("=", 1)[1]).parent == downloads.resolve()
    assert not any(a.startswith("--retry-on-phone") for a in argv)
    assert dl_call["env"]["WACLI_READONLY"] == "1"


async def test_video_is_saved_with_its_sniffed_extension(fake, downloads):
    fake.respond_download(show(media_type="video", MimeType="video/mp4", length=len(MP4)), {"clip": MP4})
    result = await download(fake, downloads)
    assert not result.is_error, result.content
    (blob,) = [c for c in result.content if c.type == "resource"]
    assert base64.b64decode(blob.resource.blob) == MP4
    assert leftovers(downloads) == [f"{GROUP.split('@')[0]}.{MSG}.mp4"]


# --- refusals before any network ---------------------------------------------------------------


@pytest.mark.parametrize("chat", [ADA, "Soundcarver's", "+1 555 000 0001", "status@broadcast", ""])
async def test_non_group_chats_never_reach_wacli(fake, downloads, chat):
    result = await download(fake, downloads, {"chat": chat})
    assert result.is_error and fake.calls() == []


async def test_denied_group_never_reaches_wacli(fake, downloads):
    result = await download(fake, downloads, denied_chats=frozenset({GROUP}))
    assert result.is_error and fake.calls() == []


@pytest.mark.parametrize("message_id", ["../x", "--retry-on-phone", "-A", "3A15 F8", "x" * 129])
async def test_bad_message_ids_never_reach_wacli(fake, downloads, message_id):
    result = await download(fake, downloads, {"message_id": message_id})
    assert result.is_error and fake.calls() == []


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        (show(chat=OTHER_GROUP), "requested group"),
        (show(chat=ADA), "requested group"),
        (show(msg_id="OTHER"), "different message"),
        (show(media_type="audio"), "only photos and videos"),
        (show(media_type="document"), "only photos and videos"),
        (show(length=10 * 1024 * 1024), "larger than"),
    ],
)
async def test_metadata_checks_happen_before_download(fake, downloads, reply, reason):
    fake.respond_download(reply, {"a.jpg": JPEG})
    result = await download(fake, downloads, max_media_bytes=64 * 1024)
    assert result.is_error and reason in result.content[0].text
    assert len(fake.calls()) == 1  # only the offline `messages show`
    assert leftovers(downloads) == []


# --- refusals after download -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("files", "reason"),
    [
        ({"a.jpg": b"\x7fELF" + b"\x00" * 60}, "not a supported image"),
        ({"a.jpg": MP4}, "not a supported image"),
        ({"a.jpg": JPEG, "b.jpg": JPEG}, "exactly one file"),
        ({}, "exactly one file"),
        ({"a.jpg": JPEG + b"\x00" * 70_000}, "larger than"),
    ],
)
async def test_bad_downloads_are_discarded(fake, downloads, files, reason):
    fake.respond_download(show(length=None), files)
    result = await download(fake, downloads, max_media_bytes=64 * 1024)
    assert result.is_error and reason in result.content[0].text
    assert leftovers(downloads) == []


async def test_symlink_written_by_wacli_is_refused(fake, downloads, tmp_path):
    secret = tmp_path / "secret.jpg"
    secret.write_bytes(JPEG)
    fake.respond_download(show(), symlinks={"a.jpg": str(secret)})
    result = await download(fake, downloads)
    assert result.is_error and "symlink" in result.content[0].text
    assert leftovers(downloads) == []


async def test_wacli_download_error_is_reported_and_cleaned_up(fake, downloads):
    error = '{"success": false, "data": null, "error": "download failed: 410 Gone"}'
    fake.respond_download(show(), stdout=error, rc=1)
    result = await download(fake, downloads)
    assert result.is_error and "HTTP 410" in result.content[0].text
    assert leftovers(downloads) == []


async def test_existing_saved_name_is_never_followed(fake, downloads, tmp_path):
    secret = tmp_path / "secret.jpg"
    secret.write_bytes(JPEG)
    os.symlink(secret, downloads / SAVED_JPEG)
    fake.respond_download(show(), {"a.jpg": JPEG})
    result = await download(fake, downloads)
    assert result.is_error
    assert (downloads / SAVED_JPEG).is_symlink()  # left alone, not overwritten through


# --- fixes from the independent security review ------------------------------------------------

LEGACY_GROUP = "12345678-87654321@g.us"
SHORT_GROUP = "12345678@g.us"
OTHER_JPEG = b"\xff\xd8\xff\xe0" + b"\x02" * 60


async def test_saved_names_cannot_collide_across_groups(fake, downloads):
    # Both pairs used to map to "12345678-87654321-AAAA"; the second must not get the first's file.
    fake.respond_download(show(chat=LEGACY_GROUP, msg_id="AAAA"), {"a.jpg": JPEG})
    first = await download(fake, downloads, {"chat": LEGACY_GROUP, "message_id": "AAAA"})
    assert not first.is_error, first.content
    fake.respond_download(show(chat=SHORT_GROUP, msg_id="87654321-AAAA"), {"b.jpg": OTHER_JPEG})
    second = await download(fake, downloads, {"chat": SHORT_GROUP, "message_id": "87654321-AAAA"})
    assert not second.is_error, second.content
    (image,) = [c for c in second.content if c.type == "image"]
    assert base64.b64decode(image.data) == OTHER_JPEG
    assert second.structured_content["downloaded"] is True
    assert leftovers(downloads) == ["12345678-87654321.AAAA.jpg", "12345678.87654321-AAAA.jpg"]


async def test_cached_copy_is_rechecked_offline_but_not_refetched(fake, downloads):
    fake.respond_download(show(), {"a.jpg": JPEG})
    assert not (await download(fake, downloads)).is_error
    again = await download(fake, downloads)
    assert not again.is_error and again.structured_content["downloaded"] is False
    commands = [call["argv"][-5:-3] if "download" in call["argv"] else call["argv"][-4:-2] for call in fake.calls()]
    assert commands == [["messages", "show"], ["media", "download"], ["messages", "show"]]


@pytest.mark.parametrize("flag", ["Revoked", "DeletedForMe"])
async def test_deleted_messages_are_refused_even_when_cached(fake, downloads, flag):
    fake.respond_download(show(**{flag: True}), {"a.jpg": JPEG})
    fresh = await download(fake, downloads)
    assert fresh.is_error and "deleted" in fresh.content[0].text
    assert len(fake.calls()) == 1
    fake.respond_download(show(), {"a.jpg": JPEG})
    assert not (await download(fake, downloads)).is_error
    fake.respond_download(show(**{flag: True}), {})
    cached = await download(fake, downloads)
    assert cached.is_error and "deleted" in cached.content[0].text


@pytest.mark.parametrize(
    "direct_path",
    [
        "",
        None,
        ".attacker.example/x?",
        "@evil.example/x?",
        "//evil.example/x?",
        "https://evil.example/v/x",
        "/v/t62/a b",
        "/v/t62/x#frag",
        "/v/t62/x@evil",
        "/other/t62/x",
    ],
)
async def test_unexpected_direct_paths_never_reach_the_network(fake, downloads, direct_path):
    fake.respond_download(show(DirectPath=direct_path), {"a.jpg": JPEG})
    result = await download(fake, downloads)
    assert result.is_error and "direct path" in result.content[0].text
    assert len(fake.calls()) == 1


async def test_download_errors_do_not_echo_urls_tokens_or_paths(fake, downloads):
    error = (
        'Get "https://mmg.whatsapp.net/v/t62/x?oh=SECRETTOKEN&oe=1": 410 Gone; '
        f"open {downloads}/.download-x/file: denied"
    )
    fake.respond_download(show(), stdout=json.dumps({"success": False, "data": None, "error": error}), rc=1)
    result = await download(fake, downloads)
    text = result.content[0].text
    assert result.is_error and "HTTP 410" in text
    for leak in ("SECRETTOKEN", "mmg.whatsapp.net", "/v/t62", str(downloads)):
        assert leak not in text


async def test_download_child_cannot_write_past_the_size_limit(fake, downloads):
    # RLIMIT_FSIZE stops the child itself, before the server ever reads the file.
    fake.respond_download(show(length=None), {"a.jpg": JPEG + b"\x00" * (3 * 1024 * 1024)})
    result = await download(fake, downloads, max_media_bytes=64 * 1024)
    assert result.is_error
    # Stopped by the limit while writing, not rejected afterwards by the server's own size check.
    assert "media download failed" in result.content[0].text
    assert leftovers(downloads) == []


async def test_full_download_directory_refuses_new_downloads(fake, downloads):
    (downloads / "filler.bin").write_bytes(b"\x00" * (1024 * 1024))
    fake.respond_download(show(), {"a.jpg": JPEG})
    result = await download(fake, downloads, max_download_dir_bytes=1024 * 1024)
    assert result.is_error and "download directory is full" in result.content[0].text
    assert len(fake.calls()) == 1


async def test_stale_partial_files_are_removed_at_startup(fake, downloads):
    (downloads / ".x.jpg.part").write_bytes(b"partial")
    (downloads / ".download-abc").mkdir(mode=0o700)
    (downloads / ".download-abc" / "f").write_bytes(b"partial")
    kept = downloads / "120363000000000042.KEEP.jpg"
    kept.write_bytes(JPEG)
    for entry in (".x.jpg.part", ".download-abc", kept.name):
        os.utime(downloads / entry, (1_000_000_000, 1_000_000_000))
    build_server(cfg(fake, downloads))
    assert leftovers(downloads) == [kept.name]


def test_failed_save_leaves_no_partial_file(fake, downloads, monkeypatch):
    from wacli_mcp import media

    def broken_fsync(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(media.os, "fsync", broken_fsync)
    with pytest.raises(media.MediaError, match="could not be saved"):
        media.save_new_file(downloads, "a.jpg", JPEG)
    assert leftovers(downloads) == []
    monkeypatch.undo()
    media.save_new_file(downloads, "a.jpg", JPEG)
    assert leftovers(downloads) == ["a.jpg"]


async def test_missing_download_directory_is_a_clean_refusal(fake, downloads):
    fake.respond_download(show(), {"a.jpg": JPEG})
    server = build_server(cfg(fake, downloads))
    downloads.rmdir()
    async with Client(server) as client:
        result = await client.call_tool("download_group_media", {"chat": GROUP, "message_id": MSG})
    assert result.is_error and "download directory" in result.content[0].text


def test_instructions_mention_download_only_when_enabled(fake, downloads):
    assert "download_group_media" in build_server(cfg(fake, downloads)).instructions
    assert "download_group_media" not in build_server(fake.config()).instructions


# --- fixes from the independent re-review ------------------------------------------------------


async def test_unreadable_download_directory_is_a_clean_refusal(fake, downloads):
    (downloads / f"{GROUP.split('@')[0]}.{MSG}.jpg").write_bytes(JPEG)
    fake.respond_download(show(), {"a.jpg": JPEG})
    server = build_server(cfg(fake, downloads))
    downloads.chmod(0o600)  # readable listing, but entries cannot be looked up
    try:
        async with Client(server) as client:
            result = await client.call_tool("download_group_media", {"chat": GROUP, "message_id": MSG})
    finally:
        downloads.chmod(0o700)
    assert result.is_error and "download directory" in result.content[0].text


@pytest.mark.parametrize(
    "direct_path",
    ["/v/../../x?a=1", "/v/%2e%2e/x", "/v/%2E%2E/x", "/v/t62/%2fevil", "/v//evil.example/x", "/o1/v/a/../b"],
)
async def test_direct_paths_with_traversal_or_encoded_separators_are_refused(fake, downloads, direct_path):
    fake.respond_download(show(DirectPath=direct_path), {"a.jpg": JPEG})
    result = await download(fake, downloads)
    assert result.is_error and "direct path" in result.content[0].text
    assert len(fake.calls()) == 1


async def test_realistic_direct_path_with_query_is_accepted(fake, downloads):
    path = "/o1/v/t62.7118-24/f2/m231/AQN_Abc-123.enc?ccb=9-4&oh=01_Q5Aa&oe=6A1B2C3D&_nc_sid=e6ed6c&mms3=true"
    fake.respond_download(show(DirectPath=path), {"a.jpg": JPEG})
    assert not (await download(fake, downloads)).is_error


def test_download_child_is_size_limited_through_prlimit(fake, downloads):
    runner = WacliRunner(cfg(fake, downloads, sandbox_prefix=("/usr/bin/unshare", "-rn", "--")))
    argv = runner.build_argv(["media", "download", "--id=x"], network=True, max_file_bytes=4096)
    assert argv[:3] == ["/usr/bin/prlimit", "--fsize=4096:4096", "--"]
    assert argv[3] == str(fake.path)
    offline = runner.build_argv(["messages", "show", "--id=x"])
    assert "/usr/bin/prlimit" not in offline


def test_download_requires_a_usable_prlimit(fake, tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    env = env_for(
        fake,
        WACLI_MCP_ALLOW_MEDIA_DOWNLOAD="1",
        WACLI_MCP_DOWNLOAD_DIR=str(private),
        WACLI_MCP_PRLIMIT="/nonexistent/prlimit",
    )
    with pytest.raises(ConfigError, match="prlimit"):
        Config.from_env(env)


def test_startup_cleanup_spares_recent_downloads_of_other_processes(fake, downloads):
    recent = downloads / ".download-live"
    recent.mkdir(mode=0o700)
    (recent / "f").write_bytes(b"in flight")
    live_part = downloads / ".y.jpg.part"
    live_part.write_bytes(b"in flight")
    old = downloads / ".download-old"
    old.mkdir(mode=0o700)
    old_part = downloads / ".z.jpg.part"
    old_part.write_bytes(b"stale")
    stale_time = 1_000_000_000
    os.utime(old, (stale_time, stale_time))
    os.utime(old_part, (stale_time, stale_time))
    build_server(cfg(fake, downloads))
    assert leftovers(downloads) == [".download-live", ".y.jpg.part"]


def test_startup_cleanup_continues_past_a_failing_entry(fake, downloads, monkeypatch):
    from wacli_mcp import media

    for name in (".a.jpg.part", ".b.jpg.part"):
        (downloads / name).write_bytes(b"stale")
        os.utime(downloads / name, (1_000_000_000, 1_000_000_000))
    real_unlink = os.unlink

    def flaky_unlink(path, *args, **kwargs):
        if str(path).endswith(".a.jpg.part"):
            raise PermissionError(13, "denied")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(media.os, "unlink", flaky_unlink)
    media.remove_stale(downloads, max_age_s=60)
    assert leftovers(downloads) == [".a.jpg.part"]


async def test_concurrent_save_of_the_same_message_serves_the_existing_copy(fake, downloads, monkeypatch):
    from wacli_mcp import media

    real_save = media.save_new_file

    def save_after_another_process(directory, name, data):
        real_save(directory, name, data)  # the other process wins the race
        real_save(directory, name, data)

    monkeypatch.setattr(media, "save_new_file", save_after_another_process)
    fake.respond_download(show(), {"a.jpg": JPEG})
    result = await download(fake, downloads)
    assert not result.is_error, result.content
    assert leftovers(downloads) == [SAVED_JPEG]


async def test_rate_limit_during_download_keeps_its_message(fake, downloads):
    fake.respond_download(show(), {"a.jpg": JPEG})
    result = await download(fake, downloads, rate_limit_per_minute=1)
    assert result.is_error and "rate limit" in result.content[0].text


def test_instructions_never_claim_nothing_is_fetched_when_download_is_enabled(fake, downloads):
    assert "nothing is fetched from WhatsApp" not in build_server(cfg(fake, downloads)).instructions
    assert "nothing is fetched from WhatsApp" in build_server(fake.config()).instructions


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o705])
def test_download_dir_must_have_no_group_or_other_bits(fake, tmp_path, mode):
    path = tmp_path / "open-read"
    path.mkdir()
    path.chmod(mode)
    with pytest.raises(ConfigError, match="WACLI_MCP_DOWNLOAD_DIR .*must not be accessible by group or others"):
        Config.from_env(env_for(fake, WACLI_MCP_ALLOW_MEDIA_DOWNLOAD="1", WACLI_MCP_DOWNLOAD_DIR=str(path)))


@pytest.mark.skipif(os.getuid() == 0, reason="root owns everything it creates")
def test_download_dir_must_be_owned_by_the_current_user(tmp_path, monkeypatch):
    path = tmp_path / "mine"
    path.mkdir(mode=0o700)
    from wacli_mcp import config

    monkeypatch.setattr(config.os, "getuid", lambda: 12345)
    with pytest.raises(ConfigError, match="must be owned by the current user"):
        config._private_dir(path, "WACLI_MCP_DOWNLOAD_DIR")


def test_a_media_dir_may_still_be_readable_by_others(fake, tmp_path):
    path = tmp_path / "readable"
    path.mkdir()
    path.chmod(0o755)
    assert Config.from_env(env_for(fake, WACLI_MCP_MEDIA_DIR=str(path))).media_dir == path.resolve()


def test_a_leftover_part_file_does_not_block_saving(tmp_path):
    from wacli_mcp import media

    (tmp_path / ".x.jpg.part").write_bytes(b"killed process")
    media.save_new_file(tmp_path, "x.jpg", JPEG)
    assert (tmp_path / "x.jpg").read_bytes() == JPEG
    assert sorted(p.name for p in tmp_path.iterdir()) == [".x.jpg.part", "x.jpg"]
    with pytest.raises(media.AlreadySaved):
        media.save_new_file(tmp_path, "x.jpg", MP4)
    assert (tmp_path / "x.jpg").read_bytes() == JPEG


def test_unique_part_files_are_still_swept_when_stale(tmp_path):
    from wacli_mcp import media

    old = tmp_path / ".x.jpg.0123456789abcdef.part"
    old.write_bytes(b"partial")
    os.utime(old, (1, 1))
    media.remove_stale(tmp_path, max_age_s=60)
    assert not old.exists()


async def test_the_final_capacity_check_uses_the_real_size_and_saves_nothing(fake, downloads):
    # The declared length fits; the bytes wacli produced do not.
    fake.respond_download(show(length=JPEG_LENGTH), {"a.jpg": JPEG + b"\x00" * 2000})
    result = await download(fake, downloads, max_download_dir_bytes=1000)
    assert result.is_error and "download directory is full" in result.content[0].text
    assert leftovers(downloads) == []


async def test_capacity_lock_file_is_private_and_ignored_by_cleanup(fake, downloads):
    from wacli_mcp import media

    fake.respond_download(show(), {"a.jpg": JPEG})
    result = await download(fake, downloads)
    assert not result.is_error, result.content
    lock = downloads / ".capacity.lock"
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    os.utime(lock, (1, 1))
    media.remove_stale(downloads, max_age_s=60)
    assert lock.exists()
