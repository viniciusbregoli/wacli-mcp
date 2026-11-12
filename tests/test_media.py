"""get_group_media: serves already-downloaded photos and videos of group chats only.

Every file here is synthetic: a few magic bytes plus padding, written into the
fake's private media directory. Nothing touches a real store or the network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest
from conftest import ADA, GROUP, OTHER_GROUP
from mcp import Client

from wacli_mcp import media
from wacli_mcp.server import ALLOWED_COMMANDS, build_server

pytestmark = pytest.mark.anyio

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 60
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 60
MP4 = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 60
HEIC = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 60
ELF = b"\x7fELF" + b"\x00" * 60


def message(local_path, *, chat=GROUP, msg_id="3EB0A1", media_type="image", mime="image/jpeg", **extra):
    return {
        "ChatJID": chat,
        "MsgID": msg_id,
        "SenderJID": "15550000001@s.whatsapp.net",
        "Timestamp": "2026-01-01T00:00:00Z",
        "FromMe": False,
        "MediaType": media_type,
        "MimeType": mime,
        "MediaCaption": "rehearsal",
        "LocalPath": str(local_path),
        "DirectPath": "/v/t62/should-never-leak",
        **extra,
    }


def put(fake, name, data, mode=0o600):
    path = fake.media / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


async def fetch(fake, args, **cfg):
    async with Client(build_server(fake.config(**cfg))) as client:
        return await client.call_tool("get_group_media", {"chat": GROUP, **args})


async def test_photo_is_returned_as_image_content(fake):
    path = put(fake, "ab/photo.jpg", JPEG)
    fake.respond(message(path))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert not result.is_error, result.content
    images = [c for c in result.content if c.type == "image"]
    assert len(images) == 1
    assert images[0].mime_type == "image/jpeg"
    assert base64.b64decode(images[0].data) == JPEG
    meta = result.structured_content
    assert meta["chat_jid"] == GROUP and meta["msg_id"] == "3EB0A1"
    assert meta["size_bytes"] == len(JPEG)
    assert meta["sha256"] == hashlib.sha256(JPEG).hexdigest()
    assert meta["untrusted_content"] is True
    dumped = json.dumps(meta) + json.dumps([c.model_dump() for c in result.content if c.type == "text"])
    assert str(fake.media) not in dumped and "should-never-leak" not in dumped


async def test_only_message_show_for_the_requested_group_is_spawned(fake):
    path = put(fake, "photo.jpg", JPEG)
    fake.respond(message(path, chat=OTHER_GROUP))
    result = await fetch(fake, {"chat": OTHER_GROUP, "message_id": "3EB0A1"})
    assert not result.is_error, result.content
    assert result.structured_content["chat_jid"] == OTHER_GROUP
    (call,) = fake.calls()
    argv = call["argv"]
    assert argv[:2] == ["--read-only", "--json"]
    assert argv[-4:] == ["messages", "show", f"--chat={OTHER_GROUP}", "--id=3EB0A1"]
    assert "media" not in argv and "download" not in argv


@pytest.mark.parametrize(
    "chat", [ADA, "15550000001@lid", "status@broadcast", "1203@newsletter", "Soundcarver's", "+1 555 000 0001", ""]
)
async def test_non_group_chats_never_reach_wacli(fake, chat):
    result = await fetch(fake, {"chat": chat, "message_id": "3EB0A1"})
    assert result.is_error
    assert fake.calls() == []


async def test_group_outside_the_allowlist_is_refused(fake):
    result = await fetch(fake, {"chat": OTHER_GROUP, "message_id": "3EB0A1"}, allowed_chats=frozenset({GROUP}))
    assert result.is_error
    assert fake.calls() == []


def test_no_media_or_network_command_is_allowlisted():
    assert ("messages", "show") in ALLOWED_COMMANDS
    assert not any(
        cmd[0] in ("media", "sync", "auth", "send", "history") and cmd != ("history", "coverage")
        for cmd in ALLOWED_COMMANDS
    )


async def test_video_is_returned_as_embedded_blob(fake):
    path = put(fake, "clip.mp4", MP4)
    fake.respond(message(path, media_type="video", mime="video/mp4"))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert not result.is_error, result.content
    (blob,) = [c for c in result.content if c.type == "resource"]
    assert blob.resource.mime_type == "video/mp4"
    assert base64.b64decode(blob.resource.blob) == MP4
    assert str(blob.resource.uri).startswith("wacli-media:")


async def test_sniffed_type_wins_over_declared_mime(fake):
    path = put(fake, "photo.jpg", PNG)
    fake.respond(message(path, mime="image/jpeg"))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert not result.is_error
    assert result.structured_content["mime_type"] == "image/png"


@pytest.mark.parametrize(
    ("data", "media_type", "reason"),
    [
        (ELF, "image", "not a supported image"),  # executable dressed up as a photo
        (b"-----BEGIN OPENSSH PRIVATE KEY-----", "image", "not a supported image"),
        (HEIC, "video", "not a supported video"),  # ISO media container, but not a video brand
        (JPEG, "video", "not a supported video"),  # category mismatch
        (MP4, "image", "not a supported image"),
        (JPEG, "audio", "only photos and videos"),
        (JPEG, "document", "only photos and videos"),
        (JPEG, "sticker", "only photos and videos"),
    ],
)
async def test_non_photo_video_content_is_refused(fake, data, media_type, reason):
    path = put(fake, "f.bin", data)
    fake.respond(message(path, media_type=media_type))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert reason in result.content[0].text
    assert not [c for c in result.content if c.type in ("image", "resource")]


@pytest.mark.parametrize("returned_chat", [OTHER_GROUP, ADA, None])
async def test_reply_from_another_chat_is_refused(fake, returned_chat):
    path = put(fake, "photo.jpg", JPEG)
    fake.respond(message(path, chat=returned_chat))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert "requested group" in result.content[0].text


async def test_mismatched_message_id_is_refused(fake):
    path = put(fake, "photo.jpg", JPEG)
    fake.respond(message(path, msg_id="SOMETHINGELSE"))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert "different message" in result.content[0].text


async def test_media_not_downloaded_is_a_clear_error(fake):
    fake.respond(message(""))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert "not downloaded" in result.content[0].text
    assert len(fake.calls()) == 1


@pytest.mark.parametrize(
    "local_path",
    [
        "/etc/passwd",
        "{media}/../secret.jpg",
        "{media}/sub/../../secret.jpg",
        "{media}/./photo.jpg/..",
        "relative/photo.jpg",
        "{media}",
        "{media}sibling/photo.jpg",  # shares the prefix but is a different directory
    ],
)
async def test_paths_outside_the_media_root_are_refused(fake, tmp_path, local_path):
    (fake.media.parent / "secret.jpg").write_bytes(JPEG)
    (fake.media.parent / "mediasibling").mkdir()
    (fake.media.parent / "mediasibling" / "photo.jpg").write_bytes(JPEG)
    put(fake, "photo.jpg", JPEG)
    fake.respond(message(local_path.format(media=fake.media)))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert "outside the configured media directory" in result.content[0].text
    assert not [c for c in result.content if c.type == "image"]


async def test_symlinked_file_is_refused(fake, tmp_path):
    outside = tmp_path / "outside.jpg"
    outside.write_bytes(JPEG)
    link = fake.media / "photo.jpg"
    link.symlink_to(outside)
    fake.respond(message(link))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert "symlink" in result.content[0].text


async def test_symlinked_directory_is_refused(fake, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "photo.jpg").write_bytes(JPEG)
    (fake.media / "ab").symlink_to(outside, target_is_directory=True)
    fake.respond(message(fake.media / "ab" / "photo.jpg"))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert "symlink" in result.content[0].text


async def test_hardlinked_file_is_refused(fake, tmp_path):
    original = put(fake, "original.jpg", JPEG)
    alias = fake.media / "alias.jpg"
    os.link(original, alias)
    fake.respond(message(alias))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert "hard link" in result.content[0].text


async def test_fifo_and_directory_are_refused_without_blocking(fake):
    fifo = fake.media / "photo.jpg"
    os.mkfifo(fifo, 0o600)
    fake.respond(message(fifo))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error and "regular file" in result.content[0].text
    (fake.media / "dir.jpg").mkdir()
    fake.respond(message(fake.media / "dir.jpg"))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error and "regular file" in result.content[0].text


async def test_oversized_file_is_refused(fake):
    path = put(fake, "big.jpg", JPEG + b"\x00" * 70_000)
    fake.respond(message(path))
    result = await fetch(fake, {"message_id": "3EB0A1"}, max_media_bytes=64 * 1024)
    assert result.is_error
    assert "larger than" in result.content[0].text


@pytest.mark.parametrize(
    "message_id",
    ["", "../etc/passwd", "--chat=x@g.us", "-3EB0", "3EB0 A1", "3EB0;rm -rf ~", "x" * 129, "3EB0‮A1"],
)
async def test_bad_message_ids_never_reach_wacli(fake, message_id):
    result = await fetch(fake, {"message_id": message_id})
    assert result.is_error
    assert "message_id" in result.content[0].text
    assert fake.calls() == []


async def test_media_access_without_media_dir_fails_closed(fake):
    result = await fetch(fake, {"message_id": "3EB0A1"}, media_dir=None, store_dir=None)
    assert result.is_error
    assert "not configured" in result.content[0].text
    assert fake.calls() == []


def test_sniff_recognizes_only_allowed_types():
    assert media.sniff(JPEG) == "image/jpeg"
    assert media.sniff(PNG) == "image/png"
    assert media.sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
    assert media.sniff(b"GIF89a" + b"\x00" * 10) == "image/gif"
    assert media.sniff(MP4) == "video/mp4"
    assert media.sniff(b"\x00\x00\x00\x14ftypqt  ") == "video/quicktime"
    assert media.sniff(b"\x00\x00\x00\x14ftyp3gp5") == "video/3gpp"
    for data in (HEIC, ELF, b"", b"\x00\x00\x00\x18ftypM4A ", b"%PDF-1.7", b"RIFF\x00\x00\x00\x00WAVE"):
        assert media.sniff(data) is None


async def test_media_root_swapped_for_a_symlink_is_refused(fake, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (elsewhere / "photo.jpg").write_bytes(JPEG)
    cfg_media = fake.media
    fake.media.rename(tmp_path / "old-media")
    cfg_media.symlink_to(elsewhere, target_is_directory=True)
    fake.respond(message(cfg_media / "photo.jpg"))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert "media directory cannot be opened" in result.content[0].text


@pytest.mark.parametrize("media_type", [["image"], {"t": "image"}, None, 7])
async def test_malformed_media_type_is_a_clean_refusal(fake, media_type):
    path = put(fake, "photo.jpg", JPEG)
    fake.respond(message(path, media_type=media_type))
    result = await fetch(fake, {"message_id": "3EB0A1"})
    assert result.is_error
    assert "only photos and videos" in result.content[0].text


def test_read_errors_become_media_errors(fake, monkeypatch):
    put(fake, "photo.jpg", JPEG)

    class Broken:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n):
            raise OSError(5, "Input/output error")

    def fake_fdopen(fd, *args, **kwargs):
        os.close(fd)
        return Broken()

    monkeypatch.setattr(media.os, "fdopen", fake_fdopen)
    with pytest.raises(media.MediaError, match="could not be read"):
        media.read_media_file(fake.media, ("photo.jpg",), 1024)


async def test_media_reads_are_serialized(fake, monkeypatch):
    # Each read can hold several copies of a large file in memory, so only one runs at a time.
    import anyio

    path = put(fake, "photo.jpg", JPEG)
    fake.respond(message(path))
    active = 0
    peak = 0
    original = media.read_media_file

    def tracking_read(*args):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            import time

            time.sleep(0.2)
            return original(*args)
        finally:
            active -= 1

    monkeypatch.setattr(media, "read_media_file", tracking_read)
    async with Client(build_server(fake.config())) as client:
        results = []

        async def one():
            results.append(await client.call_tool("get_group_media", {"chat": GROUP, "message_id": "3EB0A1"}))

        async with anyio.create_task_group() as tg:
            for _ in range(3):
                tg.start_soon(one)
    assert [r.is_error for r in results] == [False, False, False]
    assert peak == 1
