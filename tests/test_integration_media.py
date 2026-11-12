"""get_group_media end to end with the real wacli binary.

The store is a throwaway built in a temp directory with synthetic rows and
synthetic files; every wacli call runs inside an empty network namespace.
"""

from __future__ import annotations

import base64

import pytest
from conftest import (
    ADA,
    BAND_TWO,
    BOOK_CLUB,
    REAL_WACLI,
    SYNTHETIC_JPEG,
    SYNTHETIC_MP4,
    build_media_store,
    unshare_works,
)
from mcp import Client

from wacli_mcp.config import Config
from wacli_mcp.server import build_server

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.integration,
    pytest.mark.skipif(not REAL_WACLI.exists(), reason="wacli binary not installed"),
    pytest.mark.skipif(not unshare_works(), reason="unprivileged user namespaces unavailable"),
]


@pytest.fixture(scope="module")
def store(tmp_path_factory):
    return build_media_store(tmp_path_factory.mktemp("wacli-media"))


def make_config(store, **extra) -> Config:
    home, store_dir = store
    return Config.from_env(
        {
            "WACLI_MCP_HOME": str(home),
            "WACLI_MCP_BIN": str(REAL_WACLI),
            "WACLI_MCP_STORE": str(store_dir),
            "WACLI_MCP_NETWORK_ISOLATION": "require",
            **extra,
        }
    )


async def call(cfg, tool, args):
    async with Client(build_server(cfg)) as client:
        return await client.call_tool(tool, args)


async def test_group_photo_and_video_are_served(store):
    cfg = make_config(store)
    photo = await call(cfg, "get_group_media", {"chat": BOOK_CLUB, "message_id": "GM1"})
    assert not photo.is_error, photo.content
    (image,) = [c for c in photo.content if c.type == "image"]
    assert base64.b64decode(image.data) == SYNTHETIC_JPEG
    assert photo.structured_content["caption"] == "flyer"

    video = await call(cfg, "get_group_media", {"chat": BAND_TWO, "message_id": "BV1"})
    assert not video.is_error, video.content
    (blob,) = [c for c in video.content if c.type == "resource"]
    assert base64.b64decode(blob.resource.blob) == SYNTHETIC_MP4
    assert video.structured_content["mime_type"] == "video/mp4"


@pytest.mark.parametrize(
    ("chat", "msg_id"), [(ADA, "AM1"), (BOOK_CLUB, "AM1"), (BAND_TWO, "GM1"), ("Ada Lovelace", "AM1")]
)
async def test_media_outside_the_named_group_is_refused(store, chat, msg_id):
    result = await call(make_config(store), "get_group_media", {"chat": chat, "message_id": msg_id})
    assert result.is_error
    assert not [c for c in result.content if c.type in ("image", "resource")]


async def test_existing_chat_policy_applies_to_media(store):
    cfg = make_config(store, WACLI_MCP_DENIED_CHATS=BAND_TWO)
    assert (await call(cfg, "get_group_media", {"chat": BAND_TWO, "message_id": "BV1"})).is_error
    assert not (await call(cfg, "get_group_media", {"chat": BOOK_CLUB, "message_id": "GM1"})).is_error


async def test_direct_chat_text_and_contacts_still_readable(store):
    cfg = make_config(store)
    dm = (await call(cfg, "list_messages", {"chat": ADA, "oldest_first": True})).structured_content
    assert [m["msg_id"] for m in dm["messages"]][:2] == ["M1", "M2"]
    private_photo = next(m for m in dm["messages"] if m["msg_id"] == "AM1")
    assert private_photo["media_available_locally"] is True and "/media/" not in str(private_photo)
    contacts = (await call(cfg, "search_contacts", {"query": "Ada"})).structured_content
    assert ADA in [c["jid"] for c in contacts["items"]]


async def test_media_reads_leave_the_store_untouched(store):
    _, store_dir = store
    db = store_dir / "wacli.db"
    before = (db.stat().st_mtime_ns, db.stat().st_size)
    assert not (await call(make_config(store), "get_group_media", {"chat": BOOK_CLUB, "message_id": "GM1"})).is_error
    assert (db.stat().st_mtime_ns, db.stat().st_size) == before
