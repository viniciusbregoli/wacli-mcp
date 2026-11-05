from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from wacli_mcp import validation
from wacli_mcp.config import Config
from wacli_mcp.shaping import project_message, sanitize_text, shape_chats, shape_messages

RLO = chr(0x202E)
ZWSP = chr(0x200B)
ZWJ = chr(0x200D)


def cfg(**kw) -> Config:
    return Config(wacli_bin=Path("/bin/true"), home=Path("/tmp"), **kw)


def test_sanitize_strips_bidi_zero_width_and_controls():
    assert sanitize_text(f"+1555{RLO}evil{ZWSP}\x1b[31m\x00ok", 100) == "+1555evil[31mok"


def test_sanitize_keeps_newlines_tabs_and_emoji_joiners():
    family = f"{chr(0x1F468)}{ZWJ}{chr(0x1F469)}"
    assert sanitize_text(f"a\nb\t{family}", 100) == f"a\nb\t{family}"


def test_sanitize_truncates_with_marker():
    assert sanitize_text("x" * 250, 200) == "x" * 200 + "... [truncated 50 chars]"


def test_message_projection_drops_local_and_cdn_paths():
    raw = {
        "ChatJID": "1@s.whatsapp.net",
        "MsgID": "A",
        "Timestamp": "2026-01-01T00:00:00Z",
        "FromMe": False,
        "Text": "",
        "DisplayText": "hello",
        "LocalPath": "/home/user/.local/state/wacli/media/x.jpg",
        "DirectPath": "/v/t62/secret",
        "DownloadedAt": "0001-01-01T00:00:00Z",
        "MediaType": "",
    }
    out = project_message(raw, 100)
    assert out == {
        "chat_jid": "1@s.whatsapp.net",
        "msg_id": "A",
        "timestamp": "2026-01-01T00:00:00Z",
        "from_me": False,
        "text": "hello",
    }


def test_policy_filters_messages_and_context():
    data = {
        "messages": [{"ChatJID": "1@s.whatsapp.net", "Text": "a"}, {"ChatJID": "2@s.whatsapp.net", "Text": "b"}],
        "context": [
            {"chat_jid": "1@s.whatsapp.net", "msg_id": "x", "messages": [{"ChatJID": "1@s.whatsapp.net", "Text": "a"}]},
            {"chat_jid": "2@s.whatsapp.net", "msg_id": "y", "messages": [{"ChatJID": "2@s.whatsapp.net", "Text": "b"}]},
        ],
        "page": {"has_more": False, "next_cursor": None},
        "source": {"last_sync_at": None},
    }
    out = shape_messages(data, cfg(denied_chats=frozenset({"2@s.whatsapp.net"})))
    assert [m["text"] for m in out["messages"]] == ["a"]
    assert out["hidden_by_policy"] == 1
    assert [g["chat_jid"] for g in out["context"]] == ["1@s.whatsapp.net"]
    assert out["untrusted_content"] is True


def test_allowlist_filters_chats():
    rows = [{"jid": "1@s.whatsapp.net", "name": "A"}, {"jid": "2@g.us", "name": "B"}]
    out = shape_chats(rows, cfg(allowed_chats=frozenset({"2@g.us"})))
    assert [c["jid"] for c in out["items"]] == ["2@g.us"]
    assert out["hidden_by_policy"] == 1


@pytest.mark.parametrize(
    "value",
    ["15550000001@s.whatsapp.net", "120363000000000001@g.us", "+1 555 000 0001", "Ada Lovelace", "--store=/etc"],
)
def test_chat_ref_accepts_ids_numbers_and_names(value):
    assert validation.chat_ref(value) == value


def test_zwj_emoji_names_round_trip():
    family = "Family " + chr(0x1F468) + chr(0x200D) + chr(0x1F469)
    assert sanitize_text(family, 100) == family
    assert validation.chat_ref(family) == family
    assert validation.query_text(family) == family


@pytest.mark.parametrize("value", ["", "x" * 101, f"Ada{RLO}", "a\nb"])
def test_chat_ref_rejects_bad_values(value):
    with pytest.raises(ToolError):
        validation.chat_ref(value)


def test_allowlist_requires_explicit_jid():
    policy = cfg(allowed_chats=frozenset({"1@s.whatsapp.net"}))
    validation.chat_allowed_by_policy("1@s.whatsapp.net", policy)
    with pytest.raises(ToolError, match="exact JID"):
        validation.chat_allowed_by_policy("Ada", policy)
    with pytest.raises(ToolError, match="not available"):
        validation.chat_allowed_by_policy("2@s.whatsapp.net", policy)


@pytest.mark.parametrize("value", ["2026-01-01", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00-03:00"])
def test_time_bound_ok(value):
    assert validation.time_bound(value, "after") == value


@pytest.mark.parametrize("value", ["yesterday", "2026-13-01", "2026-01-01T10:00:00", "--limit=5"])
def test_time_bound_rejects(value):
    with pytest.raises(ToolError):
        validation.time_bound(value, "after")


def test_cursor_and_query():
    assert validation.cursor("eyJ2IjoxfQ==") == "eyJ2IjoxfQ=="
    with pytest.raises(ToolError):
        validation.cursor("abc def")
    with pytest.raises(ToolError):
        validation.query_text("   ")
    with pytest.raises(ToolError):
        validation.query_text("q" * 201)


def test_ids_cursor_and_sync_time_are_sanitized():
    bidi = chr(0x202E)
    cfg = Config(wacli_bin=Path("/bin/true"), home=Path("/"))
    out = shape_messages(
        {
            "messages": [],
            "context": [{"chat_jid": "1@s.whatsapp.net", "msg_id": "ID" + bidi + "evil", "messages": []}],
            "page": {"has_more": True, "next_cursor": "c" + bidi},
            "source": {"last_sync_at": "2026" + bidi},
        },
        cfg,
    )
    assert bidi not in json.dumps(out, ensure_ascii=False)
    assert out["context"][0]["hit_msg_id"] == "IDevil"
