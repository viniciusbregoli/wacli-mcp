from __future__ import annotations

import json
import stat

import pytest
from mcp import Client

from wacli_mcp.server import build_server

pytestmark = pytest.mark.anyio

EXPECTED_TOOLS = {
    "list_chats",
    "list_messages",
    "search_messages",
    "search_contacts",
    "history_coverage",
    "archive_health",
}
SEARCH_RESULT = {
    "messages": [
        {
            "ChatJID": "1@s.whatsapp.net",
            "MsgID": "A",
            "Text": "invoice",
            "LocalPath": "/x",
            "Timestamp": "2026-01-01T00:00:00Z",
            "FromMe": False,
        },
        {
            "ChatJID": "2@s.whatsapp.net",
            "MsgID": "B",
            "Text": "invoice too",
            "Timestamp": "2026-01-01T00:00:00Z",
            "FromMe": False,
        },
    ],
    "fts": True,
    "page": {"has_more": False, "next_cursor": None},
    "source": {"last_sync_at": None, "scope": "local_archive"},
}


async def test_only_read_only_tools_are_exposed(fake):
    async with Client(build_server(fake.config())) as client:
        tools = (await client.list_tools()).tools
    assert {t.name for t in tools} == EXPECTED_TOOLS
    for tool in tools:
        assert tool.annotations is not None and tool.annotations.read_only_hint is True
        assert tool.annotations.open_world_hint is False
        for word in ("send", "delete", "edit", "revoke", "download", "backfill", "auth"):
            assert word not in tool.name


async def test_search_puts_query_after_double_dash(fake):
    fake.respond(SEARCH_RESULT)
    async with Client(build_server(fake.config())) as client:
        result = await client.call_tool("search_messages", {"query": "--store=/etc", "chat": "--account=x", "limit": 5})
    assert not result.is_error
    argv = fake.calls()[0]["argv"]
    assert argv[-2:] == ["--", "--store=/etc"]
    assert "--chat=--account=x" in argv
    assert argv.count("--read-only") == 1
    data = result.structured_content
    assert data["untrusted_content"] is True
    assert "LocalPath" not in json.dumps(data) and "local_path" not in json.dumps(data)


async def test_deny_list_hides_results_and_rejects_explicit_chat(fake):
    fake.respond(SEARCH_RESULT)
    server = build_server(fake.config(denied_chats=frozenset({"2@s.whatsapp.net"})))
    async with Client(server) as client:
        result = await client.call_tool("search_messages", {"query": "invoice"})
        assert [m["msg_id"] for m in result.structured_content["messages"]] == ["A"]
        assert result.structured_content["hidden_by_policy"] == 1
        denied = await client.call_tool("list_messages", {"chat": "2@s.whatsapp.net"})
    assert denied.is_error
    assert len(fake.calls()) == 1


async def test_allowlist_requires_jid(fake):
    async with Client(build_server(fake.config(allowed_chats=frozenset({"1@s.whatsapp.net"})))) as client:
        result = await client.call_tool("list_messages", {"chat": "Ada Lovelace"})
    assert result.is_error
    assert "exact JID" in result.content[0].text
    assert fake.calls() == []


@pytest.mark.parametrize(
    "args",
    [
        {"query": "x", "limit": 0},
        {"query": "x", "limit": 51},
        {"query": "x", "context_before": 6},
        {"query": "x", "context_after": 1, "limit": 30},
        {"query": "x", "after": "last week"},
        {"query": "x", "media_type": "sticker"},
    ],
)
async def test_bad_arguments_never_reach_wacli(fake, args):
    async with Client(build_server(fake.config())) as client:
        result = await client.call_tool("search_messages", args)
    assert result.is_error
    assert fake.calls() == []


async def test_wacli_errors_become_tool_errors(fake):
    fake.scenario(stdout=json.dumps({"success": False, "data": None, "error": "store locked"}), rc=1)
    async with Client(build_server(fake.config())) as client:
        result = await client.call_tool("list_chats", {})
    assert result.is_error
    assert "store locked" in result.content[0].text


async def test_audit_log_is_private_and_has_no_arguments(fake, tmp_path):
    log = tmp_path / "audit.jsonl"
    fake.respond(SEARCH_RESULT)
    async with Client(build_server(fake.config(audit_log=log))) as client:
        await client.call_tool("search_messages", {"query": "very-private-term"})
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    text = log.read_text()
    assert "very-private-term" not in text
    entry = json.loads(text.splitlines()[-1])
    assert entry["tool"] == "search_messages" and entry["ok"] is True and entry["count"] == 2


def test_audit_records_do_not_reach_stderr():
    from wacli_mcp.server import audit_logger

    assert audit_logger.propagate is False
