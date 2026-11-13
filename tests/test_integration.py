"""End-to-end tests with the real wacli binary.

Each test builds a throwaway store in a temp directory, never touches the
owner's store, and runs every wacli call inside an empty network namespace,
so nothing can reach WhatsApp.
"""

from __future__ import annotations

import json
import os
import sqlite3

import pytest
from conftest import ADA, BIDI_OVERRIDE, BOOK_CLUB, REAL_WACLI, SECRET, build_real_store, unshare_works
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
    return build_real_store(tmp_path_factory.mktemp("wacli-real"))


def make_config(store, **extra) -> Config:
    home, store_dir = store
    env = {
        "WACLI_MCP_HOME": str(home),
        "WACLI_MCP_BIN": str(REAL_WACLI),
        "WACLI_MCP_STORE": str(store_dir),
        "WACLI_MCP_NETWORK_ISOLATION": "require",
        **extra,
    }
    return Config.from_env(env)


async def call(cfg, tool, args=None):
    async with Client(build_server(cfg)) as client:
        return await client.call_tool(tool, args or {})


async def test_health_reports_isolated_unauthenticated_store(store):
    result = await call(make_config(store), "archive_health")
    data = result.structured_content
    assert not result.is_error
    assert data["authenticated"] is False
    assert data["store_counts"] == {"messages": 4, "chats": 3, "contacts": 2, "groups": 0}
    assert data["mcp_policy"]["network_isolated"] is True


async def test_search_with_context_and_sanitized_injection(store):
    result = await call(make_config(store), "search_messages", {"query": "invoice", "context_before": 1})
    data = result.structured_content
    assert {m["msg_id"] for m in data["messages"]} == {"M1", "M2", "S1"}
    assert data["context"]
    injection = await call(make_config(store), "search_messages", {"query": "instructions"})
    (msg,) = injection.structured_content["messages"]
    assert msg["chat_jid"] == BOOK_CLUB
    assert BIDI_OVERRIDE not in msg["text"]
    assert injection.structured_content["untrusted_content"] is True


async def test_deny_list_hides_secret_chat_everywhere(store):
    cfg = make_config(store, WACLI_MCP_DENIED_CHATS=SECRET)
    search = (await call(cfg, "search_messages", {"query": "secret"})).structured_content
    assert search["messages"] == [] and search["hidden_by_policy"] == 1
    chats = (await call(cfg, "list_chats")).structured_content
    assert SECRET not in [c["jid"] for c in chats["items"]]
    contacts = (await call(cfg, "search_contacts", {"query": "Secret"})).structured_content
    assert contacts["items"] == []
    coverage = (await call(cfg, "history_coverage")).structured_content
    assert SECRET not in json.dumps(coverage)


async def test_allowlist_limits_to_one_chat(store):
    cfg = make_config(store, WACLI_MCP_ALLOWED_CHATS=ADA)
    listing = (await call(cfg, "list_messages", {"chat": ADA, "oldest_first": True})).structured_content
    assert [m["msg_id"] for m in listing["messages"]] == ["M1", "M2"]
    recent = (await call(cfg, "list_messages")).structured_content
    assert {m["chat_jid"] for m in recent["messages"]} == {ADA}


async def test_flag_like_query_is_treated_as_text(store):
    result = await call(make_config(store), "search_messages", {"query": "--limit"})
    assert not result.is_error
    assert result.structured_content["messages"] == []


async def test_unknown_chat_name_is_a_clean_error(store):
    result = await call(make_config(store), "list_messages", {"chat": "nobody"})
    assert result.is_error
    assert "no local exact name match" in result.content[0].text


async def test_pagination_cursor_round_trip(store):
    cfg = make_config(store)
    first = (await call(cfg, "list_messages", {"limit": 2})).structured_content
    assert first["page"]["has_more"] is True
    second = (await call(cfg, "list_messages", {"limit": 2, "cursor": first["page"]["next_cursor"]})).structured_content
    ids = [m["msg_id"] for m in first["messages"] + second["messages"]]
    assert sorted(ids) == ["G1", "M1", "M2", "S1"]


async def test_store_is_not_modified_by_reads(store):
    _, store_dir = store
    db = store_dir / "wacli.db"
    before = (db.stat().st_mtime_ns, db.stat().st_size)
    cfg = make_config(store)
    for tool, args in [("list_chats", {}), ("search_messages", {"query": "invoice"}), ("archive_health", {})]:
        assert not (await call(cfg, tool, args)).is_error
    assert (db.stat().st_mtime_ns, db.stat().st_size) == before


async def test_stdio_entry_point_end_to_end(store):
    """Spawns the real `wacli-mcp` CLI as an MCP client would."""
    import sys

    from mcp import StdioServerParameters

    home, store_dir = store
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "wacli_mcp", "stdio"],
        env={
            "WACLI_MCP_HOME": str(home),
            "WACLI_MCP_BIN": str(REAL_WACLI),
            "WACLI_MCP_STORE": str(store_dir),
            "WACLI_MCP_DENIED_CHATS": SECRET,
        },
    )
    async with Client(params) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool("search_messages", {"query": "invoice"})
    assert "search_messages" in tools and "send_message" not in tools
    assert {m["msg_id"] for m in result.structured_content["messages"]} == {"M1", "M2"}


async def test_send_is_delegated_to_the_sync_daemon_from_an_offline_sandbox(tmp_path_factory):
    """Real wacli, run with no network at all, hands the send to a fake `sync --follow` daemon."""
    from conftest import DAEMON_REPLY, FakeDaemon
    from mcp.types import ElicitResult

    home, store_dir = build_real_store(tmp_path_factory.mktemp("s"))
    db = store_dir / "wacli.db"
    before = (db.stat().st_mtime_ns, db.stat().st_size)
    prompts = []

    async def user(context, params):
        prompts.append(params.message)
        return ElicitResult(action="accept", content={"approve": True})

    text = "dinner at 8?\n-- sent from the archive assistant"
    daemon = FakeDaemon(store_dir)
    try:
        cfg = make_config(
            (home, store_dir),
            WACLI_MCP_ENABLE_SEND="1",
            WACLI_MCP_SEND_RECIPIENTS=f"ada={ADA}",
        )
        assert cfg.network_isolated
        async with Client(build_server(cfg), elicitation_callback=user) as client:
            result = await client.call_tool("send_message", {"recipient": "ada", "text": text})
        requests = daemon.requests()
    finally:
        daemon.stop()

    assert not result.is_error, result.content
    assert result.structured_content["sent"] is True
    assert result.structured_content["message_id"] == DAEMON_REPLY["id"]
    assert len(prompts) == 1 and text in prompts[0]
    (request,) = requests
    assert request["kind"] == "text"
    assert request["to"] == ADA
    assert request["message"] == text
    assert request["no_preview"] is True
    assert not request.get("allow_self") and not request.get("mentions") and not request.get("reply_to")
    # The delegated path never opens the archive for writing.
    assert (db.stat().st_mtime_ns, db.stat().st_size) == before


async def test_send_file_is_delegated_with_a_staged_snapshot_from_an_offline_sandbox(tmp_path_factory):
    """Real wacli hands a staged copy of an outbox file to the fake daemon and never opens the archive."""
    from conftest import DAEMON_REPLY, FakeDaemon
    from mcp.types import ElicitResult

    root = tmp_path_factory.mktemp("f")
    home, store_dir = build_real_store(root)
    outbox, staging = root / "outbox", root / "staging"
    for path in (outbox, staging):
        path.mkdir(mode=0o700)
    pdf = b"%PDF-1.4\nsynthetic invoice\n"
    (outbox / "invoice.pdf").write_bytes(pdf)
    db = store_dir / "wacli.db"
    before = (db.stat().st_mtime_ns, db.stat().st_size)
    prompts = []

    async def user(context, params):
        prompts.append(params.message)
        return ElicitResult(action="accept", content={"approve": True})

    daemon = FakeDaemon(store_dir)
    try:
        cfg = make_config(
            (home, store_dir),
            WACLI_MCP_ENABLE_SEND="1",
            WACLI_MCP_SEND_RECIPIENTS=f"ada={ADA}",
            WACLI_MCP_ENABLE_SEND_FILES="1",
            WACLI_MCP_SEND_FILE_DIR=str(outbox),
            WACLI_MCP_SEND_STAGING_DIR=str(staging),
        )
        assert cfg.network_isolated
        async with Client(build_server(cfg), elicitation_callback=user) as client:
            result = await client.call_tool(
                "send_file", {"recipient": "ada", "file": "invoice.pdf", "caption": "the invoice"}
            )
        requests = daemon.requests()
    finally:
        daemon.stop()

    assert not result.is_error, result.content
    assert result.structured_content["sent"] is True
    assert result.structured_content["message_id"] == DAEMON_REPLY["id"]
    assert len(prompts) == 1 and "invoice.pdf" in prompts[0]
    (request,) = requests
    assert request["kind"] == "file"
    assert request["to"] == ADA
    assert os.path.dirname(request["file"]) == str(staging.resolve())
    assert request["file"].endswith(".pdf") and os.path.basename(request["file"]) != "invoice.pdf"
    assert request["filename"] == "invoice.pdf"
    assert request["mime"] == "application/pdf"
    assert request["as"] == "document"
    assert request["caption"] == "the invoice"
    assert request["max_size_bytes"] == 16 * 1024 * 1024
    assert not request.get("reply_to") and not request.get("ptt")
    assert list(staging.iterdir()) == []
    assert (outbox / "invoice.pdf").read_bytes() == pdf
    assert (db.stat().st_mtime_ns, db.stat().st_size) == before


async def test_wacli_refuses_a_file_outside_the_media_roots_it_is_given(tmp_path_factory):
    """WACLI_MEDIA_ROOTS makes the real wacli child refuse any --file outside the staging directory."""
    from conftest import FakeDaemon

    from wacli_mcp.runner import WacliError, WacliRunner

    root = tmp_path_factory.mktemp("r")
    home, store_dir = build_real_store(root)
    staging = root / "staging"
    staging.mkdir(mode=0o700)
    elsewhere = root / "elsewhere.txt"
    elsewhere.write_text("not staged")
    daemon = FakeDaemon(store_dir)
    try:
        cfg = make_config((home, store_dir), WACLI_MCP_ENABLE_SEND="1", WACLI_MCP_SEND_RECIPIENTS=f"ada={ADA}")
        with pytest.raises(WacliError):
            await WacliRunner(cfg).run_write(
                ["send", "file", f"--to={ADA}", f"--file={elsewhere}", "--mime=text/plain", "--as=document"],
                extra_env={"WACLI_MEDIA_ROOTS": str(staging.resolve())},
            )
        requests = daemon.requests()
    finally:
        daemon.stop()
    assert requests == []


async def test_send_without_daemon_never_runs_wacli(tmp_path_factory):
    home, store_dir = build_real_store(tmp_path_factory.mktemp("n"))
    cfg = make_config((home, store_dir), WACLI_MCP_ENABLE_SEND="1", WACLI_MCP_SEND_RECIPIENTS=f"ada={ADA}")
    async with Client(build_server(cfg), elicitation_callback=None) as client:
        result = await client.call_tool("send_message", {"recipient": "ada", "text": "hi"})
    assert result.is_error and "wacli sync --follow" in result.content[0].text
    assert sorted(p.name for p in store_dir.iterdir()) == ["wacli.db"]


@pytest.fixture(scope="module")
def two_accounts(tmp_path_factory):
    """Two real stores registered as named wacli accounts in a synthetic wacli config.yaml.

    `personal` keeps Ada and the book club; `work` keeps only the secret chat.
    wacli's default account is `work`, so a fallback to wacli's default would show up.
    """
    root = tmp_path_factory.mktemp("wacli-accounts")
    stores = {}
    for name, drop in (("personal", [SECRET]), ("work", [ADA, BOOK_CLUB])):
        (root / name).mkdir()
        home, store = build_real_store(root / name)
        db = sqlite3.connect(store / "wacli.db")
        for jid in drop:
            for table, column in (("messages", "chat_jid"), ("chats", "jid"), ("contacts", "jid")):
                db.execute(f"DELETE FROM {table} WHERE {column} = ?", (jid,))  # noqa: S608
        db.commit()
        db.close()
        stores[name] = (home, store)
    state = root / "state"
    (state / "wacli").mkdir(parents=True, mode=0o700)
    (state / "wacli" / "config.yaml").write_text(
        "default_account: work\naccounts:\n"
        + "".join(f"  {name}:\n    store: {store}\n" for name, (_, store) in stores.items())
    )
    accounts_file = root / "accounts.toml"
    accounts_file.write_text(
        '[accounts.personal]\nwacli_account = "personal"\n\n[accounts.work]\nwacli_account = "work"\n'
        f'denied_chats = ["{BOOK_CLUB}"]\n'
    )
    accounts_file.chmod(0o600)
    env = {
        "WACLI_MCP_HOME": str(stores["personal"][0]),
        "WACLI_MCP_BIN": str(REAL_WACLI),
        "WACLI_MCP_NETWORK_ISOLATION": "require",
        "XDG_STATE_HOME": str(state),
        "WACLI_MCP_ACCOUNTS_FILE": str(accounts_file),
    }
    return env, {name: store for name, (_, store) in stores.items()}


async def test_named_wacli_accounts_resolve_and_stay_isolated(two_accounts):
    env, stores = two_accounts
    cfg = Config.from_env(env)
    assert {v.alias: v.store_dir for v in cfg.account_views()} == stores

    personal = await call(cfg, "search_messages", {"account": "personal", "query": "invoice"})
    work = await call(cfg, "search_messages", {"account": "work", "query": "invoice"})
    assert {m["chat_jid"] for m in personal.structured_content["messages"]} == {ADA}
    assert {m["chat_jid"] for m in work.structured_content["messages"]} == {SECRET}

    health = await call(cfg, "archive_health", {"account": "personal"})
    assert health.structured_content["store_counts"]["chats"] == 2
    missing = await call(cfg, "archive_health", {})
    assert missing.is_error
