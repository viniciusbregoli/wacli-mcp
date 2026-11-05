"""Multi-account mode, with a fake wacli and fake sync daemons. Nothing here can reach WhatsApp."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import ADA, BOOK_CLUB, SECRET, FakeDaemon
from mcp import Client
from mcp.types import ElicitResult

from wacli_mcp.config import Config, ConfigError, load_accounts_file
from wacli_mcp.runner import WacliError, WacliRunner
from wacli_mcp.server import build_server

pytestmark = pytest.mark.anyio

READ_TOOLS = {"list_chats", "list_messages", "search_messages", "search_contacts", "history_coverage", "archive_health"}
SENT = {"sent": True, "to": ADA, "id": "3EB0FAKEMESSAGEID"}


@pytest.fixture
def stores(tmp_path: Path) -> dict[str, Path]:
    out = {}
    for name in ("personal", "work"):
        out[name] = tmp_path / "stores" / name
        out[name].mkdir(parents=True, mode=0o700)
    return out


def write_accounts(tmp_path: Path, body: str, mode: int = 0o600) -> Path:
    path = tmp_path / "accounts.toml"
    path.write_text(body)
    path.chmod(mode)
    return path


def two_accounts(stores, personal_extra: str = "", work_extra: str = "") -> str:
    return (
        f'[accounts.personal]\nstore = "{stores["personal"]}"\nlabel = "Personal phone"\n{personal_extra}\n'
        f'[accounts.work]\nstore = "{stores["work"]}"\n{work_extra}\n'
    )


def env_for(fake, accounts_file: Path, **extra) -> dict[str, str]:
    return {
        "WACLI_MCP_BIN": str(fake.path),
        "HOME": str(fake.home),
        "WACLI_MCP_NETWORK_ISOLATION": "off",
        "WACLI_MCP_ACCOUNTS_FILE": str(accounts_file),
        **extra,
    }


def multi_config(fake, tmp_path, stores, **kwargs) -> Config:
    extra = kwargs.pop("env", {})
    return Config.from_env(env_for(fake, write_accounts(tmp_path, two_accounts(stores, **kwargs)), **extra))


def store_args(fake) -> list[str]:
    return [next(a for a in c["argv"] if a.startswith("--store=")) for c in fake.calls()]


async def tools_of(cfg) -> dict:
    async with Client(build_server(cfg)) as client:
        return {t.name: t for t in (await client.list_tools()).tools}


async def call(cfg, tool, args, user=None):
    async with Client(build_server(cfg), elicitation_callback=user) as client:
        return await client.call_tool(tool, args)


# Schemas


async def test_single_account_schemas_have_no_account_argument(fake):
    tools = await tools_of(fake.config())
    assert set(tools) == READ_TOOLS
    assert all("account" not in t.input_schema.get("properties", {}) for t in tools.values())


async def test_single_account_ignores_an_injected_account(fake):
    # The SDK drops arguments that are not in the schema; the server-side value wins.
    fake.respond([])
    result = await call(fake.config(), "list_chats", {"account": "work"})
    assert not result.is_error
    assert "account" not in result.structured_content
    assert store_args(fake) == [f"--store={fake.home}"]


async def test_every_tool_requires_a_configured_account(fake, tmp_path, stores):
    tools = await tools_of(multi_config(fake, tmp_path, stores))
    assert set(tools) == READ_TOOLS
    for tool in tools.values():
        prop = tool.input_schema["properties"]["account"]
        assert prop["enum"] == ["personal", "work"]
        assert "account" in tool.input_schema["required"]
    assert "personal (Personal phone)" in tools["list_chats"].input_schema["properties"]["account"]["description"]


# Isolation of read tools


async def test_each_call_is_pinned_to_the_chosen_store(fake, tmp_path, stores):
    cfg = multi_config(fake, tmp_path, stores)
    fake.respond([{"jid": ADA, "name": "Ada"}])
    work = await call(cfg, "list_chats", {"account": "work"})
    personal = await call(cfg, "search_messages", {"account": "personal", "query": "invoice"})
    assert not work.is_error and not personal.is_error
    assert work.structured_content["account"] == "work"
    assert personal.structured_content["account"] == "personal"
    assert store_args(fake) == [f"--store={stores['work']}", f"--store={stores['personal']}"]
    assert all("--account" not in " ".join(c["argv"]) for c in fake.calls())


@pytest.mark.parametrize("account", [None, "other", "WORK", "../work"])
async def test_missing_or_unknown_account_runs_nothing(fake, tmp_path, stores, account):
    cfg = multi_config(fake, tmp_path, stores)
    args = {} if account is None else {"account": account}
    result = await call(cfg, "list_chats", args)
    assert result.is_error
    assert fake.calls() == []


async def test_chat_policy_is_per_account(fake, tmp_path, stores):
    cfg = multi_config(fake, tmp_path, stores, work_extra=f'denied_chats = ["{SECRET}"]')
    fake.respond([{"jid": ADA, "name": "Ada"}, {"jid": SECRET, "name": "Secret"}])

    work = await call(cfg, "list_chats", {"account": "work"})
    personal = await call(cfg, "list_chats", {"account": "personal"})
    assert [c["jid"] for c in work.structured_content["items"]] == [ADA]
    assert work.structured_content["hidden_by_policy"] == 1
    assert [c["jid"] for c in personal.structured_content["items"]] == [ADA, SECRET]

    calls_before = len(fake.calls())
    refused = await call(cfg, "list_messages", {"account": "work", "chat": SECRET})
    allowed = await call(cfg, "list_messages", {"account": "personal", "chat": SECRET})
    assert refused.is_error and not allowed.is_error
    assert len(fake.calls()) == calls_before + 1


async def test_health_reports_policy_per_account(fake, tmp_path, stores):
    cfg = multi_config(fake, tmp_path, stores, work_extra=f'allowed_chats = ["{ADA}"]')
    fake.respond({"store": {"messages": 1}})
    work = (await call(cfg, "archive_health", {"account": "work"})).structured_content
    personal = (await call(cfg, "archive_health", {"account": "personal"})).structured_content
    assert work["account"] == "work" and work["mcp_policy"]["chat_allowlist_active"] is True
    assert personal["account_label"] == "Personal phone"
    assert personal["mcp_policy"]["chat_allowlist_active"] is False


async def test_audit_log_names_the_account(fake, tmp_path, stores):
    log = tmp_path / "audit.jsonl"
    cfg = multi_config(fake, tmp_path, stores, env={"WACLI_MCP_AUDIT_LOG": str(log)})
    fake.respond([])
    await call(cfg, "list_chats", {"account": "work", "query": "private name"})
    (entry,) = [json.loads(line) for line in log.read_text().splitlines()]
    assert entry["account"] == "work" and entry["tool"] == "list_chats"
    assert "private name" not in log.read_text()


def test_runner_never_falls_back_to_the_default_store(fake, tmp_path, stores):
    cfg = multi_config(fake, tmp_path, stores)
    runner = WacliRunner(cfg)
    with pytest.raises(WacliError):
        runner.build_argv(["doctor"])
    assert runner.build_argv(["doctor"], target=cfg.account_view("work"))[-2] == f"--store={stores['work']}"


# wacli account names


def test_wacli_account_is_resolved_once_and_pinned(fake, tmp_path, stores):
    fake.respond({"name": "Work.Phone", "store_dir": str(stores["work"]), "default": False})
    path = write_accounts(tmp_path, '[accounts.work]\nwacli_account = "Work.Phone"\n')
    cfg = Config.from_env(env_for(fake, path))
    (call_,) = fake.calls()
    assert call_["argv"] == ["--read-only", "--json", "accounts", "show", "Work.Phone"]
    assert call_["env"]["WACLI_READONLY"] == "1"
    view = cfg.account_view("work")
    assert view.store_dir == stores["work"] and view.account is None


@pytest.mark.parametrize(
    "reply",
    [
        {"success": False, "data": None, "error": 'account "work" is not configured'},
        {"success": True, "data": {"name": "other", "store_dir": "/tmp"}, "error": None},
        {"success": True, "data": {"name": "work"}, "error": None},
        None,
        [],
        "ok",
    ],
)
def test_wacli_account_resolution_failures_are_config_errors(fake, tmp_path, reply):
    fake.scenario(stdout=json.dumps(reply), rc=0 if isinstance(reply, dict) and reply["success"] else 1)
    path = write_accounts(tmp_path, '[accounts.work]\nwacli_account = "work"\n')
    with pytest.raises(ConfigError, match="wacli account"):
        Config.from_env(env_for(fake, path))


def test_relative_store_from_wacli_is_refused(fake, tmp_path):
    base = fake.config(store_dir=None)
    path = write_accounts(tmp_path, '[accounts.work]\nwacli_account = "work"\n')
    with pytest.raises(ConfigError, match="relative store path"):
        load_accounts_file(path, base, send_switch=False, resolve=lambda *_: Path(".wacli/accounts/work"))


def test_check_reports_every_account(fake, tmp_path, stores, capsys, monkeypatch):
    from wacli_mcp import cli

    path = write_accounts(tmp_path, two_accounts(stores))
    for key, value in env_for(fake, path).items():
        monkeypatch.setenv(key, value)
    fake.respond({"authenticated": False, "store": {"messages": 0}})
    assert cli.main(["check"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [(a["account"], a["store"]) for a in report["accounts"]] == [
        ("personal", str(stores["personal"])),
        ("work", str(stores["work"])),
    ]


def test_two_aliases_on_one_store_are_refused(fake, tmp_path, stores):
    base = fake.config(store_dir=None)
    path = write_accounts(tmp_path, '[accounts.a]\nwacli_account = "a"\n[accounts.b]\nwacli_account = "b"\n')
    with pytest.raises(ConfigError, match="same store"):
        load_accounts_file(path, base, send_switch=False, resolve=lambda *_: stores["work"])


# Configuration errors


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ("", "at least one"),
        ("[accounts]\n", "at least one"),
        ('title = "x"\n[accounts.a]\nstore = "/tmp"\n', "unknown top-level"),
        ('[accounts.Work]\nstore = "{work}"\n', "alias"),
        ('[accounts.work]\nstore = "relative/path"\n', "absolute"),
        ('[accounts.work]\nstore = "/nonexistent/wacli-store"\n', "does not exist"),
        ('[accounts.work]\nlabel = "x"\n', "exactly one"),
        ('[accounts.work]\nstore = "{work}"\nwacli_account = "work"\n', "exactly one"),
        ('[accounts.work]\nstore = "{work}"\npassword = "x"\n', "unknown keys"),
        ('[accounts.work]\nstore = "{work}"\nallowed_chats = ["not-a-jid"]\n', "full JIDs"),
        (f'[accounts.work]\nstore = "{{work}}"\nallowed_chats = ["{ADA}"]\ndenied_chats = ["{ADA}"]\n', "both"),
        ('[accounts.work]\nstore = "{work}"\n[accounts.dup]\nstore = "{work}"\n', "same store"),
        ("[accounts.work\n", "not valid TOML"),
    ],
)
def test_invalid_accounts_files(fake, tmp_path, stores, body, match):
    path = write_accounts(tmp_path, body.replace("{work}", str(stores["work"])))
    with pytest.raises(ConfigError, match=match):
        Config.from_env(env_for(fake, path))


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_accounts_file_must_be_private(fake, tmp_path, stores, mode):
    path = write_accounts(tmp_path, two_accounts(stores), mode=mode)
    with pytest.raises(ConfigError, match="chmod 600"):
        Config.from_env(env_for(fake, path))


@pytest.mark.parametrize(
    "key", ["WACLI_MCP_STORE", "WACLI_MCP_ACCOUNT", "WACLI_MCP_DENIED_CHATS", "WACLI_MCP_SEND_RECIPIENTS"]
)
def test_per_account_env_cannot_be_mixed_with_the_file(fake, tmp_path, stores, key):
    path = write_accounts(tmp_path, two_accounts(stores))
    with pytest.raises(ConfigError, match=key):
        Config.from_env(env_for(fake, path, **{key: "x"}))


# Sending


class User:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def __call__(self, context, params):
        self.prompts.append(params.message)
        return ElicitResult(action="accept", content={"approve": True})


def send_config(fake, tmp_path, stores, **env) -> Config:
    return multi_config(
        fake,
        tmp_path,
        stores,
        personal_extra=f'[accounts.personal.send]\nrecipients = {{ ada = "{ADA}" }}',
        work_extra=f'[accounts.work.send]\nrecipients = {{ club = "{BOOK_CLUB}" }}',
        env={"WACLI_MCP_ENABLE_SEND": "1", **env},
    )


@pytest.fixture
def daemons(stores):
    running = {name: FakeDaemon(store) for name, store in stores.items()}
    yield running
    for d in running.values():
        d.stop()


async def test_send_recipients_without_the_global_switch_stay_off(fake, tmp_path, stores):
    cfg = multi_config(
        fake, tmp_path, stores, work_extra=f'[accounts.work.send]\nrecipients = {{ club = "{BOOK_CLUB}" }}'
    )
    assert not cfg.send_enabled
    assert "send_message" not in await tools_of(cfg)


def test_global_switch_needs_recipients_somewhere(fake, tmp_path, stores):
    with pytest.raises(ConfigError, match="send recipients"):
        multi_config(fake, tmp_path, stores, env={"WACLI_MCP_ENABLE_SEND": "1"})


def test_recipients_must_be_visible_in_their_own_account(fake, tmp_path, stores):
    extra = f'denied_chats = ["{BOOK_CLUB}"]\n[accounts.work.send]\nrecipients = {{ club = "{BOOK_CLUB}" }}'
    with pytest.raises(ConfigError, match="hidden by the chat policy"):
        multi_config(fake, tmp_path, stores, work_extra=extra, env={"WACLI_MCP_ENABLE_SEND": "1"})


async def test_send_account_enum_lists_only_accounts_that_can_send(fake, tmp_path, stores):
    cfg = multi_config(
        fake,
        tmp_path,
        stores,
        work_extra=f'[accounts.work.send]\nrecipients = {{ club = "{BOOK_CLUB}" }}',
        env={"WACLI_MCP_ENABLE_SEND": "1"},
    )
    tools = await tools_of(cfg)
    schema = tools["send_message"].input_schema
    account = schema["properties"]["account"]
    # Pydantic renders a one-value Literal as `const`.
    assert account.get("enum", [account.get("const")]) == ["work"]
    assert set(schema["required"]) == {"account", "recipient", "text"}
    result = await call(cfg, "send_message", {"account": "personal", "recipient": "club", "text": "hi"})
    assert result.is_error and fake.calls() == []


async def test_recipient_of_another_account_is_refused(fake, tmp_path, stores, daemons):
    cfg = send_config(fake, tmp_path, stores)
    for recipient in ("ada", ADA):
        result = await call(cfg, "send_message", {"account": "work", "recipient": recipient, "text": "hi"})
        assert result.is_error
        assert "for this account: club" in result.content[0].text
    assert fake.calls() == []


async def test_send_goes_through_the_chosen_accounts_store_and_daemon(fake, tmp_path, stores, daemons):
    fake.respond(SENT)
    user = User()
    cfg = send_config(fake, tmp_path, stores)
    result = await call(cfg, "send_message", {"account": "work", "recipient": "club", "text": "meeting moved"}, user)
    assert not result.is_error, result.content
    assert result.structured_content["account"] == "work"
    (prompt,) = user.prompts
    assert "from the work account" in prompt and BOOK_CLUB in prompt
    (argv,) = [c["argv"] for c in fake.calls()]
    assert f"--store={stores['work']}" in argv and f"--to={BOOK_CLUB}" in argv


async def test_send_needs_the_daemon_of_that_account(fake, tmp_path, stores):
    only_personal = FakeDaemon(stores["personal"])
    try:
        cfg = send_config(fake, tmp_path, stores)
        result = await call(cfg, "send_message", {"account": "work", "recipient": "club", "text": "hi"}, User())
        assert result.is_error and "sync --follow" in result.content[0].text
        assert fake.calls() == []
        health = await call(cfg, "archive_health", {"account": "personal"})
        assert health.structured_content["mcp_policy"]["send_ready"] is True
        health = await call(cfg, "archive_health", {"account": "work"})
        assert health.structured_content["mcp_policy"]["send_ready"] is False
    finally:
        only_personal.stop()


async def test_send_limits_are_per_account(fake, tmp_path, stores, daemons):
    fake.respond(SENT)
    cfg = send_config(fake, tmp_path, stores, WACLI_MCP_SEND_PER_HOUR="1")
    server = build_server(cfg)
    async with Client(server, elicitation_callback=User()) as client:
        first = await client.call_tool("send_message", {"account": "work", "recipient": "club", "text": "one"})
        second = await client.call_tool("send_message", {"account": "work", "recipient": "club", "text": "two"})
        other = await client.call_tool("send_message", {"account": "personal", "recipient": "ada", "text": "one"})
    assert not first.is_error and not other.is_error
    assert second.is_error and "per hour" in second.content[0].text
    assert store_args(fake) == [f"--store={stores['work']}", f"--store={stores['personal']}"]


async def test_send_audit_names_the_account(fake, tmp_path, stores, daemons):
    fake.respond(SENT)
    log = tmp_path / "send-audit.jsonl"
    cfg = send_config(fake, tmp_path, stores, WACLI_MCP_AUDIT_LOG=str(log))
    await call(cfg, "send_message", {"account": "work", "recipient": "club", "text": "do not log me"}, User())
    await call(cfg, "send_message", {"account": "work", "recipient": "ada", "text": "do not log me"}, User())
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    assert [(e["account"], e["outcome"]) for e in entries] == [("work", "sent"), ("work", "rejected")]
    assert "do not log me" not in log.read_text()
