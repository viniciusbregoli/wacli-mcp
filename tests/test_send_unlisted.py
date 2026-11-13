"""Sending to recipients outside the allowlist, with a fake wacli and a fake sync daemon.

Nothing here can reach WhatsApp. Every unlisted send needs a verified per-send approval and fails closed.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import ADA, BOOK_CLUB, GROUP, SECRET, SYNTHETIC_JPEG, FakeDaemon
from mcp import Client
from mcp.types import ElicitResult, Implementation

from wacli_mcp.config import Config, ConfigError
from wacli_mcp.sending import MAX_PROMPT_UNITS, confirmation_question, prompt_units, unlisted_jid
from wacli_mcp.server import _instructions, build_server

pytestmark = pytest.mark.anyio

RECIPIENTS = (("ada", ADA), ("club", BOOK_CLUB))
SENT = {"sent": True, "to": ADA, "id": "3EB0FAKEMESSAGEID"}
TRUSTED = "openbot"
# Synthetic number (555 is reserved for fiction), shown to the user as +5511955550100.
NUMBER = "+55 (11) 95555-0100"
DIGITS = "5511955550100"
NUMBER_JID = f"{DIGITS}@s.whatsapp.net"
NOT_LISTED = "NOT on the pre-approved list"
EMOJI = chr(0x1F600)


def open_config(fake, **overrides) -> Config:
    return fake.config(
        send_enabled=True,
        send_recipients=RECIPIENTS,
        send_any_recipient=True,
        send_confirm_clients=frozenset({TRUSTED}),
        **overrides,
    )


class User:
    """Scripted answers to elicitation prompts, recording what was shown."""

    def __init__(self, action: str = "accept", approve: bool = True) -> None:
        self.action = action
        self.approve = approve
        self.prompts: list[str] = []

    async def __call__(self, context, params):
        self.prompts.append(params.message)
        if self.action != "accept":
            return ElicitResult(action=self.action)
        return ElicitResult(action="accept", content={"approve": self.approve})


def never_asked(*_):
    raise AssertionError("the user must not be prompted")


async def call(server, tool, args, user=None, name=TRUSTED):
    async with Client(server, elicitation_callback=user, client_info=Implementation(name=name, version="1")) as client:
        return await client.call_tool(tool, args)


async def send(server, args, user=None, name=TRUSTED):
    return await call(server, "send_message", args, user, name)


def text_of(result) -> str:
    return result.content[0].text


def audit_entries(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines() if "send_" in line]


def argv_of(fake) -> list[list[str]]:
    return [c["argv"] for c in fake.calls()]


# Config from the environment


def env_for(fake, **extra) -> dict[str, str]:
    return {
        "HOME": str(fake.home),
        "WACLI_MCP_BIN": str(fake.path),
        "WACLI_MCP_NETWORK_ISOLATION": "off",
        "WACLI_MCP_STORE": str(fake.home),
        "WACLI_MCP_ENABLE_SEND": "1",
        "WACLI_MCP_SEND_RECIPIENTS": f"ada={ADA}, club={BOOK_CLUB}",
        "WACLI_MCP_SEND_ANY_RECIPIENT": "1",
        "WACLI_MCP_SEND_CONFIRM_CLIENTS": f"{TRUSTED}, other-client",
        **extra,
    }


def test_any_recipient_config_from_env(fake):
    cfg = Config.from_env(env_for(fake))
    assert cfg.send_any_recipient is True
    assert cfg.send_confirm_clients == frozenset({TRUSTED, "other-client"})
    assert cfg.send_recipients == RECIPIENTS


def test_any_recipient_is_off_by_default(fake):
    env = env_for(fake)
    del env["WACLI_MCP_SEND_ANY_RECIPIENT"]
    cfg = Config.from_env(env)
    assert cfg.send_any_recipient is False
    assert cfg.send_confirm_clients == frozenset()


def test_single_account_needs_no_recipients_when_any_recipient_is_on(fake):
    cfg = Config.from_env(env_for(fake, WACLI_MCP_SEND_RECIPIENTS=""))
    assert cfg.send_enabled and cfg.send_any_recipient and cfg.send_recipients == ()


def test_recipients_are_still_required_without_any_recipient(fake):
    env = env_for(fake, WACLI_MCP_SEND_RECIPIENTS="")
    del env["WACLI_MCP_SEND_ANY_RECIPIENT"]
    with pytest.raises(ConfigError, match="requires WACLI_MCP_SEND_RECIPIENTS"):
        Config.from_env(env)


@pytest.mark.parametrize(
    ("drop", "extra", "message"),
    [
        ("WACLI_MCP_ENABLE_SEND", {}, "requires WACLI_MCP_ENABLE_SEND=1"),
        (None, {"WACLI_MCP_ENABLE_SEND": "0"}, "requires WACLI_MCP_ENABLE_SEND=1"),
        (None, {"WACLI_MCP_SEND_CONFIRMATION": "none"}, "requires WACLI_MCP_SEND_CONFIRMATION=elicit"),
        ("WACLI_MCP_SEND_CONFIRM_CLIENTS", {}, "requires WACLI_MCP_SEND_CONFIRM_CLIENTS"),
        (None, {"WACLI_MCP_SEND_CONFIRM_CLIENTS": " , "}, "requires WACLI_MCP_SEND_CONFIRM_CLIENTS"),
        (None, {"WACLI_MCP_SEND_CONFIRM_CLIENTS": "bad name"}, "must be MCP client names"),
        (None, {"WACLI_MCP_SEND_CONFIRM_CLIENTS": f"{TRUSTED},-leading"}, "must be MCP client names"),
        (None, {"WACLI_MCP_SEND_CONFIRM_CLIENTS": "x" * 65}, "must be MCP client names"),
        (None, {"WACLI_MCP_SEND_ANY_RECIPIENT": "sure"}, "must be 1 or 0"),
    ],
)
def test_any_recipient_config_errors(fake, drop, extra, message):
    env = env_for(fake, **extra)
    if drop:
        del env[drop]
    with pytest.raises(ConfigError, match=message):
        Config.from_env(env)


def test_confirm_clients_are_ignored_without_any_recipient(fake):
    env = env_for(fake)
    del env["WACLI_MCP_SEND_ANY_RECIPIENT"]
    assert Config.from_env(env).send_confirm_clients == frozenset()


# Config from the accounts file


@pytest.fixture
def stores(tmp_path: Path) -> dict[str, Path]:
    out = {}
    for name in ("personal", "work"):
        out[name] = tmp_path / "stores" / name
        out[name].mkdir(parents=True, mode=0o700)
    return out


def accounts_env(fake, tmp_path, stores, personal_send: str = "", work_send: str = "", **extra) -> dict[str, str]:
    path = tmp_path / "accounts.toml"
    path.write_text(
        f'[accounts.personal]\nstore = "{stores["personal"]}"\n{personal_send}\n'
        f'[accounts.work]\nstore = "{stores["work"]}"\n{work_send}\n'
    )
    path.chmod(0o600)
    return {
        "WACLI_MCP_BIN": str(fake.path),
        "HOME": str(fake.home),
        "WACLI_MCP_NETWORK_ISOLATION": "off",
        "WACLI_MCP_ACCOUNTS_FILE": str(path),
        "WACLI_MCP_ENABLE_SEND": "1",
        "WACLI_MCP_SEND_ANY_RECIPIENT": "1",
        "WACLI_MCP_SEND_CONFIRM_CLIENTS": TRUSTED,
        **extra,
    }


PERSONAL_OPEN = "[accounts.personal.send]\nany_recipient = true"
WORK_LISTED = f'[accounts.work.send]\nrecipients = {{ club = "{BOOK_CLUB}" }}'


def test_account_opt_in_needs_no_recipients_table(fake, tmp_path, stores):
    cfg = Config.from_env(accounts_env(fake, tmp_path, stores, PERSONAL_OPEN, WORK_LISTED))
    personal, work = cfg.account_views()
    assert personal.send_enabled and personal.send_any_recipient and personal.send_recipients == ()
    assert work.send_enabled and not work.send_any_recipient
    assert cfg.send_any_recipient is True


def test_account_opt_in_may_combine_with_recipients(fake, tmp_path, stores):
    send = f'[accounts.personal.send]\nany_recipient = true\nrecipients = {{ ada = "{ADA}" }}'
    cfg = Config.from_env(accounts_env(fake, tmp_path, stores, send))
    personal = cfg.account_views()[0]
    assert personal.send_any_recipient and personal.send_recipients == (("ada", ADA),)


def test_account_opt_in_is_false_by_default(fake, tmp_path, stores):
    send = f'[accounts.personal.send]\nrecipients = {{ ada = "{ADA}" }}'
    with pytest.raises(ConfigError, match="send.any_recipient = true for at least one account"):
        Config.from_env(accounts_env(fake, tmp_path, stores, send, WORK_LISTED))


def test_env_switch_with_no_account_opting_in_is_an_error(fake, tmp_path, stores):
    with pytest.raises(ConfigError, match="send.any_recipient = true for at least one account"):
        Config.from_env(accounts_env(fake, tmp_path, stores, WORK_LISTED, WORK_LISTED.replace("work", "personal")))


@pytest.mark.parametrize("value", ['"yes"', "1", '"true"'])
def test_account_opt_in_must_be_a_boolean(fake, tmp_path, stores, value):
    send = f"[accounts.personal.send]\nany_recipient = {value}"
    with pytest.raises(ConfigError, match="any_recipient must be true or false"):
        Config.from_env(accounts_env(fake, tmp_path, stores, send, WORK_LISTED))


def test_empty_recipients_table_is_still_refused_without_opt_in(fake, tmp_path, stores):
    send = "[accounts.personal.send]\nany_recipient = false"
    with pytest.raises(ConfigError, match="non-empty table"):
        Config.from_env(accounts_env(fake, tmp_path, stores, send, PERSONAL_OPEN.replace("personal", "work")))


def test_account_opt_in_does_nothing_without_the_env_switch(fake, tmp_path, stores):
    env = accounts_env(fake, tmp_path, stores, PERSONAL_OPEN, WORK_LISTED)
    del env["WACLI_MCP_SEND_ANY_RECIPIENT"]
    cfg = Config.from_env(env)
    assert not cfg.send_any_recipient
    assert not any(v.send_any_recipient for v in cfg.account_views())


def test_account_opt_in_needs_the_send_switch_too(fake, tmp_path, stores):
    env = accounts_env(fake, tmp_path, stores, PERSONAL_OPEN, WORK_LISTED)
    del env["WACLI_MCP_ENABLE_SEND"]
    with pytest.raises(ConfigError, match="requires WACLI_MCP_ENABLE_SEND=1"):
        Config.from_env(env)


async def test_an_account_without_opt_in_refuses_unlisted_numbers(fake, tmp_path, stores):
    cfg = Config.from_env(accounts_env(fake, tmp_path, stores, PERSONAL_OPEN, WORK_LISTED))
    daemons = {name: FakeDaemon(store) for name, store in stores.items()}
    try:
        fake.respond(SENT)
        user = User()
        server = build_server(cfg)
        refused = await send(server, {"account": "work", "recipient": NUMBER, "text": "hi"}, never_asked)
        assert refused.is_error and "configured aliases for this account: club" in text_of(refused)
        assert fake.calls() == []
        allowed = await send(server, {"account": "personal", "recipient": NUMBER, "text": "hi"}, user)
        assert not allowed.is_error, allowed.content
        assert allowed.structured_content["account"] == "personal"
        assert "from the personal account" in user.prompts[0] and NOT_LISTED in user.prompts[0]
        (argv,) = argv_of(fake)
        assert f"--to={NUMBER_JID}" in argv and f"--store={stores['personal']}" in argv
    finally:
        for d in daemons.values():
            d.stop()


async def test_multi_account_tool_text_names_the_open_accounts(fake, tmp_path, stores):
    cfg = Config.from_env(accounts_env(fake, tmp_path, stores, PERSONAL_OPEN, WORK_LISTED))
    async with Client(build_server(cfg)) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "send_message")
    assert set(tool.input_schema["properties"]) == {"account", "recipient", "text"}
    assert "for the personal account(s)" in tool.description


# Recipient parsing


@pytest.mark.parametrize(
    ("value", "jid"),
    [
        ("+5511955550100", NUMBER_JID),
        (NUMBER, NUMBER_JID),
        (DIGITS, NUMBER_JID),
        ("+1 555-000-0099", "15550000099@s.whatsapp.net"),
        (BOOK_CLUB, BOOK_CLUB),
        (GROUP, GROUP),
        (SECRET, SECRET),
        ("1234567890123@lid", "1234567890123@lid"),
    ],
)
def test_unlisted_jid_accepts(value, jid):
    assert unlisted_jid(value) == jid


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0115550000",
        "+0115550000",
        "1234567",
        "+1234567890123456",
        "55119abc50100",
        "Ada Lovelace",
        "120363000000000009@newsletter",
        "status@broadcast",
        "+55 11 9555 0100 ext 5",
        "+55\n11955550100",
    ],
)
def test_unlisted_jid_rejects(value):
    with pytest.raises(Exception, match="recipient must be"):
        unlisted_jid(value)


def test_prompt_units_counts_utf16():
    assert prompt_units("abc") == 3
    assert prompt_units(EMOJI) == 2
    assert prompt_units(EMOJI * 3 + "a") == 7


# Approved unlisted text sends


async def test_approved_unlisted_text_send_runs_exact_command(fake, daemon):
    fake.respond(SENT)
    user = User()
    server = build_server(open_config(fake))
    result = await send(server, {"recipient": NUMBER, "text": "oi\nate logo -at 8"}, user)
    assert not result.is_error, result.content
    sc = result.structured_content
    assert sc["sent"] is True and sc["unlisted"] is True
    assert sc["recipient"] == NUMBER_JID and sc["jid"] == NUMBER_JID
    assert sc["message_id"] == "3EB0FAKEMESSAGEID"
    (prompt,) = user.prompts
    assert f"+{DIGITS} ({NUMBER_JID})" in prompt
    assert NOT_LISTED in prompt
    assert "check every digit before approving" in prompt
    assert "oi\nate logo -at 8" in prompt
    (call_,) = fake.calls()
    argv = call_["argv"]
    assert "--read-only" not in argv
    assert argv[-5:] == ["send", "text", f"--to={NUMBER_JID}", "--message=oi\nate logo -at 8", "--no-preview"]


async def test_unlisted_jid_form_is_sent_to_that_jid(fake, daemon):
    fake.respond(SENT)
    user = User()
    result = await send(build_server(open_config(fake)), {"recipient": SECRET, "text": "hi"}, user)
    assert result.structured_content["unlisted"] is True and result.structured_content["jid"] == SECRET
    assert f"+{SECRET.split('@')[0]} ({SECRET})" in user.prompts[0]
    assert f"--to={SECRET}" in argv_of(fake)[0]


async def test_group_jid_unlisted_send(fake, daemon):
    fake.respond(SENT)
    user = User()
    result = await send(build_server(open_config(fake)), {"recipient": GROUP, "text": "hello group"}, user)
    assert not result.is_error, result.content
    assert result.structured_content["unlisted"] is True and result.structured_content["jid"] == GROUP
    (prompt,) = user.prompts
    assert f"the group {GROUP}" in prompt and NOT_LISTED in prompt
    assert argv_of(fake)[0][-5:] == ["send", "text", f"--to={GROUP}", "--message=hello group", "--no-preview"]


async def test_audit_marks_the_recipient_unlisted_and_never_logs_the_number(fake, daemon, tmp_path):
    fake.respond(SENT)
    log = tmp_path / "audit.jsonl"
    await send(build_server(open_config(fake, audit_log=log)), {"recipient": NUMBER, "text": "private words"}, User())
    raw = log.read_text()
    assert DIGITS not in raw and "55119" not in raw and "private words" not in raw
    (entry,) = audit_entries(log)
    assert entry["recipient"] == "<unlisted>" and entry["outcome"] == "sent" and entry["chars"] == len("private words")


async def test_audit_of_a_rejected_unlisted_send_has_no_number(fake, daemon, tmp_path):
    log = tmp_path / "audit.jsonl"
    server = build_server(open_config(fake, audit_log=log))
    result = await send(server, {"recipient": NUMBER, "text": "hi"}, never_asked, name="unknown-client")
    assert result.is_error
    assert DIGITS not in log.read_text()
    assert [e["outcome"] for e in audit_entries(log)] == ["rejected"]


async def test_tool_text_and_schema_mention_unlisted_recipients(fake):
    async with Client(build_server(open_config(fake))) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "send_message")
    assert "approval of every single send" in tool.description
    assert "phone number in international format" in tool.input_schema["properties"]["recipient"]["description"]


async def test_declined_unlisted_send_reports_the_jid_and_sends_nothing(fake, daemon, tmp_path):
    log = tmp_path / "audit.jsonl"
    result = await send(
        build_server(open_config(fake, audit_log=log)), {"recipient": NUMBER, "text": "hi"}, User(approve=False)
    )
    assert result.structured_content == {
        "sent": False,
        "recipient": NUMBER_JID,
        "reason": "the user did not approve this message",
    }
    assert fake.calls() == []
    (entry,) = audit_entries(log)
    assert entry["outcome"] == "declined" and entry["recipient"] == "<unlisted>"
    assert DIGITS not in log.read_text()


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_declined_or_cancelled_elicitation_sends_nothing(fake, daemon, action):
    user = User(action=action)
    result = await send(build_server(open_config(fake)), {"recipient": NUMBER, "text": "hi"}, user)
    assert result.is_error
    assert len(user.prompts) == 1
    assert fake.calls() == []


async def test_rate_limit_applies_to_unlisted_sends(fake, daemon):
    fake.respond(SENT)
    server = build_server(open_config(fake, send_per_hour=1))
    async with Client(
        server, elicitation_callback=User(), client_info=Implementation(name=TRUSTED, version="1")
    ) as client:
        first = await client.call_tool("send_message", {"recipient": NUMBER, "text": "one"})
        second = await client.call_tool("send_message", {"recipient": "+5511955550101", "text": "two"})
    assert not first.is_error
    assert second.is_error and "per hour" in text_of(second)
    assert len(fake.calls()) == 1


async def test_duplicate_guard_applies_to_unlisted_sends(fake, daemon):
    fake.respond(SENT)
    server = build_server(open_config(fake))
    async with Client(
        server, elicitation_callback=User(), client_info=Implementation(name=TRUSTED, version="1")
    ) as client:
        first = await client.call_tool("send_message", {"recipient": NUMBER, "text": "on my way"})
        # The same number written another way is the same recipient.
        second = await client.call_tool("send_message", {"recipient": f"+{DIGITS}", "text": "on my way"})
    assert not first.is_error and second.is_error
    assert "already sent" in text_of(second)
    assert len(fake.calls()) == 1


async def test_unlisted_send_still_needs_the_sync_daemon(fake):
    result = await send(build_server(open_config(fake)), {"recipient": NUMBER, "text": "hi"}, never_asked)
    assert result.is_error and "wacli sync --follow" in text_of(result)
    assert fake.calls() == []


# Fail closed: nothing runs and the user is never prompted


async def test_client_without_elicitation_capability_cannot_send_unlisted(fake, daemon):
    async with Client(build_server(open_config(fake)), client_info=Implementation(name=TRUSTED, version="1")) as client:
        result = await client.call_tool("send_message", {"recipient": NUMBER, "text": "hi"})
    assert result.is_error
    assert "cannot be verified" in text_of(result) and "form elicitation" in text_of(result)
    assert fake.calls() == []


async def test_client_name_outside_the_confirm_clients_cannot_send_unlisted(fake, daemon):
    result = await send(build_server(open_config(fake)), {"recipient": NUMBER, "text": "hi"}, never_asked, name="mcp")
    assert result.is_error
    assert "cannot be verified" in text_of(result) and "not one the operator verified" in text_of(result)
    assert fake.calls() == []


async def test_client_name_match_is_exact(fake, daemon):
    server = build_server(open_config(fake))
    for name in (TRUSTED.upper(), TRUSTED + "-evil", " " + TRUSTED):
        result = await send(server, {"recipient": NUMBER, "text": "hi"}, never_asked, name=name)
        assert result.is_error, name
    assert fake.calls() == []


async def test_the_client_name_check_does_not_apply_to_listed_recipients(fake, daemon):
    fake.respond(SENT)
    user = User()
    result = await send(build_server(open_config(fake)), {"recipient": "ada", "text": "hi"}, user, name="mcp")
    assert not result.is_error, result.content
    assert "unlisted" not in result.structured_content
    assert len(user.prompts) == 1


async def test_prompt_over_the_display_limit_is_refused_before_asking(fake, daemon):
    # 700 emoji are 1400 UTF-16 units in the text alone, and 700 characters, so they pass validation.
    text = EMOJI * 700 + "a" * 700
    assert len(text) <= 1500 and prompt_units(text) > MAX_PROMPT_UNITS
    server = build_server(open_config(fake, send_max_chars=1500))
    result = await send(server, {"recipient": NUMBER, "text": text}, never_asked)
    assert result.is_error and "too long to show in full" in text_of(result)
    assert fake.calls() == []


async def test_prompt_just_under_the_limit_is_shown(fake, daemon):
    fake.respond(SENT)
    user = User()
    server = build_server(open_config(fake, send_max_chars=1900))
    # Grow the text until the prompt is within one emoji of the limit.
    text = "a" * 1000
    while True:
        bigger = text + "a"
        if prompt_units(confirmation_question("<unlisted>", NUMBER_JID, bigger, listed=False)) > MAX_PROMPT_UNITS:
            break
        text = bigger
    result = await send(server, {"recipient": NUMBER, "text": text}, user)
    assert not result.is_error, result.content
    assert prompt_units(user.prompts[0]) <= MAX_PROMPT_UNITS
    assert text in user.prompts[0]


async def test_a_long_prompt_is_fine_for_a_listed_recipient(fake, daemon):
    fake.respond(SENT)
    text = EMOJI * 700 + "a" * 700
    user = User()
    server = build_server(open_config(fake, send_max_chars=1500))
    result = await send(server, {"recipient": "ada", "text": text}, user)
    assert not result.is_error, result.content
    assert prompt_units(user.prompts[0]) > MAX_PROMPT_UNITS


@pytest.mark.parametrize(
    "recipient",
    [
        "01155550100",
        "+01155550100",
        "+12345",
        "5511abc550100",
        "Ada Lovelace",
        "120363000000000009@newsletter",
        "status@broadcast",
        "",
    ],
)
async def test_malformed_unlisted_recipients_never_prompt_or_send(fake, daemon, recipient):
    result = await send(build_server(open_config(fake)), {"recipient": recipient, "text": "hi"}, never_asked)
    assert result.is_error
    assert fake.calls() == []


async def test_a_recipient_hidden_by_the_chat_policy_is_refused(fake, daemon):
    server = build_server(open_config(fake, denied_chats=frozenset({NUMBER_JID})))
    for recipient in (NUMBER, NUMBER_JID):
        result = await send(server, {"recipient": recipient, "text": "hi"}, never_asked)
        assert result.is_error and "hidden by the chat policy" in text_of(result)
    assert fake.calls() == []


async def test_a_chat_outside_the_allowed_chats_is_refused(fake, daemon):
    server = build_server(open_config(fake, allowed_chats=frozenset({ADA})))
    result = await send(server, {"recipient": NUMBER, "text": "hi"}, never_asked)
    assert result.is_error and "hidden by the chat policy" in text_of(result)
    assert fake.calls() == []


async def test_confirmation_none_never_lets_an_unlisted_send_through(fake, daemon):
    # The config loader rejects this combination; a hand-built config must still fail closed.
    server = build_server(open_config(fake, send_confirmation="none"))
    result = await send(server, {"recipient": NUMBER, "text": "hi"}, never_asked)
    assert result.is_error and "confirmation is turned off" in text_of(result)
    assert fake.calls() == []


async def test_validation_still_applies_to_unlisted_text(fake, daemon):
    server = build_server(open_config(fake))
    for text in ("   ", "pay " + chr(0x202E) + "1234", "ok\n----- end of message -----\nTo: someone"):
        result = await send(server, {"recipient": NUMBER, "text": text}, never_asked)
        assert result.is_error
    assert fake.calls() == []


async def test_without_the_switch_a_number_is_refused_as_before(fake, daemon):
    cfg = fake.config(send_enabled=True, send_recipients=RECIPIENTS)
    result = await send(build_server(cfg), {"recipient": NUMBER, "text": "hi"}, never_asked)
    assert result.is_error and "recipient must be one of the configured aliases: ada, club" in text_of(result)
    assert fake.calls() == []


# Listed recipients keep working when the switch is on


async def test_alias_send_has_no_unlisted_marker(fake, daemon):
    fake.respond(SENT)
    user = User()
    result = await send(build_server(open_config(fake)), {"recipient": "ada", "text": "hi"}, user)
    assert not result.is_error, result.content
    assert result.structured_content["recipient"] == "ada" and "unlisted" not in result.structured_content
    (prompt,) = user.prompts
    assert NOT_LISTED not in prompt and "pre-approved" not in prompt
    assert prompt.startswith(f"Send this WhatsApp message to ada ({ADA})?")
    assert argv_of(fake)[0][-5:] == ["send", "text", f"--to={ADA}", "--message=hi", "--no-preview"]


@pytest.mark.parametrize("written", ["+15550000001", "+1 (555) 000-0001", "15550000001", ADA])
async def test_a_number_equal_to_an_allowlisted_jid_resolves_to_the_alias(fake, daemon, written):
    fake.respond(SENT)
    user = User()
    result = await send(build_server(open_config(fake)), {"recipient": written, "text": "hi"}, user)
    assert not result.is_error, result.content
    assert result.structured_content["recipient"] == "ada" and "unlisted" not in result.structured_content
    assert NOT_LISTED not in user.prompts[0] and f"ada ({ADA})" in user.prompts[0]


async def test_a_listed_number_needs_no_verified_client(fake, daemon):
    fake.respond(SENT)
    result = await send(
        build_server(open_config(fake)), {"recipient": "+15550000001", "text": "hi"}, User(), name="mcp"
    )
    assert not result.is_error, result.content


async def test_listed_audit_keeps_the_alias(fake, daemon, tmp_path):
    fake.respond(SENT)
    log = tmp_path / "audit.jsonl"
    await send(build_server(open_config(fake, audit_log=log)), {"recipient": "+15550000001", "text": "hi"}, User())
    (entry,) = audit_entries(log)
    assert entry["recipient"] == "ada"


# Tool schema and health


async def test_send_tool_schema_hides_the_approval_and_context(fake, daemon):
    async with Client(build_server(open_config(fake))) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "send_message")
    assert set(tool.input_schema["properties"]) == {"recipient", "text"}
    assert set(tool.input_schema["required"]) == {"recipient", "text"}


async def test_send_file_schema_hides_the_approval_and_context(fake, tmp_path):
    cfg = file_config(fake, tmp_path)
    async with Client(build_server(cfg)) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "send_file")
    assert set(tool.input_schema["properties"]) == {"recipient", "file", "caption"}


async def test_multi_account_send_schema_adds_only_account(fake, tmp_path, stores):
    cfg = Config.from_env(accounts_env(fake, tmp_path, stores, PERSONAL_OPEN, WORK_LISTED))
    async with Client(build_server(cfg)) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "send_message")
    assert set(tool.input_schema["properties"]) == {"account", "recipient", "text"}


async def test_health_reports_send_any_recipient(fake, daemon):
    fake.respond({"authenticated": True, "store": {"messages": 1}})
    async with Client(build_server(open_config(fake))) as client:
        policy = (await client.call_tool("archive_health", {})).structured_content["mcp_policy"]
    assert policy["send_any_recipient"] is True and policy["send_enabled"] is True


async def test_health_reports_send_any_recipient_off(fake, daemon):
    fake.respond({"authenticated": True, "store": {"messages": 1}})
    cfg = fake.config(send_enabled=True, send_recipients=RECIPIENTS)
    async with Client(build_server(cfg)) as client:
        policy = (await client.call_tool("archive_health", {})).structured_content["mcp_policy"]
    assert policy["send_any_recipient"] is False


# send_file to an unlisted recipient


def file_config(fake, tmp_path, **overrides) -> Config:
    outbox = tmp_path / "outbox"
    staging = tmp_path / "staging"
    for path in (outbox, staging):
        path.mkdir(exist_ok=True)
        path.chmod(0o700)
    return open_config(
        fake, send_files_enabled=True, send_file_dir=outbox.resolve(), send_staging_dir=staging.resolve(), **overrides
    )


async def test_approved_unlisted_file_send_runs_exact_command(fake, daemon, tmp_path):
    cfg = file_config(fake, tmp_path)
    (cfg.send_file_dir / "photo.jpg").write_bytes(SYNTHETIC_JPEG)
    fake.respond(SENT)
    user = User()
    log = tmp_path / "audit.jsonl"
    cfg = file_config(fake, tmp_path, audit_log=log)
    result = await call(
        build_server(cfg), "send_file", {"recipient": NUMBER, "file": "photo.jpg", "caption": "look"}, user
    )
    assert not result.is_error, result.content
    sc = result.structured_content
    assert sc["sent"] is True and sc["unlisted"] is True and sc["jid"] == NUMBER_JID and sc["file"] == "photo.jpg"
    (prompt,) = user.prompts
    assert f"+{DIGITS} ({NUMBER_JID})" in prompt and NOT_LISTED in prompt
    assert "photo.jpg" in prompt and "look" in prompt
    (argv,) = argv_of(fake)
    assert argv[argv.index("send") : argv.index("send") + 3] == ["send", "file", f"--to={NUMBER_JID}"]
    assert "--caption=look" in argv and "--as=image" in argv
    assert sorted(p.name for p in cfg.send_staging_dir.iterdir()) == []
    (entry,) = audit_entries(log)
    assert entry["tool"] == "send_file" and entry["recipient"] == "<unlisted>" and entry["outcome"] == "sent"
    assert DIGITS not in log.read_text()


async def test_unlisted_file_send_is_refused_for_an_unverified_client(fake, daemon, tmp_path):
    cfg = file_config(fake, tmp_path)
    (cfg.send_file_dir / "photo.jpg").write_bytes(SYNTHETIC_JPEG)
    for name in ("mcp", TRUSTED):
        user = never_asked if name == "mcp" else None
        if name == TRUSTED:
            # Trusted name but no elicitation capability.
            async with Client(build_server(cfg), client_info=Implementation(name=name, version="1")) as client:
                result = await client.call_tool("send_file", {"recipient": NUMBER, "file": "photo.jpg"})
        else:
            result = await call(build_server(cfg), "send_file", {"recipient": NUMBER, "file": "photo.jpg"}, user, name)
        assert result.is_error and "cannot be verified" in text_of(result)
    assert fake.calls() == []
    assert list(cfg.send_staging_dir.iterdir()) == []


async def test_declined_unlisted_file_sends_nothing(fake, daemon, tmp_path):
    cfg = file_config(fake, tmp_path)
    (cfg.send_file_dir / "photo.jpg").write_bytes(SYNTHETIC_JPEG)
    result = await call(build_server(cfg), "send_file", {"recipient": NUMBER, "file": "photo.jpg"}, User(approve=False))
    assert result.structured_content["sent"] is False and result.structured_content["recipient"] == NUMBER_JID
    assert fake.calls() == []


async def test_unlisted_file_caption_that_makes_the_prompt_too_long_is_refused(fake, daemon, tmp_path):
    cfg = file_config(fake, tmp_path, send_max_chars=1500)
    (cfg.send_file_dir / "photo.jpg").write_bytes(SYNTHETIC_JPEG)
    caption = EMOJI * 700 + "a" * 700
    result = await call(
        build_server(cfg), "send_file", {"recipient": NUMBER, "file": "photo.jpg", "caption": caption}, never_asked
    )
    assert result.is_error and "too long to show in full" in text_of(result)
    assert fake.calls() == []


async def test_unlisted_file_to_a_hidden_chat_is_refused(fake, daemon, tmp_path):
    cfg = file_config(fake, tmp_path, denied_chats=frozenset({NUMBER_JID}))
    (cfg.send_file_dir / "photo.jpg").write_bytes(SYNTHETIC_JPEG)
    result = await call(build_server(cfg), "send_file", {"recipient": NUMBER, "file": "photo.jpg"}, never_asked)
    assert result.is_error and "hidden by the chat policy" in text_of(result)
    assert fake.calls() == []


def test_server_instructions_mention_unlisted_sends_only_when_enabled(fake):
    assert "outside that list" in _instructions(open_config(fake), downloads_enabled=False)
    plain = fake.config(send_enabled=True, send_recipients=RECIPIENTS)
    assert "outside that list" not in _instructions(plain, downloads_enabled=False)


# Codex as OpenBot runs it

CODEX = "codex-mcp-client"
# The form requestedSchema shape Codex's app-server parses (MCP 2025-11-25), with unknown fields refused.
FORM_KEYS = {"$schema", "type", "properties", "required"}
BOOLEAN_KEYS = {"type", "title", "description", "default"}


class CodexUser:
    """Codex's app-server, then OpenBot's card, then a person who taps Yes.

    Codex answers cancel by itself, before any card, when the schema does not parse.
    """

    def __init__(self) -> None:
        self.prompts: list[str] = []
        self.schemas: list[dict] = []

    async def __call__(self, context, params):
        schema = params.requested_schema
        self.schemas.append(schema)
        properties = schema.get("properties", {})
        if (
            set(schema) - FORM_KEYS
            or schema.get("type") != "object"
            or any(set(p) - BOOLEAN_KEYS or p.get("type") != "boolean" for p in properties.values())
        ):
            return ElicitResult(action="cancel")
        self.prompts.append(params.message)
        return ElicitResult(action="accept", content={name: True for name in properties})


def codex_config(fake, tmp_path) -> Config:
    return replace(file_config(fake, tmp_path), send_confirm_clients=frozenset({CODEX}))


async def codex_call(server, tool, args, user):
    # Codex connects with the initialize handshake, so prompts travel as elicitation/create requests.
    info = Implementation(name=CODEX, version="0.167.0")
    async with Client(server, elicitation_callback=user, client_info=info, mode="legacy") as client:
        return await client.call_tool(tool, args)


@pytest.mark.parametrize("recipient", ["ada", NUMBER])
async def test_codex_shows_the_text_approval_and_the_send_goes_through(fake, daemon, tmp_path, recipient):
    fake.respond(SENT)
    user = CodexUser()
    result = await codex_call(
        build_server(codex_config(fake, tmp_path)), "send_message", {"recipient": recipient, "text": "hi"}, user
    )
    assert not result.is_error, result.content
    assert result.structured_content["sent"] is True
    (schema,) = user.schemas
    assert set(schema) <= FORM_KEYS and schema["required"] == ["approve"]
    (prompt,) = user.prompts
    assert "hi" in prompt
    assert len(fake.calls()) == 1


@pytest.mark.parametrize("recipient", ["ada", NUMBER])
async def test_codex_shows_the_file_approval_and_the_send_goes_through(fake, daemon, tmp_path, recipient):
    cfg = codex_config(fake, tmp_path)
    (cfg.send_file_dir / "photo.jpg").write_bytes(SYNTHETIC_JPEG)
    fake.respond(SENT)
    user = CodexUser()
    result = await codex_call(build_server(cfg), "send_file", {"recipient": recipient, "file": "photo.jpg"}, user)
    assert not result.is_error, result.content
    assert result.structured_content["sent"] is True
    (schema,) = user.schemas
    assert set(schema) <= FORM_KEYS
    (prompt,) = user.prompts
    assert "photo.jpg" in prompt
    assert len(fake.calls()) == 1
