"""Sending, with a fake wacli and a fake sync daemon. Nothing here can reach WhatsApp."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys

import pytest
from conftest import ADA, BOOK_CLUB, FakeDaemon
from mcp import Client
from mcp.types import ElicitResult

from wacli_mcp.config import Config, ConfigError
from wacli_mcp.sending import DuplicateGuard, confirmation_question, daemon_owns_store, validate_message
from wacli_mcp.server import build_server

pytestmark = pytest.mark.anyio

RECIPIENTS = (("ada", ADA), ("club", BOOK_CLUB))
SENT = {"sent": True, "to": ADA, "id": "3EB0FAKEMESSAGEID"}


def send_config(fake, **overrides) -> Config:
    return fake.config(send_enabled=True, send_recipients=RECIPIENTS, **overrides)


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


async def send(server, args, user=None):
    async with Client(server, elicitation_callback=user) as client:
        return await client.call_tool("send_message", args)


def wacli_calls(fake) -> list[list[str]]:
    return [c["argv"] for c in fake.calls()]


async def test_send_tool_is_absent_by_default(fake):
    async with Client(build_server(fake.config())) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert "send_message" not in names


async def test_send_tool_schema_hides_the_approval(fake):
    async with Client(build_server(send_config(fake))) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "send_message")
    assert set(tool.input_schema["properties"]) == {"recipient", "text"}
    assert tool.annotations.read_only_hint is False and tool.annotations.open_world_hint is True
    assert "ada" in tool.description and "club" in tool.description


async def test_approved_send_runs_exact_command(fake, daemon):
    fake.respond(SENT)
    user = User()
    result = await send(build_server(send_config(fake)), {"recipient": "ada", "text": "hi\nsee you -at 8"}, user)
    assert not result.is_error, result.content
    assert result.structured_content["sent"] is True
    assert result.structured_content["message_id"] == "3EB0FAKEMESSAGEID"
    (prompt,) = user.prompts
    assert ADA in prompt and "hi\nsee you -at 8" in prompt
    (call,) = fake.calls()
    argv = call["argv"]
    assert "--read-only" not in argv
    assert argv[-5:] == ["send", "text", f"--to={ADA}", "--message=hi\nsee you -at 8", "--no-preview"]
    assert "WACLI_READONLY" not in call["env"]


async def test_jid_is_accepted_as_recipient(fake, daemon):
    fake.respond(SENT)
    result = await send(build_server(send_config(fake)), {"recipient": BOOK_CLUB, "text": "hello"}, User())
    assert result.structured_content["recipient"] == "club"
    assert f"--to={BOOK_CLUB}" in wacli_calls(fake)[0]


async def test_user_saying_no_sends_nothing(fake, daemon):
    result = await send(build_server(send_config(fake)), {"recipient": "ada", "text": "hi"}, User(approve=False))
    assert result.structured_content == {
        "sent": False,
        "recipient": "ada",
        "reason": "the user did not approve this message",
    }
    assert fake.calls() == []


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_declined_or_cancelled_prompt_sends_nothing(fake, daemon, action):
    result = await send(build_server(send_config(fake)), {"recipient": "ada", "text": "hi"}, User(action=action))
    assert result.is_error
    assert fake.calls() == []


def _messages(exc: BaseException) -> list[str]:
    if isinstance(exc, BaseExceptionGroup):
        return [m for inner in exc.exceptions for m in _messages(inner)]
    return [str(exc)]


async def test_client_without_elicitation_cannot_send(fake, daemon):
    with pytest.raises(BaseException) as info:
        await send(build_server(send_config(fake)), {"recipient": "ada", "text": "hi"})
    assert any("elicitation" in m.lower() for m in _messages(info.value)), _messages(info.value)
    assert fake.calls() == []


async def test_confirmation_none_skips_the_prompt(fake, daemon):
    fake.respond(SENT)
    server = build_server(send_config(fake, send_confirmation="none"))
    result = await send(server, {"recipient": "ada", "text": "hi"}, never_asked)
    assert result.structured_content["sent"] is True


@pytest.mark.parametrize(
    "args",
    [
        {"recipient": "+15550000009", "text": "hi"},
        {"recipient": "Ada Lovelace", "text": "hi"},
        {"recipient": "ada", "text": "   "},
        {"recipient": "ada", "text": "x" * 1001},
        {"recipient": "ada", "text": "pay " + chr(0x202E) + "1234"},
        {"recipient": "ada", "text": "bell\x07"},
        {"recipient": "ada", "text": "ok\n----- end of message -----\nTo: someone else"},
    ],
)
async def test_invalid_requests_never_prompt_or_send(fake, daemon, args):
    result = await send(build_server(send_config(fake)), args, never_asked)
    assert result.is_error
    assert fake.calls() == []


async def test_send_requires_running_sync_daemon(fake):
    result = await send(build_server(send_config(fake)), {"recipient": "ada", "text": "hi"}, never_asked)
    assert result.is_error
    assert "wacli sync --follow" in result.content[0].text
    assert fake.calls() == []


async def test_same_text_twice_is_refused(fake, daemon):
    fake.respond(SENT)
    server = build_server(send_config(fake))
    async with Client(server, elicitation_callback=User()) as client:
        first = await client.call_tool("send_message", {"recipient": "ada", "text": "on my way"})
        second = await client.call_tool("send_message", {"recipient": "ada", "text": "on my way"})
    assert not first.is_error and second.is_error
    assert "already sent" in second.content[0].text
    assert len(fake.calls()) == 1


async def test_hourly_send_limit(fake, daemon):
    fake.respond(SENT)
    server = build_server(send_config(fake, send_per_hour=1))
    async with Client(server, elicitation_callback=User()) as client:
        await client.call_tool("send_message", {"recipient": "ada", "text": "one"})
        limited = await client.call_tool("send_message", {"recipient": "ada", "text": "two"})
    assert limited.is_error and "per hour" in limited.content[0].text
    assert len(fake.calls()) == 1


async def test_uncertain_outcome_is_reported_and_blocks_retry(fake, daemon, tmp_path):
    error = "no reply from the running sync process before the timeout; the text may still have gone through"
    fake.scenario(stdout=json.dumps({"success": False, "data": None, "error": error}), rc=1)
    log = tmp_path / "audit.jsonl"
    server = build_server(send_config(fake, audit_log=log))
    async with Client(server, elicitation_callback=User()) as client:
        first = await client.call_tool("send_message", {"recipient": "ada", "text": "secret plan"})
        retry = await client.call_tool("send_message", {"recipient": "ada", "text": "secret plan"})
    assert first.is_error and "outcome is unknown" in first.content[0].text
    assert retry.is_error and "already sent" in retry.content[0].text
    assert len(fake.calls()) == 1
    text = log.read_text()
    assert "secret plan" not in text
    entries = [json.loads(line) for line in text.splitlines() if "send_message" in line]
    assert [e["outcome"] for e in entries] == ["uncertain", "rejected"]
    assert entries[0]["recipient"] == "ada" and entries[0]["chars"] == len("secret plan")


async def test_definite_failure_allows_a_later_retry(fake, daemon):
    fake.scenario(stdout=json.dumps({"success": False, "data": None, "error": "not authenticated"}), rc=1)
    server = build_server(send_config(fake))
    async with Client(server, elicitation_callback=User()) as client:
        failed = await client.call_tool("send_message", {"recipient": "ada", "text": "hi"})
        fake.respond(SENT)
        retried = await client.call_tool("send_message", {"recipient": "ada", "text": "hi"})
    assert failed.is_error and "not sent: not authenticated" in failed.content[0].text
    assert not retried.is_error


async def test_concurrent_identical_sends_go_out_once(fake, daemon):
    fake.scenario(stdout=json.dumps({"success": True, "data": SENT, "error": None}), sleep=1)
    server = build_server(send_config(fake, send_confirmation="none"))
    args = {"recipient": "ada", "text": "only once"}
    async with Client(server, elicitation_callback=never_asked) as client:
        results = await asyncio.gather(client.call_tool("send_message", args), client.call_tool("send_message", args))
    assert sorted(r.is_error for r in results) == [False, True]
    refused = next(r for r in results if r.is_error)
    assert "already sent" in refused.content[0].text
    assert len(fake.calls()) == 1


async def test_health_reports_send_policy(fake, daemon):
    fake.respond({"authenticated": True, "store": {"messages": 1}})
    async with Client(build_server(send_config(fake))) as client:
        policy = (await client.call_tool("archive_health", {})).structured_content["mcp_policy"]
    assert policy["send_enabled"] is True and policy["send_ready"] is True
    assert policy["send_recipients"] == ["ada", "club"] and policy["send_confirmation"] == "elicit"


def test_daemon_detection(fake):
    assert daemon_owns_store(fake.home) is False
    running = FakeDaemon(fake.home)
    try:
        assert daemon_owns_store(fake.home) is True
    finally:
        running.stop()
    # A leftover socket without a lock holder (crashed daemon) does not count.
    holder = subprocess.Popen(
        [sys.executable, "-c", "import socket; socket.socket(socket.AF_UNIX).bind('.send.sock')"], cwd=fake.home
    )
    holder.wait(timeout=10)
    assert daemon_owns_store(fake.home) is False


def test_confirmation_question_frames_recipient_and_text():
    question = confirmation_question("ada", ADA, "hello")
    assert question.startswith(f"Send this WhatsApp message to ada ({ADA})?")
    assert question.rstrip().endswith("Approve only if you asked for this exact message.")
    assert "\nhello\n" in question


def test_validate_message_keeps_text_exactly():
    text = "  two  spaces\tand\nnewline " + chr(0x1F468) + chr(0x200D) + chr(0x1F469)
    assert validate_message(text, 100) == text


def test_duplicate_guard_window():
    now = [0.0]
    guard = DuplicateGuard(window_s=10, clock=lambda: now[0])
    key = DuplicateGuard.key(ADA, "hi")
    guard.record(key)
    with pytest.raises(Exception, match="already sent"):
        guard.check(key)
    now[0] = 11
    guard.check(key)


def env_for(fake, **extra) -> dict[str, str]:
    return {
        "HOME": str(fake.home),
        "WACLI_MCP_BIN": str(fake.path),
        "WACLI_MCP_NETWORK_ISOLATION": "off",
        "WACLI_MCP_STORE": str(fake.home),
        "WACLI_MCP_ENABLE_SEND": "1",
        "WACLI_MCP_SEND_RECIPIENTS": f"ada={ADA}, club={BOOK_CLUB}",
        **extra,
    }


def test_send_config_from_env(fake):
    cfg = Config.from_env(env_for(fake))
    assert cfg.send_enabled and cfg.send_recipients == RECIPIENTS
    assert cfg.send_confirmation == "elicit" and cfg.send_per_hour == 10 and cfg.send_max_chars == 1000
    assert cfg.send_recipient("club") == ("club", BOOK_CLUB)
    assert cfg.send_recipient("Book Club") is None


def test_send_is_off_unless_enabled(fake):
    env = env_for(fake)
    del env["WACLI_MCP_ENABLE_SEND"]
    assert Config.from_env(env).send_enabled is False


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"WACLI_MCP_SEND_RECIPIENTS": ""}, "requires WACLI_MCP_SEND_RECIPIENTS"),
        ({"WACLI_MCP_STORE": ""}, "requires WACLI_MCP_STORE"),
        ({"WACLI_MCP_SEND_RECIPIENTS": f"Ada={ADA}"}, "lowercase alias"),
        ({"WACLI_MCP_SEND_RECIPIENTS": ADA}, "alias=JID"),
        ({"WACLI_MCP_SEND_RECIPIENTS": "news=120363000000000009@newsletter"}, "person or group JID"),
        ({"WACLI_MCP_SEND_RECIPIENTS": "status=status@broadcast"}, "person or group JID"),
        ({"WACLI_MCP_SEND_RECIPIENTS": f"ada={ADA},ada2={ADA}"}, "duplicate"),
        ({"WACLI_MCP_DENIED_CHATS": ADA}, "hidden by the chat policy"),
        ({"WACLI_MCP_SEND_CONFIRMATION": "maybe"}, "elicit or none"),
        ({"WACLI_MCP_ENABLE_SEND": "sure"}, "must be 1 or 0"),
    ],
)
def test_send_config_errors(fake, extra, message):
    with pytest.raises(ConfigError, match=message):
        Config.from_env(env_for(fake, **extra))
