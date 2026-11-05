from __future__ import annotations

import json
import os
import time

import pytest
from conftest import unshare_works

from wacli_mcp.runner import PASSTHROUGH_ENV, RateLimiter, WacliError, WacliRunner

pytestmark = pytest.mark.anyio


async def test_argv_starts_with_read_only_prefix(fake):
    fake.respond({"ok": 1})
    runner = WacliRunner(fake.config())
    assert await runner.run(["chats", "list", "--limit=5"]) == {"ok": 1}
    (call,) = fake.calls()
    assert call["argv"][:3] == ["--read-only", "--json", "--timeout=20s"]
    assert call["argv"][3] == f"--store={fake.home}"
    assert call["argv"][4:] == ["chats", "list", "--limit=5"]


async def test_account_is_passed_when_no_store(fake):
    runner = WacliRunner(fake.config(store_dir=None, account="work"))
    await runner.run(["doctor"])
    assert "--account=work" in fake.calls()[0]["argv"]


async def test_child_env_is_minimal(fake, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "should-not-leak")
    monkeypatch.setenv("WACLI_STORE_DIR", "/somewhere/else")
    await WacliRunner(fake.config()).run(["doctor"])
    env = fake.calls()[0]["env"]
    assert env["WACLI_READONLY"] == "1"
    assert env["HOME"] == str(fake.home)
    assert "ANTHROPIC_API_KEY" not in env
    assert "WACLI_STORE_DIR" not in env
    # Beyond what the runner sets, only the documented passthrough keys (copied
    # unchanged) and the interpreter's own LC_CTYPE may appear.
    assert set(env) - {"HOME", "PATH", "LANG", "WACLI_READONLY", "LC_CTYPE", *PASSTHROUGH_ENV} == set()
    for key in PASSTHROUGH_ENV:
        assert env.get(key) == os.environ.get(key)


async def test_error_envelope_is_surfaced(fake):
    fake.scenario(
        stderr=json.dumps({"success": False, "data": None, "error": "no local exact name match"}), stdout="", rc=1
    )
    with pytest.raises(WacliError, match="no local exact name match"):
        await WacliRunner(fake.config()).run(["messages", "list"])


async def test_non_json_output_is_an_error(fake):
    fake.scenario(stdout="not json")
    with pytest.raises(WacliError, match="not a JSON envelope"):
        await WacliRunner(fake.config()).run(["doctor"])


async def test_nonzero_exit_without_envelope(fake):
    fake.scenario(stdout="", stderr="panic: boom", rc=2)
    with pytest.raises(WacliError, match="exited with status 2"):
        await WacliRunner(fake.config()).run(["doctor"])


async def test_timeout_kills_child(fake):
    fake.scenario(sleep=30)
    runner = WacliRunner(fake.config(timeout_s=1.0))
    started = time.monotonic()
    with pytest.raises(WacliError) as info:
        await runner.run(["doctor"])
    assert info.value.kind == "timeout"
    assert time.monotonic() - started < 10


async def test_output_cap(fake):
    fake.scenario(big=300_000)
    with pytest.raises(WacliError) as info:
        await WacliRunner(fake.config(max_output_bytes=64 * 1024)).run(["doctor"])
    assert info.value.kind == "output_limit"


async def test_rate_limit(fake):
    runner = WacliRunner(fake.config(rate_limit_per_minute=2))
    await runner.run(["doctor"])
    await runner.run(["doctor"])
    with pytest.raises(WacliError) as info:
        await runner.run(["doctor"])
    assert info.value.kind == "rate_limit"
    assert len(fake.calls()) == 2


def test_rate_limiter_window_slides():
    now = [0.0]
    limiter = RateLimiter(1, clock=lambda: now[0])
    limiter.check()
    with pytest.raises(WacliError):
        limiter.check()
    now[0] = 61.0
    limiter.check()


@pytest.mark.skipif(not unshare_works(), reason="unprivileged user namespaces unavailable")
async def test_network_isolation_blocks_outbound(fake):
    fake.scenario(netprobe=True)
    unsandboxed = await WacliRunner(fake.config()).run(["doctor"])
    sandboxed = await WacliRunner(fake.config(sandbox_prefix=("/usr/bin/unshare", "-rn", "--"))).run(["doctor"])
    assert sandboxed == {"net": "blocked"}
    # Shows the probe itself works; offline CI hosts report blocked for both.
    assert unsandboxed["net"] in ("reachable", "blocked")
