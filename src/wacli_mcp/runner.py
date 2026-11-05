"""Spawns wacli with a fixed, read-only argument prefix and bounded resources."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from collections import deque
from collections.abc import Callable, Sequence
from typing import Any

from .config import Config
from .shaping import sanitize_text

MAX_STDERR_BYTES = 64 * 1024
MAX_ERROR_CHARS = 300

# Environment variables passed to wacli. Everything else (API keys, tokens,
# WACLI_STORE_DIR overrides) is dropped so the child sees only what it needs.
PASSTHROUGH_ENV = ("XDG_STATE_HOME", "XDG_CONFIG_HOME", "TZ")


class WacliError(Exception):
    """A failure whose message is safe to show to the model."""

    def __init__(self, message: str, kind: str = "wacli_error") -> None:
        super().__init__(message)
        self.kind = kind


class RateLimiter:
    """Sliding one-minute window. Bounds how fast a misbehaving agent can page through the archive."""

    def __init__(self, per_minute: int, clock=time.monotonic) -> None:
        self._per_minute = per_minute
        self._clock = clock
        self._calls: deque[float] = deque()

    def check(self) -> None:
        now = self._clock()
        while self._calls and now - self._calls[0] >= 60.0:
            self._calls.popleft()
        if len(self._calls) >= self._per_minute:
            raise WacliError("rate limit exceeded; wait before calling again", kind="rate_limit")
        self._calls.append(now)


class WacliRunner:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._sem = asyncio.Semaphore(cfg.max_concurrency)
        self._limiter = RateLimiter(cfg.rate_limit_per_minute)

    def build_argv(self, args: Sequence[str]) -> list[str]:
        cfg = self.cfg
        argv = [*cfg.sandbox_prefix, str(cfg.wacli_bin), "--read-only", "--json", f"--timeout={int(cfg.timeout_s)}s"]
        if cfg.store_dir is not None:
            argv.append(f"--store={cfg.store_dir}")
        elif cfg.account is not None:
            argv.append(f"--account={cfg.account}")
        argv.extend(args)
        return argv

    def build_env(self) -> dict[str, str]:
        env = {
            "HOME": str(self.cfg.home),
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            # Belt and braces: wacli also refuses writes when this is set.
            "WACLI_READONLY": "1",
        }
        for key in PASSTHROUGH_ENV:
            if key in os.environ:
                env[key] = os.environ[key]
        return env

    async def run(self, args: Sequence[str]) -> Any:
        """Run one wacli read command and return the `data` field of its JSON envelope."""
        self._limiter.check()
        async with self._sem:
            stdout, stderr, returncode = await self._spawn(self.build_argv(args))
        return self._parse(stdout, stderr, returncode)

    async def _spawn(self, argv: list[str]) -> tuple[bytes, bytes, int]:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.build_env(),
            cwd="/",
            # Own process group, so a timeout can kill wacli together with the unshare wrapper.
            start_new_session=True,
        )
        assert proc.stdout is not None and proc.stderr is not None
        overflow = asyncio.Event()

        def on_overflow() -> None:
            overflow.set()
            _kill_group(proc.pid)

        readers = asyncio.gather(
            _read_capped(proc.stdout, self.cfg.max_output_bytes, on_overflow),
            _read_capped(proc.stderr, MAX_STDERR_BYTES),
        )
        try:
            async with asyncio.timeout(self.cfg.timeout_s + 2.0):
                stdout, stderr = await readers
                returncode = await proc.wait()
        except TimeoutError as exc:
            raise WacliError(f"wacli did not finish within {self.cfg.timeout_s:g}s", kind="timeout") from exc
        finally:
            if proc.returncode is None:
                _kill_group(proc.pid)
            # asyncio only reports exit once both pipes reach EOF, and a paused,
            # unread pipe never does. Drain whatever is left after the kill.
            readers.cancel()
            await _drain(proc.stdout)
            await _drain(proc.stderr)
            await proc.wait()
        if overflow.is_set():
            raise WacliError(
                f"wacli output exceeded {self.cfg.max_output_bytes} bytes; request fewer results",
                kind="output_limit",
            )
        return stdout, stderr, returncode

    def _parse(self, stdout: bytes, stderr: bytes, returncode: int) -> Any:
        envelope = _decode_envelope(stdout) or _decode_envelope(stderr)
        if returncode == 0 and envelope is not None and envelope.get("success") is True:
            return envelope.get("data")
        if envelope is not None and envelope.get("error"):
            message = str(envelope["error"])
        elif returncode == 0:
            message = "wacli returned output that is not a JSON envelope"
        else:
            message = f"wacli exited with status {returncode}"
        raise WacliError(sanitize_text(message, MAX_ERROR_CHARS))


async def _read_capped(stream: asyncio.StreamReader, cap: int, on_overflow: Callable[[], None] | None = None) -> bytes:
    """Read to EOF, keeping at most `cap` bytes. Reading continues past the cap so the child never blocks."""
    buf = bytearray()
    total = 0
    while chunk := await stream.read(64 * 1024):
        total += len(chunk)
        if len(buf) < cap:
            buf.extend(chunk[: cap - len(buf)])
        if total > cap and on_overflow is not None:
            on_overflow()
            on_overflow = None
    return bytes(buf)


async def _drain(stream: asyncio.StreamReader) -> None:
    try:
        async with asyncio.timeout(5.0):
            while await stream.read(64 * 1024):
                pass
    except TimeoutError:
        pass


def _decode_envelope(raw: bytes) -> dict[str, Any] | None:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    candidates = [text] + [line for line in reversed(text.splitlines()) if line.startswith("{")]
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "success" in value:
            return value
    return None


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
