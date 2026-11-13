"""Spawns wacli with a fixed, read-only argument prefix and bounded resources."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .config import Config
from .shaping import sanitize_text

MAX_STDERR_BYTES = 64 * 1024
MAX_ERROR_CHARS = 300

# Environment variables passed to wacli. Everything else (API keys, tokens,
# WACLI_STORE_DIR overrides) is dropped so the child sees only what it needs.
PASSTHROUGH_ENV = ("XDG_STATE_HOME", "XDG_CONFIG_HOME", "TZ")
# Extra variables a write call may set. WACLI_MEDIA_ROOTS confines `send file --file` to a directory.
WRITE_EXTRA_ENV = frozenset({"WACLI_MEDIA_ROOTS"})


class WacliError(Exception):
    """A failure whose message is safe to show to the model."""

    def __init__(self, message: str, kind: str = "wacli_error") -> None:
        super().__init__(message)
        self.kind = kind


class RateLimiter:
    """Sliding window. Bounds how fast a misbehaving agent can page through the archive or send."""

    def __init__(self, limit: int, window_s: float = 60.0, clock=time.monotonic) -> None:
        self._limit = limit
        self._window_s = window_s
        self._clock = clock
        self._calls: deque[float] = deque()

    def _expire(self) -> float:
        now = self._clock()
        while self._calls and now - self._calls[0] >= self._window_s:
            self._calls.popleft()
        return now

    def would_allow(self) -> bool:
        self._expire()
        return len(self._calls) < self._limit

    def check(self) -> None:
        now = self._expire()
        if len(self._calls) >= self._limit:
            raise WacliError("rate limit exceeded; wait before calling again", kind="rate_limit")
        self._calls.append(now)


class WacliRunner:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._sem = asyncio.Semaphore(cfg.max_concurrency)
        self._limiter = RateLimiter(cfg.rate_limit_per_minute)
        # One send at a time, so confirmations and outcomes map one to one.
        self._write_lock = asyncio.Lock()

    def build_argv(
        self,
        args: Sequence[str],
        *,
        write: bool = False,
        network: bool = False,
        max_file_bytes: int | None = None,
        target: Config | None = None,
    ) -> list[str]:
        """Build the argv for one call. `target` is the account view to run against (default: the server's)."""
        cfg = self.cfg
        selector = target or cfg
        # Media download is the only command allowed out of the empty network
        # namespace: in --read-only mode wacli fetches the encrypted file from the
        # WhatsApp CDN without opening a session.
        if network and (write or tuple(args[:2]) != ("media", "download")):
            raise WacliError("network access is only allowed for media download", kind="policy")
        if network and max_file_bytes is None:
            raise WacliError("a network download needs a file size limit", kind="policy")
        if network:
            # prlimit sets RLIMIT_FSIZE in the child only. Setting it from Python
            # (preexec_fn) is unsafe in a threaded server and would also bind this process.
            prefix: tuple[str, ...] = (str(cfg.prlimit_bin), f"--fsize={max_file_bytes}:{max_file_bytes}", "--")
        else:
            prefix = cfg.sandbox_prefix
        argv = [*prefix, str(cfg.wacli_bin)]
        if write:
            argv += ["--json", f"--timeout={int(cfg.send_timeout_s)}s"]
        else:
            argv += ["--read-only", "--json", f"--timeout={int(cfg.timeout_s)}s"]
        if selector.store_dir is not None:
            argv.append(f"--store={selector.store_dir}")
        elif selector.account is not None:
            argv.append(f"--account={selector.account}")
        elif cfg.multi_account:
            # Never fall back to wacli's default store when several accounts are configured.
            raise WacliError("no store selected for this call", kind="config")
        argv.extend(args)
        return argv

    def build_env(self, *, write: bool = False, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        env = {
            "HOME": str(self.cfg.home),
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
        }
        if not write:
            # Belt and braces: wacli also refuses writes when this is set.
            env["WACLI_READONLY"] = "1"
        for key in PASSTHROUGH_ENV:
            if key in os.environ:
                env[key] = os.environ[key]
        if extra:
            if not write or not set(extra) <= WRITE_EXTRA_ENV:
                raise WacliError("this environment variable cannot be set for this call", kind="policy")
            env.update(extra)
        return env

    async def run(
        self,
        args: Sequence[str],
        *,
        network: bool = False,
        max_file_bytes: int | None = None,
        target: Config | None = None,
    ) -> Any:
        """Run one wacli read command and return the `data` field of its JSON envelope.

        max_file_bytes sets RLIMIT_FSIZE on the child (through prlimit), so a download
        larger than the limit is stopped while it is written instead of filling the disk.
        """
        argv = self.build_argv(args, network=network, max_file_bytes=max_file_bytes, target=target)
        self._limiter.check()
        async with self._sem:
            stdout, stderr, returncode = await self._spawn(argv, self.build_env(), self.cfg.timeout_s)
        return self._parse(stdout, stderr, returncode)

    async def run_write(
        self, args: Sequence[str], target: Config | None = None, *, extra_env: Mapping[str, str] | None = None
    ) -> Any:
        """Run one wacli write command. Callers own authorization, confirmation and rate limits.

        Never retried: a send that timed out may still have been delivered.
        """
        async with self._write_lock:
            stdout, stderr, returncode = await self._spawn(
                self.build_argv(args, write=True, target=target),
                self.build_env(write=True, extra=extra_env),
                self.cfg.send_timeout_s,
            )
        return self._parse(stdout, stderr, returncode)

    async def _spawn(self, argv: list[str], env: dict[str, str], timeout_s: float) -> tuple[bytes, bytes, int]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd="/",
                # Own process group, so a timeout can kill wacli together with the unshare wrapper.
                start_new_session=True,
            )
        except OSError as exc:
            # The binary was vetted at startup; it may have been removed or replaced since.
            raise WacliError("could not start wacli", kind="spawn_error") from exc
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
            async with asyncio.timeout(timeout_s + 2.0):
                stdout, stderr = await readers
                returncode = await proc.wait()
        except TimeoutError as exc:
            raise WacliError(f"wacli did not finish within {timeout_s:g}s", kind="timeout") from exc
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
