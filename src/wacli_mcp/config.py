"""Operator configuration.

Everything security-relevant (which binary, which stores, which chats, who can
receive messages) is fixed here at startup, from environment variables and an
optional accounts file. Nothing in this module is reachable from tool
arguments, so a model cannot redirect the server to another store or
executable. The `account` tool argument only picks one of the aliases defined
here.
"""

from __future__ import annotations

import errno
import grp
import hashlib
import ipaddress
import json
import logging
import os
import pwd
import re
import shutil
import stat
import struct
import subprocess
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

NetworkIsolation = Literal["require", "auto", "off"]

ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
JID_RE = re.compile(r"^[0-9A-Za-z._:+-]{1,64}@(s\.whatsapp\.net|g\.us|lid|newsletter|broadcast|c\.us)$")
# Group JIDs only: current groups are all digits, legacy ones are <creator>-<timestamp>.
GROUP_JID_RE = re.compile(r"(?:[0-9]{5,32}|[0-9]{5,20}-[0-9]{5,20})@g\.us")
# Sending is limited to people and groups. Channels, status and broadcast lists are excluded.
SEND_JID_RE = re.compile(r"^[0-9]{5,20}(-[0-9]{5,20})?@(s\.whatsapp\.net|g\.us|lid)$")
ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
# clientInfo.name values an operator may trust to show send approvals to a person.
CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@/:+-]{0,63}$")
# wacli's own rule for account names (internal/config/config.go).
WACLI_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_ACCOUNTS = 16
DEFAULT_ALIAS = "default"
# Settings that belong to one account. In multi-account mode they live in the
# accounts file, so setting them globally as well would be ambiguous.
PER_ACCOUNT_ENV = (
    "WACLI_MCP_STORE",
    "WACLI_MCP_ACCOUNT",
    "WACLI_MCP_ALLOWED_CHATS",
    "WACLI_MCP_DENIED_CHATS",
    "WACLI_MCP_SEND_RECIPIENTS",
    "WACLI_MCP_MEDIA_DIR",
)
SendConfirmation = Literal["elicit", "none"]

# Tailscale hands out addresses from these ranges. Binding the HTTP transport
# anywhere else (LAN, 0.0.0.0) is refused so the endpoint stays local or tailnet-only.
TAILNET_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
)

MIN_TOKEN_LENGTH = 32


class ConfigError(ValueError):
    """Raised when the operator configuration is unsafe or invalid."""


def _int(env: Mapping[str, str], key: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be an integer") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{key} must be between {lo} and {hi}")
    return value


def _float(env: Mapping[str, str], key: str, default: float, lo: float, hi: float) -> float:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a number") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{key} must be between {lo} and {hi}")
    return value


def _jids(items: list[str], key: str) -> frozenset[str]:
    for item in items:
        if not JID_RE.match(item):
            raise ConfigError(f"{key} entries must be full JIDs (for example 15551234567@s.whatsapp.net), got {item!r}")
    return frozenset(items)


def _jid_set(env: Mapping[str, str], key: str) -> frozenset[str]:
    raw = env.get(key, "")
    return _jids([item.strip() for item in raw.split(",") if item.strip()], key)


def _flag(env: Mapping[str, str], key: str) -> bool:
    raw = env.get(key, "").strip().lower()
    if raw in ("", "0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    raise ConfigError(f"{key} must be 1 or 0")


def _recipients(raw: str) -> tuple[tuple[str, str], ...]:
    items: list[tuple[str, str]] = []
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        alias, sep, jid = item.partition("=")
        if not sep:
            raise ConfigError(
                f"WACLI_MCP_SEND_RECIPIENTS entries must be alias=JID with a lowercase alias, got {item!r}"
            )
        items.append((alias.strip(), jid.strip()))
    return _recipient_pairs(items, "WACLI_MCP_SEND_RECIPIENTS")


def _recipient_pairs(items: list[tuple[str, str]], where: str) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for alias, jid in items:
        if not ALIAS_RE.match(alias):
            raise ConfigError(f"{where} entries must be alias=JID with a lowercase alias, got {alias!r}")
        if not isinstance(jid, str) or not SEND_JID_RE.match(jid):
            raise ConfigError(f"send recipient {alias!r} must be a person or group JID, got {jid!r}")
        if any(alias == a or jid == j for a, j in pairs):
            raise ConfigError(f"duplicate send recipient {alias!r} or {jid!r}")
        pairs.append((alias, jid))
    return tuple(pairs)


def _client_names(raw: str) -> frozenset[str]:
    names = frozenset(item.strip() for item in raw.split(",") if item.strip())
    for name in names:
        if not CLIENT_NAME_RE.match(name):
            raise ConfigError(f"WACLI_MCP_SEND_CONFIRM_CLIENTS entries must be MCP client names, got {name!r}")
    return names


def _chat_allowed(jid: str, allowed: frozenset[str], denied: frozenset[str]) -> bool:
    return jid not in denied and (not allowed or jid in allowed)


def _check_not_writable_by_others(path: Path, what: str) -> os.stat_result:
    st = path.stat()
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(f"{what} {path} is writable by group or others")
    if st.st_uid not in (os.getuid(), 0):
        raise ConfigError(f"{what} {path} is owned by uid {st.st_uid}, expected the current user or root")
    return st


def validate_executable(path: Path, *, sha256: str | None = None) -> Path:
    """Resolve and vet an executable the server will spawn."""
    if not path.is_absolute():
        raise ConfigError(f"executable path must be absolute: {path}")
    resolved = path.resolve(strict=False)
    if not resolved.is_file():
        raise ConfigError(f"executable not found: {path}")
    if not os.access(resolved, os.X_OK):
        raise ConfigError(f"not executable: {resolved}")
    # A writable binary or parent directory would let another local user swap
    # the program we run with the owner's WhatsApp data in reach.
    _check_not_writable_by_others(resolved, "executable")
    _check_not_writable_by_others(resolved.parent, "executable directory")
    if sha256:
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if digest.lower() != sha256.strip().lower():
            raise ConfigError(f"sha256 mismatch for {resolved}")
    return resolved


def _group_is_private(gid: int) -> bool:
    """True when `gid` is the current user's primary group and nobody else belongs to it."""
    me = pwd.getpwuid(os.getuid())
    if gid != me.pw_gid:
        return False
    try:
        members = grp.getgrgid(gid).gr_mem
    except KeyError:
        members = []
    if any(member != me.pw_name for member in members):
        return False
    return not any(user.pw_gid == gid and user.pw_uid != os.getuid() for user in pwd.getpwall())


_ACL_XATTR = "system.posix_acl_access"
_ACL_VERSION = 2
_ACL_USER, _ACL_GROUP = 0x02, 0x08
_ACL_WRITE = 0x02


def _acl_grants_others(path: Path, perms: int) -> bool:
    """True when the directory's POSIX ACL gives a named user other than us, or a named group that is not our
    private group, any of `perms`. Mode bits do not show these entries. The ACL mask is ignored, which only
    makes the check stricter. An ACL in a format this code does not know counts as granting access."""
    try:
        raw = os.getxattr(path, _ACL_XATTR, follow_symlinks=False)
    except OSError as exc:
        if exc.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
            return False
        raise
    if len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack_from("<I", raw)[0] != _ACL_VERSION:
        return True
    for tag, perm, ident in struct.iter_unpack("<HHI", raw[4:]):
        if not perm & perms:
            continue
        if tag == _ACL_USER and ident != os.getuid():
            return True
        if tag == _ACL_GROUP and not _group_is_private(ident):
            return True
    return False


def _check_ancestors(path: Path, what: str) -> None:
    """Every parent of a trusted directory must be trusted too, or its owner could be swapped after startup.

    A parent may be writable by the user's own private group (such as ~/.local, mode 775) and may be
    world-writable only with the sticky bit (such as /tmp).
    """
    try:
        for parent in path.parents:
            st = parent.stat()
            if st.st_uid not in (os.getuid(), 0):
                raise ConfigError(
                    f"{what} {path}: parent {parent} is owned by uid {st.st_uid}, expected the current user or root"
                )
            if st.st_mode & stat.S_ISVTX:
                # Sticky and owned by root or us: others can add entries but cannot rename or delete ours.
                continue
            if st.st_mode & stat.S_IWOTH:
                raise ConfigError(f"{what} {path}: parent {parent} is writable by others")
            if st.st_mode & stat.S_IWGRP and not _group_is_private(st.st_gid):
                raise ConfigError(f"{what} {path}: parent {parent} is writable by a group that has other members")
            if _acl_grants_others(parent, _ACL_WRITE):
                raise ConfigError(f"{what} {path}: parent {parent} has an access control list that lets others write")
    except OSError as exc:
        raise ConfigError(f"{what} {path}: a parent directory cannot be checked: {exc.strerror}") from exc


def _private_dir(path: Path, what: str) -> Path:
    """Vet a directory only the current user may use and return its resolved form."""
    if not path.is_absolute():
        raise ConfigError(f"{what} must be absolute")
    if not path.is_dir():
        raise ConfigError(f"{what} does not exist or is not a directory: {path}")
    resolved = path.resolve(strict=True)
    st = resolved.stat()
    if st.st_uid != os.getuid():
        raise ConfigError(f"{what} {resolved} must be owned by the current user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(
            f"{what} {resolved} is writable by group or others and "
            "must not be accessible by group or others (chmod 700)"
        )
    if st.st_mode & 0o077:
        raise ConfigError(f"{what} {resolved} must not be accessible by group or others (chmod 700)")
    try:
        shared = _acl_grants_others(resolved, 0o7)
    except OSError as exc:
        raise ConfigError(f"{what} {resolved}: its access control list cannot be read: {exc.strerror}") from exc
    if shared:
        raise ConfigError(f"{what} {resolved} has an access control list that gives others access")
    _check_ancestors(resolved, what)
    return resolved


def _media_dir(path: Path, what: str) -> Path:
    """Vet the directory media files are served from and return its resolved form."""
    if not path.is_absolute():
        raise ConfigError(f"{what} must be absolute")
    if not path.is_dir():
        raise ConfigError(f"{what} does not exist or is not a directory: {path}")
    resolved = path.resolve(strict=True)
    # Another local user who can write here could plant files for the server to hand out.
    _check_not_writable_by_others(resolved, what)
    try:
        shared = _acl_grants_others(resolved, _ACL_WRITE)
    except OSError as exc:
        raise ConfigError(f"{what} {resolved}: its access control list cannot be read: {exc.strerror}") from exc
    if shared:
        raise ConfigError(f"{what} {resolved} has an access control list that lets others write")
    _check_ancestors(resolved, what)
    return resolved


def _staging_dir(path: Path, outbox: Path, what: str) -> Path:
    """Vet the private directory approved file snapshots are written to and return its resolved form."""
    resolved = _private_dir(path, what)
    if resolved == outbox or outbox in resolved.parents or resolved in outbox.parents:
        raise ConfigError(f"{what} must not be the outbox, inside it, or contain it")
    if os.pathsep in str(resolved):
        # The path goes into WACLI_MEDIA_ROOTS, a list separated by this character.
        raise ConfigError(f"{what} must not contain {os.pathsep!r}")
    return resolved


def _overlaps(a: Path, b: Path) -> bool:
    return a == b or a in b.parents or b in a.parents


def _check_send_dirs_apart(cfg: Config) -> None:
    """The outbox and staging directory must not share space with data the server reads or writes elsewhere."""
    assert cfg.send_file_dir is not None and cfg.send_staging_dir is not None
    protected: list[tuple[str, Path]] = []
    for view in cfg.account_views():
        for what, path in (("a store directory", view.store_dir), ("a media directory", view.media_dir)):
            if path is not None:
                protected.append((what, path.resolve()))
    for what, path in (("a media directory", cfg.media_dir), ("the download directory", cfg.download_dir)):
        if path is not None:
            protected.append((what, path.resolve()))
    for name, directory in (
        ("WACLI_MCP_SEND_FILE_DIR", cfg.send_file_dir),
        ("WACLI_MCP_SEND_STAGING_DIR", cfg.send_staging_dir),
    ):
        for what, path in protected:
            if _overlaps(directory, path):
                raise ConfigError(f"{name} must not equal, contain, or be inside {what}")
        if cfg.audit_log is not None:
            log = cfg.audit_log.parent.resolve() / cfg.audit_log.name
            if directory in log.parents:
                raise ConfigError(f"{name} must not contain the audit log")


def _auto_media_dir(store_dir: Path | None) -> Path | None:
    """The store's own media directory, if it has one that passes the checks.

    Auto-detected, so a bad directory only disables media; it must not stop the text tools.
    """
    if store_dir is None:
        return None
    try:
        # Inside the try: on Python 3.12 is_dir() raises PermissionError for a store without search permission.
        if not (store_dir / "media").is_dir():
            return None
        return _media_dir(store_dir / "media", "store media directory")
    except (ConfigError, OSError, RuntimeError) as exc:
        logging.getLogger("wacli_mcp").warning("media access disabled: %s", exc)
        return None


def probe_network_isolation(unshare: Path) -> bool:
    """Return True if an unprivileged empty network namespace can be created."""
    try:
        result = subprocess.run(
            [str(unshare), "-rn", "true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            env={"PATH": "/usr/bin:/bin"},
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


@dataclass(frozen=True)
class Config:
    wacli_bin: Path
    home: Path
    store_dir: Path | None = None
    account: str | None = None
    timeout_s: float = 20.0
    max_output_bytes: int = 2 * 1024 * 1024
    max_concurrency: int = 2
    rate_limit_per_minute: int = 60
    max_text_chars: int = 4000
    allowed_chats: frozenset[str] = field(default_factory=frozenset)
    denied_chats: frozenset[str] = field(default_factory=frozenset)
    audit_log: Path | None = None
    # Command prefix that puts every wacli call in an empty network namespace.
    # Empty tuple means no isolation.
    sandbox_prefix: tuple[str, ...] = ()
    # Directory get_group_media reads already-downloaded files from; None disables it.
    media_dir: Path | None = None
    # 3 MiB keeps the base64 form below the 5 MB per-image limit of common model APIs.
    max_media_bytes: int = 3 * 1024 * 1024
    allow_media_download: bool = False
    download_dir: Path | None = None
    max_download_dir_bytes: int = 1024 * 1024 * 1024
    # Caps the size of the file a download child may write.
    prlimit_bin: Path = Path("/usr/bin/prlimit")
    # Sending (off unless WACLI_MCP_ENABLE_SEND=1 and recipients are configured).
    send_enabled: bool = False
    send_recipients: tuple[tuple[str, str], ...] = ()  # (alias, JID) pairs
    send_confirmation: SendConfirmation = "elicit"
    send_max_chars: int = 1000
    send_per_hour: int = 10
    send_timeout_s: float = 60.0
    # Recipients outside the allowlist, each send approved by the user (WACLI_MCP_SEND_ANY_RECIPIENT=1).
    send_any_recipient: bool = False
    # clientInfo names verified to show elicitation prompts to a person; unlisted sends need one of them.
    send_confirm_clients: frozenset[str] = frozenset()
    # File sending (off unless WACLI_MCP_ENABLE_SEND_FILES=1 on top of sending).
    send_files_enabled: bool = False
    send_file_dir: Path | None = None  # the outbox: the only place files can be sent from
    send_staging_dir: Path | None = None  # where the approved snapshot is written for wacli and the daemon
    send_file_max_bytes: int = 16 * 1024 * 1024
    # Multi-account mode: one view per account, each a copy of this config with
    # that account's store, chat policy and recipients. Empty in single-account mode.
    alias: str = DEFAULT_ALIAS
    label: str | None = None
    accounts: tuple[Config, ...] = ()

    @property
    def network_isolated(self) -> bool:
        return bool(self.sandbox_prefix)

    @property
    def multi_account(self) -> bool:
        return bool(self.accounts)

    def account_views(self) -> tuple[Config, ...]:
        """Every account this server serves: the configured accounts, or itself in single-account mode."""
        return self.accounts or (self,)

    def account_view(self, alias: str) -> Config:
        for view in self.account_views():
            if view.alias == alias:
                return view
        raise KeyError(alias)

    def send_recipient(self, value: str) -> tuple[str, str] | None:
        """Resolve an alias or JID to an allowlisted (alias, JID) pair."""
        for alias, jid in self.send_recipients:
            if value in (alias, jid):
                return alias, jid
        return None

    def chat_visible(self, jid: str | None) -> bool:
        if not jid:
            # Rows without a chat identity cannot be checked against an allowlist.
            return not self.allowed_chats
        if jid in self.denied_chats:
            return False
        if self.allowed_chats and jid not in self.allowed_chats:
            return False
        return True

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        env = os.environ if env is None else env
        accounts_file = env.get("WACLI_MCP_ACCOUNTS_FILE", "").strip()
        if accounts_file:
            clashing = [key for key in PER_ACCOUNT_ENV if env.get(key, "").strip()]
            if clashing:
                raise ConfigError(
                    f"WACLI_MCP_ACCOUNTS_FILE cannot be combined with {', '.join(clashing)}; "
                    "set those per account in the file"
                )

        home = Path(env.get("WACLI_MCP_HOME") or env.get("HOME") or str(Path.home()))
        if not home.is_absolute():
            raise ConfigError("HOME must be absolute")

        bin_raw = env.get("WACLI_MCP_BIN", "").strip()
        if bin_raw:
            bin_path = Path(bin_raw)
        else:
            default = home / ".local" / "bin" / "wacli"
            found = shutil.which("wacli")
            bin_path = default if default.exists() else Path(found) if found else default
        wacli_bin = validate_executable(bin_path, sha256=env.get("WACLI_MCP_BIN_SHA256") or None)

        store_raw = env.get("WACLI_MCP_STORE", "").strip()
        account_raw = env.get("WACLI_MCP_ACCOUNT", "").strip()
        if store_raw and account_raw:
            raise ConfigError("set WACLI_MCP_STORE or WACLI_MCP_ACCOUNT, not both")
        store_dir = None
        if store_raw:
            store_dir = Path(store_raw)
            if not store_dir.is_absolute():
                raise ConfigError("WACLI_MCP_STORE must be absolute")
            if not store_dir.is_dir():
                raise ConfigError(f"WACLI_MCP_STORE does not exist: {store_dir}")
        account = None
        if account_raw:
            if not ACCOUNT_RE.match(account_raw):
                raise ConfigError("WACLI_MCP_ACCOUNT has invalid characters")
            account = account_raw

        allowed = _jid_set(env, "WACLI_MCP_ALLOWED_CHATS")
        denied = _jid_set(env, "WACLI_MCP_DENIED_CHATS")
        if allowed & denied:
            raise ConfigError("a JID cannot be both allowed and denied")

        media_raw = env.get("WACLI_MCP_MEDIA_DIR", "").strip()
        media_dir = _media_dir(Path(media_raw), "WACLI_MCP_MEDIA_DIR") if media_raw else _auto_media_dir(store_dir)

        allow_raw = env.get("WACLI_MCP_ALLOW_MEDIA_DOWNLOAD", "").strip().lower()
        if allow_raw not in ("", "0", "1", "false", "true"):
            raise ConfigError("WACLI_MCP_ALLOW_MEDIA_DOWNLOAD must be 1 or 0")
        allow_media_download = allow_raw in ("1", "true")
        download_dir = None
        if allow_media_download:
            download_raw = env.get("WACLI_MCP_DOWNLOAD_DIR", "").strip()
            if not download_raw:
                raise ConfigError(
                    "WACLI_MCP_ALLOW_MEDIA_DOWNLOAD=1 requires WACLI_MCP_DOWNLOAD_DIR (a private directory)"
                )
            download_dir = _private_dir(Path(download_raw), "WACLI_MCP_DOWNLOAD_DIR")
            try:
                prlimit_bin = validate_executable(Path(env.get("WACLI_MCP_PRLIMIT", "/usr/bin/prlimit")))
            except ConfigError as exc:
                raise ConfigError(f"media download needs prlimit to cap the file size: {exc}") from exc
        else:
            prlimit_bin = Path("/usr/bin/prlimit")

        audit_raw = env.get("WACLI_MCP_AUDIT_LOG", "").strip()
        audit_log = Path(audit_raw) if audit_raw else None
        if audit_log and not audit_log.is_absolute():
            raise ConfigError("WACLI_MCP_AUDIT_LOG must be absolute")
        if audit_log and not audit_log.parent.is_dir():
            raise ConfigError(f"directory for WACLI_MCP_AUDIT_LOG does not exist: {audit_log.parent}")
        if audit_log and os.path.lexists(audit_log):
            # The 0600 mode only applies when the file is created; an existing file keeps its own.
            st = audit_log.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                raise ConfigError(
                    f"{audit_log} must be a regular file owned by the current user and not accessible "
                    "by group or others (chmod 600)"
                )

        mode = env.get("WACLI_MCP_NETWORK_ISOLATION", "require").strip().lower() or "require"
        if mode not in ("require", "auto", "off"):
            raise ConfigError("WACLI_MCP_NETWORK_ISOLATION must be require, auto, or off")
        sandbox_prefix: tuple[str, ...] = ()
        if mode != "off":
            unshare = Path(env.get("WACLI_MCP_UNSHARE", "/usr/bin/unshare"))
            usable = False
            try:
                unshare = validate_executable(unshare)
                usable = probe_network_isolation(unshare)
            except ConfigError:
                usable = False
            if usable:
                sandbox_prefix = (str(unshare), "-rn", "--")
            elif mode == "require":
                raise ConfigError(
                    "network isolation is required but `unshare -rn` is unavailable; "
                    "set WACLI_MCP_NETWORK_ISOLATION=auto or off to run without it"
                )

        send_enabled = _flag(env, "WACLI_MCP_ENABLE_SEND")
        send_recipients = _recipients(env.get("WACLI_MCP_SEND_RECIPIENTS", ""))
        confirmation = env.get("WACLI_MCP_SEND_CONFIRMATION", "elicit").strip().lower() or "elicit"
        if confirmation not in ("elicit", "none"):
            raise ConfigError("WACLI_MCP_SEND_CONFIRMATION must be elicit or none")
        any_recipient = _flag(env, "WACLI_MCP_SEND_ANY_RECIPIENT")
        confirm_clients = _client_names(env.get("WACLI_MCP_SEND_CONFIRM_CLIENTS", ""))
        if any_recipient:
            if not send_enabled:
                raise ConfigError("WACLI_MCP_SEND_ANY_RECIPIENT=1 requires WACLI_MCP_ENABLE_SEND=1")
            if confirmation != "elicit":
                # The per-send approval is the only safeguard left once the allowlist is bypassed.
                raise ConfigError("WACLI_MCP_SEND_ANY_RECIPIENT=1 requires WACLI_MCP_SEND_CONFIRMATION=elicit")
            if not confirm_clients:
                raise ConfigError(
                    "WACLI_MCP_SEND_ANY_RECIPIENT=1 requires WACLI_MCP_SEND_CONFIRM_CLIENTS "
                    "(the MCP client names verified to show approvals to a person)"
                )
        if send_enabled and not accounts_file:
            if not send_recipients and not any_recipient:
                raise ConfigError("WACLI_MCP_ENABLE_SEND=1 requires WACLI_MCP_SEND_RECIPIENTS (alias=JID pairs)")
            if store_dir is None:
                # The running sync daemon is found through its store directory.
                raise ConfigError("sending requires WACLI_MCP_STORE (the store that `wacli sync --follow` uses)")
            blocked = [jid for _, jid in send_recipients if not _chat_allowed(jid, allowed, denied)]
            if blocked:
                raise ConfigError(f"send recipients hidden by the chat policy: {', '.join(blocked)}")
        send_files = _flag(env, "WACLI_MCP_ENABLE_SEND_FILES")
        send_file_dir = send_staging_dir = None
        if send_files:
            if not send_enabled:
                raise ConfigError("WACLI_MCP_ENABLE_SEND_FILES=1 requires WACLI_MCP_ENABLE_SEND=1 and send recipients")
            outbox_raw = env.get("WACLI_MCP_SEND_FILE_DIR", "").strip()
            staging_raw = env.get("WACLI_MCP_SEND_STAGING_DIR", "").strip()
            if not outbox_raw:
                raise ConfigError("WACLI_MCP_ENABLE_SEND_FILES=1 requires WACLI_MCP_SEND_FILE_DIR (the outbox)")
            if not staging_raw:
                raise ConfigError(
                    "WACLI_MCP_ENABLE_SEND_FILES=1 requires WACLI_MCP_SEND_STAGING_DIR (a private directory)"
                )
            send_file_dir = _media_dir(Path(outbox_raw), "WACLI_MCP_SEND_FILE_DIR")
            send_staging_dir = _staging_dir(Path(staging_raw), send_file_dir, "WACLI_MCP_SEND_STAGING_DIR")

        base = cls(
            wacli_bin=wacli_bin,
            home=home,
            store_dir=store_dir,
            account=account,
            timeout_s=_float(env, "WACLI_MCP_TIMEOUT_S", 20.0, 1.0, 120.0),
            max_output_bytes=_int(env, "WACLI_MCP_MAX_OUTPUT_BYTES", 2 * 1024 * 1024, 64 * 1024, 32 * 1024 * 1024),
            max_concurrency=_int(env, "WACLI_MCP_MAX_CONCURRENCY", 2, 1, 8),
            rate_limit_per_minute=_int(env, "WACLI_MCP_RATE_LIMIT_PER_MIN", 60, 1, 600),
            max_text_chars=_int(env, "WACLI_MCP_MAX_TEXT_CHARS", 4000, 200, 100_000),
            allowed_chats=allowed,
            denied_chats=denied,
            audit_log=audit_log,
            sandbox_prefix=sandbox_prefix,
            media_dir=media_dir,
            max_media_bytes=_int(env, "WACLI_MCP_MAX_MEDIA_BYTES", 3 * 1024 * 1024, 64 * 1024, 64 * 1024 * 1024),
            allow_media_download=allow_media_download,
            download_dir=download_dir,
            prlimit_bin=prlimit_bin,
            max_download_dir_bytes=_int(
                env, "WACLI_MCP_MAX_DOWNLOAD_DIR_BYTES", 1024 * 1024 * 1024, 1024 * 1024, 100 * 1024 * 1024 * 1024
            ),
            send_enabled=send_enabled,
            send_recipients=send_recipients,
            send_confirmation=confirmation,  # type: ignore[arg-type]
            send_max_chars=_int(env, "WACLI_MCP_SEND_MAX_CHARS", 1000, 1, 4096),
            send_per_hour=_int(env, "WACLI_MCP_SEND_PER_HOUR", 10, 1, 60),
            send_timeout_s=_float(env, "WACLI_MCP_SEND_TIMEOUT_S", 60.0, 10.0, 300.0),
            send_any_recipient=any_recipient,
            send_confirm_clients=confirm_clients if any_recipient else frozenset(),
            send_files_enabled=send_files,
            send_file_dir=send_file_dir,
            send_staging_dir=send_staging_dir,
            send_file_max_bytes=_int(env, "WACLI_MCP_SEND_FILE_MAX_BYTES", 16 * 1024 * 1024, 1024, 100 * 1024 * 1024),
        )
        if not accounts_file:
            if send_files:
                _check_send_dirs_apart(base)
            return base
        views = load_accounts_file(Path(accounts_file), base, send_switch=send_enabled, env=env)
        # The top level keeps no store or policy of its own: every call goes through a view.
        cfg = replace(
            base,
            alias="",
            send_enabled=any(v.send_enabled for v in views),
            send_any_recipient=any(v.send_any_recipient for v in views),
            send_files_enabled=base.send_files_enabled and any(v.send_enabled for v in views),
            accounts=views,
        )
        if send_files:
            _check_send_dirs_apart(cfg)
        return cfg


_ACCOUNT_KEYS = frozenset({"store", "wacli_account", "label", "allowed_chats", "denied_chats", "send"})
_SEND_KEYS = frozenset({"recipients", "any_recipient"})


def _read_private_toml(path: Path) -> dict:
    if not path.is_absolute() or not path.is_file():
        raise ConfigError("WACLI_MCP_ACCOUNTS_FILE must be an absolute path to an existing file")
    st = path.stat()
    # The file decides which archives are reachable and who can receive messages.
    if st.st_mode & 0o077:
        raise ConfigError(f"{path} must not be readable or writable by group or others (chmod 600)")
    if st.st_uid != os.getuid():
        raise ConfigError(f"{path} must be owned by the current user")
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc


def _str_list(value: object, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return [v.strip() for v in value]


def resolve_wacli_account(name: str, base: Config, env: Mapping[str, str]) -> Path:
    """Ask wacli (read-only, offline) which store a named account uses.

    Done once at startup so the alias stays pinned to that directory even if
    wacli's config.yaml or default account changes while the server runs.
    """
    argv = [*base.sandbox_prefix, str(base.wacli_bin), "--read-only", "--json", "accounts", "show", name]
    child_env = {"HOME": str(base.home), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "WACLI_READONLY": "1"}
    for key in ("XDG_STATE_HOME", "XDG_CONFIG_HOME"):
        if env.get(key):
            child_env[key] = env[key]
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=base.timeout_s,
            env=child_env,
            cwd="/",
            check=False,
        )
        envelope = json.loads(result.stdout.decode("utf-8", errors="replace") or "{}")
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ConfigError(f"could not resolve wacli account {name!r}: {exc}") from exc
    if not isinstance(envelope, dict):
        # `null`, a list or a scalar: not wacli's JSON envelope (a wrapper script or the wrong binary).
        raise ConfigError(f"could not resolve wacli account {name!r}: unexpected reply from wacli")
    data = envelope.get("data")
    if result.returncode != 0 or not envelope.get("success") or not isinstance(data, dict):
        error = str(envelope.get("error") or f"wacli exited with status {result.returncode}")[:300]
        raise ConfigError(f"could not resolve wacli account {name!r}: {error}")
    store = data.get("store_dir")
    if data.get("name") != name or not isinstance(store, str) or not store:
        raise ConfigError(f"could not resolve wacli account {name!r}: unexpected reply from wacli")
    return Path(store)


def load_accounts_file(
    path: Path,
    base: Config,
    *,
    send_switch: bool,
    env: Mapping[str, str] | None = None,
    resolve: Callable[[str, Config, Mapping[str, str]], Path] = resolve_wacli_account,
) -> tuple[Config, ...]:
    """Build one isolated view of `base` per account defined in the accounts file."""
    env = os.environ if env is None else env
    doc = _read_private_toml(path)
    if set(doc) - {"accounts"}:
        raise ConfigError(f"unknown top-level keys in {path}: {', '.join(sorted(set(doc) - {'accounts'}))}")
    table = doc.get("accounts")
    if not isinstance(table, dict) or not table:
        raise ConfigError(f"{path} must define at least one [accounts.<alias>] table")
    if len(table) > MAX_ACCOUNTS:
        raise ConfigError(f"at most {MAX_ACCOUNTS} accounts are supported")

    views: list[Config] = []
    stores: dict[Path, str] = {}
    for alias, entry in table.items():
        where = f"accounts.{alias}"
        if not ALIAS_RE.match(alias):
            raise ConfigError(f"account alias {alias!r} must be lowercase letters, digits, '_' or '-' (max 32)")
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a table")
        unknown = set(entry) - _ACCOUNT_KEYS
        if unknown:
            raise ConfigError(f"unknown keys in {where}: {', '.join(sorted(unknown))}")

        if ("store" in entry) == ("wacli_account" in entry):
            raise ConfigError(f"{where} needs exactly one of store or wacli_account")
        if "store" in entry:
            if not isinstance(entry["store"], str):
                raise ConfigError(f"{where}.store must be a string")
            store_dir = Path(entry["store"])
            if not store_dir.is_absolute():
                raise ConfigError(f"{where}.store must be absolute")
        else:
            name = entry["wacli_account"]
            if not isinstance(name, str) or not WACLI_ACCOUNT_RE.match(name):
                raise ConfigError(f"{where}.wacli_account is not a valid wacli account name")
            store_dir = resolve(name, base, env)
            if not store_dir.is_absolute():
                # A relative path would be checked here against one directory and used by wacli from another.
                raise ConfigError(f"wacli returned a relative store path for account {alias!r}")
        if not store_dir.is_dir():
            raise ConfigError(f"store for account {alias!r} does not exist: {store_dir}")
        real = store_dir.resolve()
        if real in stores:
            # Two aliases on one store would make the per-account policies meaningless.
            raise ConfigError(f"accounts {stores[real]!r} and {alias!r} use the same store")
        stores[real] = alias

        label = entry.get("label")
        if label is not None and (not isinstance(label, str) or not 0 < len(label) <= 64 or not label.isprintable()):
            raise ConfigError(f"{where}.label must be printable text of at most 64 characters")

        allowed = _jids(_str_list(entry.get("allowed_chats", []), f"{where}.allowed_chats"), f"{where}.allowed_chats")
        denied = _jids(_str_list(entry.get("denied_chats", []), f"{where}.denied_chats"), f"{where}.denied_chats")
        if allowed & denied:
            raise ConfigError(f"{where}: a JID cannot be both allowed and denied")

        recipients: tuple[tuple[str, str], ...] = ()
        open_recipients = False
        send = entry.get("send")
        if send is not None:
            if not isinstance(send, dict) or set(send) - _SEND_KEYS:
                raise ConfigError(f"{where}.send only accepts a recipients table and any_recipient")
            open_recipients = send.get("any_recipient", False)
            if not isinstance(open_recipients, bool):
                raise ConfigError(f"{where}.send.any_recipient must be true or false")
            raw = send.get("recipients")
            if raw is None and open_recipients:
                raw = {}
            elif not isinstance(raw, dict) or not raw:
                raise ConfigError(f"{where}.send.recipients must be a non-empty table of alias = JID")
            recipients = _recipient_pairs(list(raw.items()), f"{where}.send.recipients")
            blocked = [jid for _, jid in recipients if not _chat_allowed(jid, allowed, denied)]
            if blocked:
                raise ConfigError(f"{where}: send recipients hidden by the chat policy: {', '.join(blocked)}")

        # Unlisted recipients need the environment switch as well as this account's own opt-in.
        unlisted = send_switch and base.send_any_recipient and open_recipients
        views.append(
            replace(
                base,
                alias=alias,
                label=label,
                store_dir=store_dir,
                account=None,
                # Each account serves only the media of its own store.
                media_dir=_auto_media_dir(store_dir),
                allowed_chats=allowed,
                denied_chats=denied,
                # Both switches are needed: the environment enables sending, the file says to whom.
                send_enabled=send_switch and (bool(recipients) or unlisted),
                send_recipients=recipients if send_switch else (),
                send_any_recipient=unlisted,
                send_files_enabled=base.send_files_enabled and send_switch and (bool(recipients) or unlisted),
                accounts=(),
            )
        )
    if send_switch and not any(v.send_enabled for v in views):
        raise ConfigError("WACLI_MCP_ENABLE_SEND=1 requires send recipients for at least one account")
    if base.send_any_recipient and not any(v.send_any_recipient for v in views):
        raise ConfigError("WACLI_MCP_SEND_ANY_RECIPIENT=1 requires send.any_recipient = true for at least one account")
    return tuple(views)


@dataclass(frozen=True)
class HttpConfig:
    host: str
    port: int
    token: str
    allowed_hostnames: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> HttpConfig:
        env = os.environ if env is None else env
        host = env.get("WACLI_MCP_HTTP_HOST", "127.0.0.1").strip()
        try:
            addr = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ConfigError("WACLI_MCP_HTTP_HOST must be an IP address (loopback or Tailscale)") from exc
        if not (addr.is_loopback or any(addr in net for net in TAILNET_NETWORKS)):
            raise ConfigError(
                f"refusing to bind {host}: only loopback or Tailscale addresses "
                "(100.64.0.0/10, fd7a:115c:a1e0::/48) are allowed"
            )
        port = _int(env, "WACLI_MCP_HTTP_PORT", 8765, 1024, 65535)

        token_file = env.get("WACLI_MCP_TOKEN_FILE", "").strip()
        if not token_file:
            raise ConfigError("HTTP transport requires WACLI_MCP_TOKEN_FILE (a mode 600 file holding a bearer token)")
        path = Path(token_file)
        if not path.is_absolute() or not path.is_file():
            raise ConfigError("WACLI_MCP_TOKEN_FILE must be an absolute path to an existing file")
        st = path.stat()
        if st.st_mode & 0o077:
            raise ConfigError(f"{path} must not be readable or writable by group or others (chmod 600)")
        if st.st_uid != os.getuid():
            raise ConfigError(f"{path} must be owned by the current user")
        token = path.read_text(encoding="utf-8").strip()
        if len(token) < MIN_TOKEN_LENGTH:
            raise ConfigError(f"bearer token must be at least {MIN_TOKEN_LENGTH} characters")

        hostnames = tuple(h.strip() for h in env.get("WACLI_MCP_ALLOWED_HOSTNAMES", "").split(",") if h.strip())
        for name in hostnames:
            if not re.match(r"^[A-Za-z0-9.-]{1,253}$", name):
                raise ConfigError(f"invalid hostname in WACLI_MCP_ALLOWED_HOSTNAMES: {name!r}")
        return cls(host=host, port=port, token=token, allowed_hostnames=hostnames)
