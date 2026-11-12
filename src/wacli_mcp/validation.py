"""Validation for model-supplied tool arguments.

Values are passed to wacli as single `--flag=value` tokens and free text goes
after `--`, so even a value starting with a dash cannot become a new flag. The
checks here exist to give the model clear errors and to keep inputs bounded.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import date, datetime

from mcp.server.mcpserver.exceptions import ToolError

from .config import GROUP_JID_RE, JID_RE, Config
from .media import MESSAGE_ID_RE

PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()-]{4,24}$")
CURSOR_RE = re.compile(r"^[A-Za-z0-9_+/=-]{1,2048}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

MAX_QUERY_CHARS = 200
MAX_NAME_CHARS = 100
_ZWJ = chr(0x200D)  # zero-width joiner, needed by emoji sequences


def _no_controls(value: str, what: str) -> None:
    for ch in value:
        # ZWJ is allowed to match shaping.sanitize_text, which keeps it in names the model may pass back.
        if ch != _ZWJ and unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co"):
            raise ToolError(f"{what} contains control or invisible characters")


def query_text(value: str, what: str = "query") -> str:
    value = value.strip()
    if not value:
        raise ToolError(f"{what} must not be empty")
    if len(value) > MAX_QUERY_CHARS:
        raise ToolError(f"{what} must be at most {MAX_QUERY_CHARS} characters")
    _no_controls(value, what)
    return value


def chat_ref(value: str, what: str = "chat") -> str:
    """A JID, phone number, or exact local chat/contact name."""
    value = value.strip()
    if not value:
        raise ToolError(f"{what} must not be empty")
    if JID_RE.match(value) or PHONE_RE.match(value):
        return value
    if len(value) > MAX_NAME_CHARS:
        raise ToolError(f"{what} must be a JID, a phone number, or a name of at most {MAX_NAME_CHARS} characters")
    _no_controls(value, what)
    return value


def chat_allowed_by_policy(value: str, cfg: Config) -> None:
    """Reject explicit chat filters that the operator policy hides.

    Names and phone numbers are resolved by wacli, so with an allowlist only
    exact JIDs can be checked up front. Results are filtered afterwards anyway.
    """
    if JID_RE.match(value):
        if not cfg.chat_visible(value):
            raise ToolError("this chat is not available through this server")
    elif cfg.allowed_chats:
        raise ToolError("a chat allowlist is active: pass the chat as an exact JID (see list_chats)")


def time_bound(value: str, what: str) -> str:
    value = value.strip()
    try:
        if DATE_RE.match(value):
            date.fromisoformat(value)
        else:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
    except ValueError as exc:
        raise ToolError(f"{what} must be YYYY-MM-DD or an RFC3339 timestamp with a timezone") from exc
    return value


def media_group(value: str, cfg: Config) -> str:
    """An exact group JID that the operator's chat policy allows.

    Names and phone numbers are refused: wacli could resolve them to a direct chat.
    """
    value = value.strip()
    if not GROUP_JID_RE.fullmatch(value):
        raise ToolError("media is only served from group chats: pass the group's exact JID ending in @g.us")
    if not cfg.chat_visible(value):
        raise ToolError("this chat is not available through this server")
    return value


def message_id(value: str) -> str:
    value = value.strip()
    if not MESSAGE_ID_RE.fullmatch(value):
        raise ToolError("message_id must be the msg_id of a message returned by list_messages or search_messages")
    return value


def cursor(value: str) -> str:
    value = value.strip()
    if not CURSOR_RE.match(value):
        raise ToolError("cursor must be the opaque next_cursor value returned by a previous call")
    return value
