"""send_file, with a fake wacli and a fake sync daemon. Nothing here can reach WhatsApp."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import struct
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import ADA, BOOK_CLUB, SYNTHETIC_JPEG, SYNTHETIC_MP4, FakeDaemon
from mcp import Client
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ElicitResult

from wacli_mcp import outbox
from wacli_mcp.config import Config
from wacli_mcp.runner import WacliError, WacliRunner
from wacli_mcp.server import build_server

pytestmark = pytest.mark.anyio

RECIPIENTS = (("ada", ADA), ("club", BOOK_CLUB))
SENT = {"sent": True, "to": ADA, "id": "3EB0FAKEMESSAGEID"}
MIB = 1024 * 1024

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
PDF = b"%PDF-1.4\n" + b"synthetic pdf body\n" * 4
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 30
MP3 = b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\x00" * 40
MP3_FRAME = b"\xff\xfb\x90\x00" + b"\x00" * 40
OGG = b"OggS\x00\x02" + b"\x00" * 40


def box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def iso(brand: bytes, handlers: list[bytes], moov: bool = True) -> bytes:
    """A minimal ISO BMFF file: ftyp, then a moov with one trak per handler type, then mdat."""
    ftyp = box(b"ftyp", brand + b"\x00\x00\x00\x00" + brand + b"isom")
    traks = b"".join(
        box(b"trak", box(b"mdia", box(b"hdlr", b"\x00" * 8 + handler + b"\x00" * 12 + b"\x00"))) for handler in handlers
    )
    return ftyp + (box(b"moov", traks) if moov else b"") + box(b"mdat", b"\x00" * 32)


M4A = iso(b"M4A ", [b"soun"])
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 40


def ooxml(member: str, content_types: bool = True, extra: int = 0) -> bytes:
    """A minimal zip shaped like an Office document: [Content_Types].xml plus one member."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if content_types:
            zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr(member, "<xml/>")
        for i in range(extra):
            zf.writestr(f"word/n{i}", "")
    return buf.getvalue()


@pytest.fixture
def dirs(tmp_path) -> tuple[Path, Path]:
    outbox = tmp_path / "outbox"
    staging = tmp_path / "staging"
    for path in (outbox, staging):
        path.mkdir()
        path.chmod(0o700)
    return outbox.resolve(), staging.resolve()


def file_config(fake, dirs, **overrides) -> Config:
    outbox, staging = dirs
    return fake.config(
        send_enabled=True,
        send_recipients=RECIPIENTS,
        send_files_enabled=True,
        send_file_dir=outbox,
        send_staging_dir=staging,
        **overrides,
    )


class User:
    """Scripted answers to elicitation prompts. `before_answer` runs while the prompt is on screen."""

    def __init__(self, action: str = "accept", approve: bool = True, before_answer=None) -> None:
        self.action = action
        self.approve = approve
        self.before_answer = before_answer
        self.prompts: list[str] = []

    async def __call__(self, context, params):
        self.prompts.append(params.message)
        if self.before_answer is not None:
            self.before_answer()
        if self.action != "accept":
            return ElicitResult(action=self.action)
        return ElicitResult(action="accept", content={"approve": self.approve})


def never_asked(*_):
    raise AssertionError("the user must not be prompted")


async def send_file(server, args, user=None, **client_options):
    async with Client(server, elicitation_callback=user, **client_options) as client:
        return await client.call_tool("send_file", args)


def write(outbox: Path, name: str, data: bytes) -> Path:
    path = outbox / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def staged_leftovers(staging: Path) -> list[str]:
    return sorted(p.name for p in staging.iterdir())


def text_of(result) -> str:
    return result.content[0].text


# Registration


async def test_tool_is_absent_by_default_and_with_text_sending_only(fake, dirs):
    plain = fake.config()
    text_only = fake.config(send_enabled=True, send_recipients=RECIPIENTS)
    for cfg in (plain, text_only):
        async with Client(build_server(cfg)) as client:
            names = {t.name for t in (await client.list_tools()).tools}
        assert "send_file" not in names
    assert "send_message" in names


async def test_tool_is_registered_next_to_send_message(fake, dirs):
    async with Client(build_server(file_config(fake, dirs))) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert {"send_message", "send_file"} <= set(tools)
    tool = tools["send_file"]
    assert set(tool.input_schema["properties"]) == {"recipient", "file", "caption"}
    assert set(tool.input_schema["required"]) == {"recipient", "file"}
    assert tool.annotations.read_only_hint is False and tool.annotations.open_world_hint is True
    assert tool.annotations.idempotent_hint is False
    assert "ada" in tool.description and "club" in tool.description
    assert "explicitly asked" in tool.description and "outbox" in tool.description
    assert "16 MiB" in tool.description and "PDF" in tool.description
    assert "confirm" in tool.description


async def test_description_omits_confirmation_when_it_is_off(fake, dirs):
    cfg = file_config(fake, dirs, send_confirmation="none", send_file_max_bytes=2048)
    async with Client(build_server(cfg)) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "send_file")
    assert "confirm" not in tool.description and "2048 bytes" in tool.description


def test_instructions_mention_send_file_only_when_enabled(fake, dirs):
    enabled = build_server(file_config(fake, dirs)).instructions
    text_only = build_server(fake.config(send_enabled=True, send_recipients=RECIPIENTS)).instructions
    assert "send_file" in enabled and "outbox" in enabled and "explicitly asked for that file" in enabled
    assert "send_file" not in text_only and "outbox" not in text_only


async def test_health_reports_file_policy(fake, dirs, daemon):
    fake.respond({"authenticated": True, "store": {"messages": 1}})
    async with Client(build_server(file_config(fake, dirs))) as client:
        policy = (await client.call_tool("archive_health", {})).structured_content["mcp_policy"]
    assert policy["send_files_enabled"] is True and policy["send_file_max_bytes"] == 16 * MIB
    assert "send_file_dir" not in policy and "send_staging_dir" not in policy
    async with Client(build_server(fake.config(send_enabled=True, send_recipients=RECIPIENTS))) as client:
        policy = (await client.call_tool("archive_health", {})).structured_content["mcp_policy"]
    assert policy["send_files_enabled"] is False and "send_file_max_bytes" not in policy


# Approved sends


async def test_approved_send_runs_exact_command_with_a_staged_snapshot(fake, daemon, dirs):
    outbox, staging = dirs
    write(outbox, "docs/plan.pdf", PDF)
    fake.respond(SENT)
    user = User()
    result = await send_file(
        build_server(file_config(fake, dirs)),
        {"recipient": "ada", "file": "docs/plan.pdf", "caption": "the plan\n-at 8"},
        user,
    )
    assert not result.is_error, result.content
    assert result.structured_content == {
        "sent": True,
        "recipient": "ada",
        "jid": ADA,
        "message_id": "3EB0FAKEMESSAGEID",
        "file": "plan.pdf",
        "mime": "application/pdf",
        "size_bytes": len(PDF),
        "sha256": hashlib.sha256(PDF).hexdigest(),
        "note": "WhatsApp accepted the file; delivery to the recipient's device is not confirmed.",
    }
    (call,) = fake.calls()
    argv = call["argv"]
    assert "--read-only" not in argv
    tail = argv[argv.index("send") :]
    staged = tail[3].removeprefix("--file=")
    assert tail == [
        "send",
        "file",
        f"--to={ADA}",
        f"--file={staged}",
        "--filename=plan.pdf",
        "--mime=application/pdf",
        "--as=document",
        "--max-size-mb=16",
        "--caption=the plan\n-at 8",
    ]
    staged_path = Path(staged)
    assert staged_path.parent == staging and staged_path.suffix == ".pdf"
    assert staged_path.stem != "plan" and len(staged_path.stem) == 32
    assert call["env"]["WACLI_MEDIA_ROOTS"] == str(staging)
    assert "WACLI_READONLY" not in call["env"]
    assert call["staged"] == {"sha256": hashlib.sha256(PDF).hexdigest(), "mode": 0o600}
    assert staged_leftovers(staging) == []
    assert len(user.prompts) == 1


async def test_send_without_caption_has_no_caption_argument(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    result = await send_file(build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.png"}, User())
    assert not result.is_error, result.content
    assert not any(a.startswith("--caption") for a in fake.calls()[0]["argv"])


async def test_jid_is_accepted_as_recipient(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    result = await send_file(build_server(file_config(fake, dirs)), {"recipient": BOOK_CLUB, "file": "a.png"}, User())
    assert result.structured_content["recipient"] == "club"
    assert f"--to={BOOK_CLUB}" in fake.calls()[0]["argv"]


@pytest.mark.parametrize(
    ("name", "data", "mime", "kind"),
    [
        ("a.jpg", SYNTHETIC_JPEG, "image/jpeg", "image"),
        ("A.JPEG", SYNTHETIC_JPEG, "image/jpeg", "image"),
        ("a.png", PNG, "image/png", "image"),
        ("a.webp", WEBP, "image/webp", "image"),
        ("a.mp4", SYNTHETIC_MP4, "video/mp4", "video"),
        ("a.mp3", MP3, "audio/mpeg", "audio"),
        ("b.MP3", MP3_FRAME, "audio/mpeg", "audio"),
        ("a.ogg", OGG, "audio/ogg", "audio"),
        ("a.opus", OGG, "audio/ogg", "audio"),
        ("a.m4a", M4A, "audio/mp4", "audio"),
        ("a.pdf", PDF, "application/pdf", "document"),
        ("a.PDF", PDF, "application/pdf", "document"),
        ("a.txt", "plain café text\n".encode(), "text/plain", "document"),
        ("a.csv", b"a,b\n1,2\n", "text/csv", "document"),
        ("a.md", b"# title\n\nbody\n", "text/markdown", "document"),
        (
            "a.docx",
            ooxml("word/document.xml"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "document",
        ),
        (
            "a.xlsx",
            ooxml("xl/workbook.xml"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "document",
        ),
        (
            "a.pptx",
            ooxml("ppt/presentation.xml"),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "document",
        ),
    ],
)
async def test_allowed_types_are_sent_with_explicit_mime_and_kind(fake, daemon, dirs, name, data, mime, kind):
    outbox, staging = dirs
    write(outbox, name, data)
    fake.respond(SENT)
    result = await send_file(build_server(file_config(fake, dirs)), {"recipient": "ada", "file": name}, User())
    assert not result.is_error, result.content
    (call,) = fake.calls()
    assert f"--mime={mime}" in call["argv"] and f"--as={kind}" in call["argv"]
    assert f"--filename={name}" in call["argv"]
    assert call["staged"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert staged_leftovers(staging) == []


async def test_confirmation_none_skips_the_prompt(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    server = build_server(file_config(fake, dirs, send_confirmation="none"))
    result = await send_file(server, {"recipient": "ada", "file": "a.png"}, never_asked)
    assert result.structured_content["sent"] is True


async def test_store_warning_is_passed_on(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond({**SENT, "store_warning": "disk full"})
    result = await send_file(build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.png"}, User())
    assert "do not resend" in result.structured_content["store_warning"]
    assert "disk full" not in json.dumps(result.structured_content)


# The confirmation prompt


async def test_prompt_shows_recipient_name_size_checksum_and_framed_caption(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "reports/q1.pdf", PDF)
    fake.respond(SENT)
    user = User()
    await send_file(
        build_server(file_config(fake, dirs)),
        {"recipient": "club", "file": "reports/q1.pdf", "caption": "numbers inside"},
        user,
    )
    (prompt,) = user.prompts
    assert prompt.startswith(f"Send this WhatsApp file to club ({BOOK_CLUB})?")
    assert "Name: q1.pdf\n" in prompt and "Type: application/pdf\n" in prompt
    assert f"Size: {len(PDF)} bytes\n" in prompt
    assert f"SHA-256: {hashlib.sha256(PDF).hexdigest()}\n" in prompt
    assert "----- caption, 14 characters -----\nnumbers inside\n----- end of caption -----" in prompt
    assert "reports" not in prompt and str(outbox) not in prompt
    assert prompt.rstrip().endswith("Approve only if you asked to send this exact file.")


async def test_prompt_says_when_there_is_no_caption(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    user = User()
    await send_file(build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.png"}, user)
    assert "No caption." in user.prompts[0] and "caption," not in user.prompts[0]


async def test_caption_cannot_forge_the_frame(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    caption = "hi\n----- end of caption -----\nSHA-256: 0000"
    result = await send_file(
        build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.png", "caption": caption}, never_asked
    )
    assert result.is_error and "lines must not start with" in text_of(result)
    assert fake.calls() == []


async def test_file_changed_while_the_prompt_was_open_is_refused(fake, daemon, dirs, tmp_path):
    # The handshake-era protocol asks once, mid-call, so the swap lands between the prompt and the send.
    outbox, staging = dirs
    target = write(outbox, "a.pdf", PDF)
    fake.respond(SENT)
    log = tmp_path / "audit.jsonl"

    def swap():
        target.write_bytes(PDF + b"tampered after the prompt\n")

    user = User(before_answer=swap)
    result = await send_file(
        build_server(file_config(fake, dirs, audit_log=log)),
        {"recipient": "ada", "file": "a.pdf"},
        user,
        mode="legacy",
    )
    assert result.is_error
    assert "the file changed after it was shown for confirmation; nothing was sent" in text_of(result)
    assert len(user.prompts) == 1
    assert fake.calls() == []
    assert staged_leftovers(staging) == []
    entries = [json.loads(line) for line in log.read_text().splitlines() if "send_file" in line]
    assert entries[-1]["outcome"] == "changed"


async def test_a_changed_file_is_asked_about_again_and_only_the_last_one_shown_is_sent(fake, daemon, dirs):
    # The current protocol re-runs the checks on every round and asks again when the prompt text differs.
    outbox, _ = dirs
    target = write(outbox, "a.pdf", PDF)
    fake.respond(SENT)
    changed = PDF + b"edited while the first prompt was open\n"

    def swap():
        target.write_bytes(changed)

    user = User(before_answer=swap)
    result = await send_file(build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.pdf"}, user)
    assert not result.is_error, result.content
    first, second = user.prompts
    assert hashlib.sha256(PDF).hexdigest() in first and hashlib.sha256(changed).hexdigest() not in first
    assert hashlib.sha256(changed).hexdigest() in second
    assert fake.calls()[0]["staged"]["sha256"] == hashlib.sha256(changed).hexdigest()
    assert result.structured_content["sha256"] == hashlib.sha256(changed).hexdigest()


async def test_user_saying_no_stages_and_sends_nothing(fake, daemon, dirs):
    outbox, staging = dirs
    write(outbox, "a.png", PNG)
    result = await send_file(
        build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.png"}, User(approve=False)
    )
    assert result.structured_content == {
        "sent": False,
        "recipient": "ada",
        "reason": "the user did not approve this file",
    }
    assert fake.calls() == [] and staged_leftovers(staging) == []


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_declined_or_cancelled_prompt_stages_and_sends_nothing(fake, daemon, dirs, action):
    outbox, staging = dirs
    write(outbox, "a.png", PNG)
    result = await send_file(
        build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.png"}, User(action=action)
    )
    assert result.is_error
    assert fake.calls() == [] and staged_leftovers(staging) == []


def _messages(exc: BaseException) -> list[str]:
    if isinstance(exc, BaseExceptionGroup):
        return [m for inner in exc.exceptions for m in _messages(inner)]
    return [str(exc)]


async def test_client_without_elicitation_cannot_send_a_file(fake, daemon, dirs):
    outbox, staging = dirs
    write(outbox, "a.png", PNG)
    with pytest.raises(BaseException) as info:
        await send_file(build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.png"})
    assert any("elicitation" in m.lower() for m in _messages(info.value)), _messages(info.value)
    assert fake.calls() == [] and staged_leftovers(staging) == []


# Refusals before anything is shown or sent


def build_tree(outbox: Path) -> None:
    (outbox.parent / "outside.pdf").write_bytes(PDF)
    write(outbox, "ok.pdf", PDF)
    write(outbox, "empty.pdf", b"")
    write(outbox, "big.pdf", PDF + b"x" * 4096)
    write(outbox, "prog.pdf", ELF)
    write(outbox, "prog.bin", ELF)
    write(outbox, "archive.zip", ooxml("word/document.xml"))
    write(outbox, "evil.docx", ooxml("evil.sh"))
    write(outbox, "nomanifest.docx", ooxml("word/document.xml", content_types=False))
    write(outbox, "wrongdir.xlsx", ooxml("word/document.xml"))
    write(outbox, "garbage.docx", b"PK\x03\x04 not really a zip")
    os.link(outbox.parent / "outside.pdf", outbox / "hardlink.pdf")
    write(outbox, "photo.pdf", PNG)
    write(outbox, "latin1.txt", b"caf\xe9\n")
    write(outbox, "nul.txt", b"abc\x00def")
    write(outbox, "voice.mp3", MP3)
    write(outbox, "noext", PDF)
    write(outbox, "real/inner.pdf", PDF)
    (outbox / "link.pdf").symlink_to(outbox / "ok.pdf")
    (outbox / "linkdir").symlink_to(outbox / "real", target_is_directory=True)
    (outbox / "adir").mkdir()
    os.mkfifo(outbox / "fifo.pdf")


REFUSALS = [
    ("../ok.pdf", "'..'"),
    ("real/../ok.pdf", "'..'"),
    ("./ok.pdf", "'.'"),
    ("/etc/passwd", "not absolute"),
    ("real//inner.pdf", "empty path components"),
    ("real/", "empty path components"),
    ("a\\b.pdf", "backslashes"),
    (".env", "hidden"),
    ("real/.secret.pdf", "hidden"),
    (".ssh/id.pdf", "hidden"),
    ("bad\x07name.pdf", "control or invisible"),
    ("nul\x00.pdf", "control or invisible"),
    ("bidi" + chr(0x202E) + "fdp.pdf", "control or invisible"),
    ("a" + chr(0x2028) + ".pdf", "control or invisible"),
    ("a" + chr(0x2029) + ".pdf", "control or invisible"),
    ("a" + chr(0x00A0) + ".pdf", "control or invisible"),
    ("a" + chr(0x3164) + ".pdf", "control or invisible"),
    ("a" + chr(0x2800) + ".pdf", "control or invisible"),
    ("a" + chr(0x115F) + ".pdf", "control or invisible"),
    ("a" + chr(0xFFA0) + ".pdf", "control or invisible"),
    ("", "relative to the outbox"),
    ("x" * 1025, "relative to the outbox"),
    ("y" * 256 + ".pdf", "at most 255 bytes"),
    ("z" * 129 + ".pdf", "at most 128 characters"),
    ("missing.pdf", "not found"),
    ("ok.pdf/inner.pdf", "symlinks or non-directories"),
    ("link.pdf", "symlinks or non-directories"),
    ("linkdir/inner.pdf", "symlinks or non-directories"),
    ("adir", "not a regular file"),
    ("fifo.pdf", "not a regular file"),
    ("empty.pdf", "file is empty"),
    ("big.pdf", "larger than the 2048 byte limit"),
    ("prog.bin", "type is not allowed"),
    ("prog.pdf", "type is not allowed"),
    ("noext", "type is not allowed"),
    ("archive.zip", "type is not allowed"),
    ("evil.docx", "not a valid Office document"),
    ("nomanifest.docx", "not a valid Office document"),
    ("wrongdir.xlsx", "not a valid Office document"),
    ("garbage.docx", "not a valid Office document"),
    ("hardlink.pdf", "more than one hard link"),
    ("photo.pdf", "extension does not match"),
    ("latin1.txt", "valid UTF-8"),
    ("nul.txt", "NUL"),
]


@pytest.mark.parametrize(("file", "message"), REFUSALS)
async def test_bad_files_are_refused_before_any_prompt(fake, daemon, dirs, file, message):
    outbox, staging = dirs
    build_tree(outbox)
    server = build_server(file_config(fake, dirs, send_file_max_bytes=2048))
    result = await send_file(server, {"recipient": "ada", "file": file}, never_asked)
    assert result.is_error
    assert message in text_of(result)
    assert str(outbox) not in text_of(result) and str(staging) not in text_of(result)
    assert fake.calls() == [] and staged_leftovers(staging) == []


async def test_a_file_that_is_a_symlink_to_a_secret_is_not_read(fake, daemon, dirs, tmp_path):
    outbox, _ = dirs
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    (outbox / "notes.txt").symlink_to(secret)
    result = await send_file(build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "notes.txt"})
    assert result.is_error and "top secret" not in text_of(result)
    assert fake.calls() == []


async def test_caption_is_refused_for_audio(fake, daemon, dirs):
    outbox, _ = dirs
    build_tree(outbox)
    result = await send_file(
        build_server(file_config(fake, dirs)),
        {"recipient": "ada", "file": "voice.mp3", "caption": "listen"},
        never_asked,
    )
    assert result.is_error and "audio files cannot have a caption" in text_of(result)
    assert fake.calls() == []


@pytest.mark.parametrize("caption", ["   ", "pay " + chr(0x202E) + "1234", "x" * 1001])
async def test_bad_captions_are_refused(fake, daemon, dirs, caption):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    result = await send_file(
        build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.png", "caption": caption}, never_asked
    )
    assert result.is_error and fake.calls() == []


@pytest.mark.parametrize("recipient", ["+15550000009", "Ada Lovelace", ""])
async def test_unknown_recipients_are_refused(fake, daemon, dirs, recipient):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    result = await send_file(
        build_server(file_config(fake, dirs)), {"recipient": recipient, "file": "a.png"}, never_asked
    )
    assert result.is_error and "configured aliases" in text_of(result)
    assert fake.calls() == []


async def test_send_file_requires_running_sync_daemon(fake, dirs):
    outbox, staging = dirs
    write(outbox, "a.png", PNG)
    result = await send_file(build_server(file_config(fake, dirs)), {"recipient": "ada", "file": "a.png"}, never_asked)
    assert result.is_error and "wacli sync --follow" in text_of(result)
    assert fake.calls() == [] and staged_leftovers(staging) == []


async def test_a_file_exactly_at_the_limit_is_accepted_and_one_byte_more_is_not(fake, daemon, dirs):
    outbox, _ = dirs
    fake.respond(SENT)
    server = build_server(file_config(fake, dirs, send_file_max_bytes=2048, send_confirmation="none"))
    write(outbox, "ok.txt", b"a" * 2048)
    write(outbox, "over.txt", b"a" * 2049)
    ok = await send_file(server, {"recipient": "ada", "file": "ok.txt"})
    over = await send_file(server, {"recipient": "ada", "file": "over.txt"})
    assert not ok.is_error and over.is_error and "larger than the 2048 byte limit" in text_of(over)
    assert "--max-size-mb=1" in fake.calls()[0]["argv"]


# Outcomes


async def test_failure_removes_the_snapshot_and_allows_a_retry(fake, daemon, dirs):
    outbox, staging = dirs
    write(outbox, "a.png", PNG)
    fake.scenario(stdout=json.dumps({"success": False, "data": None, "error": "not authenticated"}), rc=1)
    async with Client(build_server(file_config(fake, dirs)), elicitation_callback=User()) as client:
        failed = await client.call_tool("send_file", {"recipient": "ada", "file": "a.png"})
        assert staged_leftovers(staging) == []
        fake.respond(SENT)
        retried = await client.call_tool("send_file", {"recipient": "ada", "file": "a.png"})
    assert failed.is_error and "not sent: not authenticated" in text_of(failed)
    assert not retried.is_error
    assert staged_leftovers(staging) == []


async def test_uncertain_outcome_blocks_a_retry_and_removes_the_snapshot(fake, daemon, dirs, tmp_path):
    outbox, staging = dirs
    write(outbox, "secret-plan.pdf", PDF)
    error = "no reply from the running sync process before the timeout; the file may still have gone through"
    fake.scenario(stdout=json.dumps({"success": False, "data": None, "error": error}), rc=1)
    log = tmp_path / "audit.jsonl"
    server = build_server(file_config(fake, dirs, audit_log=log))
    async with Client(server, elicitation_callback=User()) as client:
        first = await client.call_tool("send_file", {"recipient": "ada", "file": "secret-plan.pdf"})
        retry = await client.call_tool("send_file", {"recipient": "ada", "file": "secret-plan.pdf"})
    assert first.is_error and "outcome is unknown" in text_of(first)
    assert retry.is_error and "same file was already sent" in text_of(retry)
    assert len(fake.calls()) == 1
    assert staged_leftovers(staging) == []
    entries = [json.loads(line) for line in log.read_text().splitlines() if "send_file" in line]
    assert [e["outcome"] for e in entries] == ["uncertain", "rejected"]


async def test_timeout_is_uncertain_and_removes_the_snapshot(fake, daemon, dirs):
    outbox, staging = dirs
    write(outbox, "a.png", PNG)
    fake.scenario(sleep=30)
    server = build_server(file_config(fake, dirs, send_timeout_s=0.2))
    result = await send_file(server, {"recipient": "ada", "file": "a.png"}, User())
    assert result.is_error and "outcome is unknown" in text_of(result)
    assert staged_leftovers(staging) == []


@pytest.mark.skipif(os.getuid() == 0, reason="root can write to a read-only directory")
async def test_staging_failure_is_a_clean_not_sent_error_and_allows_a_retry(fake, daemon, dirs):
    outbox, staging = dirs
    write(outbox, "a.png", PNG)
    staging.chmod(0o500)
    try:
        async with Client(build_server(file_config(fake, dirs, send_confirmation="none"))) as client:
            first = await client.call_tool("send_file", {"recipient": "ada", "file": "a.png"})
            second = await client.call_tool("send_file", {"recipient": "ada", "file": "a.png"})
    finally:
        staging.chmod(0o700)
    for result in (first, second):
        assert result.is_error and "not sent: the file could not be staged" in text_of(result)
        assert str(staging) not in text_of(result)
    assert fake.calls() == []


async def test_snapshot_is_what_was_approved_even_if_the_outbox_changes_later(fake, daemon, dirs):
    outbox, _ = dirs
    target = write(outbox, "a.pdf", PDF)
    fake.respond(SENT)
    server = build_server(file_config(fake, dirs, send_confirmation="none"))
    result = await send_file(server, {"recipient": "ada", "file": "a.pdf"})
    target.write_bytes(b"changed afterwards")
    assert not result.is_error
    assert fake.calls()[0]["staged"]["sha256"] == hashlib.sha256(PDF).hexdigest()


# Shared limits


async def test_same_file_and_caption_twice_is_refused_but_another_caption_is_allowed(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    server = build_server(file_config(fake, dirs))
    args = {"recipient": "ada", "file": "a.png", "caption": "look"}
    async with Client(server, elicitation_callback=User()) as client:
        first = await client.call_tool("send_file", args)
        second = await client.call_tool("send_file", args)
        other_caption = await client.call_tool("send_file", {**args, "caption": "look again"})
        other_recipient = await client.call_tool("send_file", {**args, "recipient": "club"})
    assert not first.is_error and not other_caption.is_error and not other_recipient.is_error
    assert second.is_error and "same file was already sent" in text_of(second)
    assert len(fake.calls()) == 3


async def test_a_renamed_copy_of_a_sent_file_is_still_a_duplicate(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    write(outbox, "copy.png", PNG)
    fake.respond(SENT)
    async with Client(build_server(file_config(fake, dirs)), elicitation_callback=User()) as client:
        first = await client.call_tool("send_file", {"recipient": "ada", "file": "a.png"})
        second = await client.call_tool("send_file", {"recipient": "ada", "file": "copy.png"})
    assert not first.is_error and second.is_error and "already sent" in text_of(second)


async def test_concurrent_identical_sends_go_out_once(fake, daemon, dirs):
    outbox, staging = dirs
    write(outbox, "a.png", PNG)
    fake.scenario(stdout=json.dumps({"success": True, "data": SENT, "error": None}), sleep=1)
    server = build_server(file_config(fake, dirs, send_confirmation="none"))
    args = {"recipient": "ada", "file": "a.png"}
    async with Client(server, elicitation_callback=never_asked) as client:
        results = await asyncio.gather(client.call_tool("send_file", args), client.call_tool("send_file", args))
    assert sorted(r.is_error for r in results) == [False, True]
    assert len(fake.calls()) == 1 and staged_leftovers(staging) == []


async def test_hourly_limit_is_shared_with_send_message(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    server = build_server(file_config(fake, dirs, send_per_hour=1))
    async with Client(server, elicitation_callback=User()) as client:
        text = await client.call_tool("send_message", {"recipient": "ada", "text": "one"})
        limited = await client.call_tool("send_file", {"recipient": "ada", "file": "a.png"})
    assert not text.is_error
    assert limited.is_error and "per hour" in text_of(limited)
    assert len(fake.calls()) == 1


async def test_hourly_limit_is_shared_the_other_way_round(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    server = build_server(file_config(fake, dirs, send_per_hour=1))
    async with Client(server, elicitation_callback=User()) as client:
        sent = await client.call_tool("send_file", {"recipient": "ada", "file": "a.png"})
        limited = await client.call_tool("send_message", {"recipient": "ada", "text": "one"})
    assert not sent.is_error and limited.is_error and "per hour" in text_of(limited)


# Audit


async def test_audit_records_hold_no_file_name_path_caption_or_checksum(fake, daemon, dirs, tmp_path):
    outbox, _ = dirs
    write(outbox, "payroll/march-secret.pdf", PDF)
    fake.respond(SENT)
    log = tmp_path / "audit.jsonl"
    server = build_server(file_config(fake, dirs, audit_log=log))
    async with Client(server, elicitation_callback=User()) as client:
        await client.call_tool(
            "send_file", {"recipient": "ada", "file": "payroll/march-secret.pdf", "caption": "hush hush"}
        )
        await client.call_tool("send_file", {"recipient": "stranger", "file": "payroll/march-secret.pdf"})
        await client.call_tool("send_file", {"recipient": "ada", "file": "../payroll/march-secret.pdf"})
    text = log.read_text()
    for secret in ("payroll", "march-secret", "hush hush", hashlib.sha256(PDF).hexdigest(), str(outbox)):
        assert secret not in text
    entries = [json.loads(line) for line in text.splitlines()]
    sent, *refused = entries
    assert sent["tool"] == "send_file" and sent["outcome"] == "sent" and sent["recipient"] == "ada"
    assert sent["bytes"] == len(PDF) and sent["mime"] == "application/pdf" and "ms" in sent
    assert [e["outcome"] for e in refused] == ["rejected", "rejected"]
    assert all(e["tool"] == "send_file" and e["stage"] == "preflight" and "recipient" not in e for e in refused)


async def test_declined_send_is_audited(fake, daemon, dirs, tmp_path):
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    log = tmp_path / "audit.jsonl"
    server = build_server(file_config(fake, dirs, audit_log=log))
    await send_file(server, {"recipient": "ada", "file": "a.png"}, User(approve=False))
    (entry,) = [json.loads(line) for line in log.read_text().splitlines()]
    assert entry["outcome"] == "declined" and entry["tool"] == "send_file"


# Runner


def test_extra_env_is_limited_to_the_media_roots_of_write_calls(fake):
    runner = WacliRunner(fake.config())
    assert runner.build_env(write=True, extra={"WACLI_MEDIA_ROOTS": "/x"})["WACLI_MEDIA_ROOTS"] == "/x"
    assert "WACLI_MEDIA_ROOTS" not in runner.build_env(write=True)
    for env in ({"WACLI_STORE_DIR": "/x"}, {"PATH": "/tmp"}, {"WACLI_MEDIA_ROOTS": "/x", "LD_PRELOAD": "/y"}):
        with pytest.raises(WacliError, match="cannot be set"):
            runner.build_env(write=True, extra=env)
    with pytest.raises(WacliError, match="cannot be set"):
        runner.build_env(extra={"WACLI_MEDIA_ROOTS": "/x"})


# Multiple accounts


def accounts_toml(tmp_path: Path, stores: dict[str, Path]) -> Path:
    body = (
        f'[accounts.personal]\nstore = "{stores["personal"]}"\n'
        f'[accounts.personal.send]\nrecipients = {{ ada = "{ADA}" }}\n'
        f'[accounts.work]\nstore = "{stores["work"]}"\n'
        f'[accounts.work.send]\nrecipients = {{ club = "{BOOK_CLUB}" }}\n'
    )
    path = tmp_path / "accounts.toml"
    path.write_text(body)
    path.chmod(0o600)
    return path


@pytest.fixture
def multi(fake, dirs, tmp_path):
    stores = {}
    for name in ("personal", "work"):
        stores[name] = tmp_path / "stores" / name
        stores[name].mkdir(parents=True, mode=0o700)
    outbox, staging = dirs
    cfg = Config.from_env(
        {
            "HOME": str(fake.home),
            "WACLI_MCP_BIN": str(fake.path),
            "WACLI_MCP_NETWORK_ISOLATION": "off",
            "WACLI_MCP_ACCOUNTS_FILE": str(accounts_toml(tmp_path, stores)),
            "WACLI_MCP_ENABLE_SEND": "1",
            "WACLI_MCP_ENABLE_SEND_FILES": "1",
            "WACLI_MCP_SEND_FILE_DIR": str(outbox),
            "WACLI_MCP_SEND_STAGING_DIR": str(staging),
        }
    )
    daemons = {name: FakeDaemon(store) for name, store in stores.items()}
    yield cfg, stores, daemons
    for d in daemons.values():
        d.stop()


async def test_multi_account_requires_an_account_and_names_it_in_the_prompt(fake, dirs, multi):
    cfg, stores, _ = multi
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    async with Client(build_server(cfg)) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "send_file")
    assert set(tool.input_schema["required"]) == {"account", "recipient", "file"}
    user = User()
    result = await send_file(build_server(cfg), {"account": "work", "recipient": "club", "file": "a.png"}, user)
    assert not result.is_error, result.content
    assert result.structured_content["account"] == "work"
    (prompt,) = user.prompts
    assert "from the work account" in prompt and BOOK_CLUB in prompt
    (argv,) = [c["argv"] for c in fake.calls()]
    assert f"--store={stores['work']}" in argv and f"--to={BOOK_CLUB}" in argv


async def test_multi_account_refuses_a_recipient_of_another_account(fake, dirs, multi):
    cfg, _, _ = multi
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    for recipient in ("ada", ADA):
        result = await send_file(
            build_server(cfg), {"account": "work", "recipient": recipient, "file": "a.png"}, never_asked
        )
        assert result.is_error and "for this account: club" in text_of(result)
    assert fake.calls() == []


async def test_multi_account_send_needs_the_daemon_of_that_account(fake, dirs, multi, tmp_path):
    cfg, stores, daemons = multi
    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    daemons["work"].stop()
    log = tmp_path / "audit.jsonl"
    server = build_server(replace(cfg, audit_log=log))
    async with Client(server, elicitation_callback=User()) as client:
        work = await client.call_tool("send_file", {"account": "work", "recipient": "club", "file": "a.png"})
        personal = await client.call_tool("send_file", {"account": "personal", "recipient": "ada", "file": "a.png"})
    assert work.is_error and "sync --follow" in text_of(work)
    assert not personal.is_error
    (argv,) = [c["argv"] for c in fake.calls()]
    assert f"--store={stores['personal']}" in argv
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    assert [(e["account"], e["outcome"]) for e in entries] == [("work", "rejected"), ("personal", "sent")]
    assert "a.png" not in log.read_text()


def test_stale_snapshots_are_removed_at_startup_and_fresh_ones_are_kept(fake, dirs):
    # A call cancelled while its snapshot was being written can leave the file behind.
    _, staging = dirs
    stale = staging / ("ab" * 16 + ".pdf")
    fresh = staging / ("cd" * 16 + ".pdf")
    unrelated = staging / "notes.txt"
    for path in (stale, fresh, unrelated):
        path.write_bytes(PDF)
    old = stale.stat().st_mtime - 3600
    os.utime(stale, (old, old))
    os.utime(unrelated, (old, old))
    build_server(file_config(fake, dirs))
    assert not stale.exists()
    assert fresh.exists() and unrelated.exists()


# Review fixes


@pytest.mark.skipif(os.getuid() == 0, reason="root passes the ownership rule")
def test_files_owned_by_someone_else_are_refused(fake, dirs, monkeypatch):
    from wacli_mcp import outbox as outbox_module

    outbox, _ = dirs
    write(outbox, "a.pdf", PDF)
    monkeypatch.setattr(outbox_module.os, "getuid", lambda: 12345)
    with pytest.raises(Exception, match="not owned by the server's user"):
        outbox_module.load(outbox, "a.pdf", 1024)


async def test_a_changed_file_cannot_ride_another_calls_approval(fake, daemon, dirs):
    """Legacy mode, two identical concurrent calls: call 2's prompt must not vouch for call 1's bytes."""
    outbox, staging = dirs
    target = write(outbox, "a.pdf", PDF)
    fake.respond(SENT)
    first_swapped, second_asked = asyncio.Event(), asyncio.Event()
    prompts: list[str] = []

    async def user(context, params):
        prompts.append(params.message)
        if len(prompts) == 1:
            target.write_bytes(PDF + b"swapped after prompt one\n")
            first_swapped.set()
            await asyncio.wait_for(second_asked.wait(), 10)
            return ElicitResult(action="accept", content={"approve": True})
        second_asked.set()
        return ElicitResult(action="decline")

    args = {"recipient": "ada", "file": "a.pdf"}
    async with Client(build_server(file_config(fake, dirs)), elicitation_callback=user, mode="legacy") as client:

        async def second():
            await asyncio.wait_for(first_swapped.wait(), 10)
            return await client.call_tool("send_file", args)

        first, other = await asyncio.gather(client.call_tool("send_file", args), second())
    assert len(prompts) == 2 and other.is_error
    assert first.is_error and "the file changed after it was shown for confirmation" in text_of(first)
    assert fake.calls() == [] and staged_leftovers(staging) == []


async def test_tool_schema_does_not_expose_the_context(fake, dirs):
    async with Client(build_server(file_config(fake, dirs))) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "send_file")
    assert set(tool.input_schema["properties"]) == {"recipient", "file", "caption"}


def _sender():
    from wacli_mcp.runner import RateLimiter
    from wacli_mcp.sending import DuplicateGuard, _Sender

    return _Sender(Config(wacli_bin=Path("/bin/true"), home=Path("/tmp")), RateLimiter(5), DuplicateGuard())


async def test_a_cancelled_send_is_audited_as_uncertain():
    from wacli_mcp.sending import _deliver

    record: dict = {}
    started = asyncio.Event()

    async def hang():
        started.set()
        await asyncio.sleep(60)

    task = asyncio.ensure_future(_deliver(_sender(), "k", record, hang))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert record["outcome"] == "uncertain"


async def test_output_limit_is_an_uncertain_outcome():
    from mcp.server.mcpserver.exceptions import ToolError

    from wacli_mcp.sending import _deliver

    sender, record = _sender(), {}

    async def overflow():
        raise WacliError("wacli output exceeded 10 bytes", kind="output_limit")

    with pytest.raises(ToolError, match="outcome is unknown"):
        await _deliver(sender, "k", record, overflow)
    assert record["outcome"] == "uncertain"
    with pytest.raises(Exception, match="already sent"):
        sender.guard.check("k")


class LeakyRunner(WacliRunner):
    """Fails the way wacli can: with a message that quotes the paths it was given."""

    async def run_write(self, args, target=None, *, extra_env=None):
        file = next(a for a in args if a.startswith("--file=")).split("=", 1)[1]
        name = next(a for a in args if a.startswith("--filename=")).split("=", 1)[1]
        root = extra_env["WACLI_MEDIA_ROOTS"]
        raise WacliError(f"open {file}: denied ({name} under {root}, {os.path.basename(file)})")


async def test_wacli_error_text_carries_no_local_path(fake, daemon, dirs):
    outbox, staging = dirs
    write(outbox, "payroll-march.pdf", PDF)
    server = build_server(file_config(fake, dirs, send_confirmation="none"), LeakyRunner(fake.config()))
    result = await send_file(server, {"recipient": "ada", "file": "payroll-march.pdf"})
    message = text_of(result)
    assert result.is_error and "not sent: " in message
    assert "<staging>" in message and "<file>" in message
    assert str(staging) not in message and "payroll-march" not in message
    assert not any(part in message for part in os.listdir(staging)) and ".pdf" not in message.replace("<file>", "")


async def test_cancelling_a_call_while_staging_leaves_no_file(fake, daemon, dirs, monkeypatch):
    import threading

    from wacli_mcp import sending

    outbox, staging = dirs
    write(outbox, "a.pdf", PDF)
    entered, release = threading.Event(), threading.Event()
    real = sending._stage

    def slow(path, data):
        entered.set()
        release.wait(10)
        real(path, data)

    monkeypatch.setattr(sending, "_stage", slow)
    async with Client(build_server(file_config(fake, dirs, send_confirmation="none"))) as client:
        task = asyncio.ensure_future(client.call_tool("send_file", {"recipient": "ada", "file": "a.pdf"}))
        for _ in range(400):
            if entered.is_set():
                break
            await asyncio.sleep(0.025)
        assert entered.is_set()
        task.cancel()
        await asyncio.sleep(0.2)
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0.5)
    assert staged_leftovers(staging) == []


async def test_snapshot_reads_are_limited_to_two_at_a_time(fake, daemon, dirs, monkeypatch):
    import threading
    import time

    from wacli_mcp import outbox as outbox_module

    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    lock, state = threading.Lock(), {"active": 0, "peak": 0}
    real = outbox_module.load

    def counted(*args):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        time.sleep(0.1)
        try:
            return real(*args)
        finally:
            with lock:
                state["active"] -= 1

    monkeypatch.setattr(outbox_module, "load", counted)
    server = build_server(file_config(fake, dirs, send_confirmation="none", send_per_hour=60))
    async with Client(server) as client:
        await asyncio.gather(
            *(
                client.call_tool("send_file", {"recipient": "ada", "file": "a.png", "caption": f"c{i}"})
                for i in range(6)
            )
        )
    assert state["peak"] <= 2


async def test_a_refusal_in_the_send_step_is_audited_without_arguments(fake, daemon, dirs, tmp_path):
    # The prompt passes, then the file disappears before the send re-checks it (handshake-era protocol).
    outbox, _ = dirs
    target = write(outbox, "secret-name.pdf", PDF)
    log = tmp_path / "audit.jsonl"
    user = User(before_answer=target.unlink)
    server = build_server(file_config(fake, dirs, audit_log=log))
    result = await send_file(server, {"recipient": "ada", "file": "secret-name.pdf"}, user, mode="legacy")
    assert result.is_error
    (entry,) = [json.loads(line) for line in log.read_text().splitlines()]
    assert entry == {**entry, "tool": "send_file", "outcome": "rejected", "stage": "send"}
    assert "recipient" not in entry and "secret-name" not in log.read_text()


async def test_a_text_refusal_in_the_send_step_is_audited_as_send_stage(fake, daemon, dirs, tmp_path):
    log = tmp_path / "audit.jsonl"
    user = User(before_answer=daemon.stop)
    server = build_server(file_config(fake, dirs, audit_log=log))
    async with Client(server, elicitation_callback=user, mode="legacy") as client:
        result = await client.call_tool("send_message", {"recipient": "ada", "text": "hi"})
    assert result.is_error
    (entry,) = [json.loads(line) for line in log.read_text().splitlines()]
    assert entry["tool"] == "send_message" and entry["outcome"] == "rejected" and entry["stage"] == "send"


async def test_an_office_zip_with_too_many_entries_is_refused(fake, daemon, dirs):
    outbox, _ = dirs
    write(outbox, "huge.docx", ooxml("word/document.xml", extra=10000))
    write(outbox, "fine.docx", ooxml("word/document.xml", extra=100))
    fake.respond(SENT)
    server = build_server(file_config(fake, dirs, send_confirmation="none"))
    huge = await send_file(server, {"recipient": "ada", "file": "huge.docx"})
    fine = await send_file(server, {"recipient": "ada", "file": "fine.docx"})
    assert huge.is_error and "not a valid Office document" in text_of(huge)
    assert not fine.is_error


@pytest.mark.parametrize("brand", [b"M4A ", b"isom", b"mp42"])
def test_audio_only_m4a_is_accepted_whatever_its_brand(brand):
    assert outbox.classify("a.m4a", iso(brand, [b"soun"])) == ("audio/mp4", "audio", ".m4a")


@pytest.mark.parametrize(
    "data",
    [
        iso(b"M4A ", [b"soun", b"vide"]),
        iso(b"isom", [b"vide"]),
        iso(b"M4A ", []),
        iso(b"M4A ", [b"soun"], moov=False),
        b"\x00\x00\x00\x18ftypM4A " + b"\x00" * 40,
        b"\x00\x00\x00\x18ftypisom" + b"\xff" * 40,
    ],
    ids=["audio-and-video", "video-only", "no-tracks", "no-moov", "header-only", "garbage-boxes"],
)
def test_m4a_that_is_not_provably_audio_only_is_refused(data):
    with pytest.raises(ToolError, match="audio-only"):
        outbox.classify("a.m4a", data)


def test_an_mp4_video_is_still_a_video():
    assert outbox.classify("a.mp4", iso(b"isom", [b"vide", b"soun"]))[:2] == ("video/mp4", "video")


@pytest.mark.parametrize(
    "scenario", [{"stdout": "not json at all"}, {"stdout": "", "rc": 1}, {"stdout": "boom", "rc": 2}]
)
async def test_a_reply_without_an_envelope_is_uncertain_for_files_too(fake, daemon, dirs, scenario):
    outbox, staging = dirs
    write(outbox, "a.png", PNG)
    fake.scenario(**scenario)
    server = build_server(file_config(fake, dirs))
    async with Client(server, elicitation_callback=User()) as client:
        first = await client.call_tool("send_file", {"recipient": "ada", "file": "a.png"})
        retry = await client.call_tool("send_file", {"recipient": "ada", "file": "a.png"})
    assert first.is_error and "outcome is unknown" in text_of(first)
    assert retry.is_error and "same file was already sent" in text_of(retry)
    assert len(fake.calls()) == 1 and staged_leftovers(staging) == []


def _office_zip_with_claimed_entries(count: int) -> bytes:
    data = bytearray(ooxml("word/document.xml"))
    eocd = data.rindex(b"PK\x05\x06")
    data[eocd + 8 : eocd + 12] = count.to_bytes(2, "little") * 2
    return bytes(data)


@pytest.mark.parametrize("count", [10_001, 20_000, 0xFFFF])
def test_the_zip_directory_is_not_opened_when_it_claims_too_many_entries(dirs, monkeypatch, count):
    from mcp.server.mcpserver.exceptions import ToolError

    from wacli_mcp import outbox as outbox_module

    outbox, _ = dirs
    write(outbox, "claims.docx", _office_zip_with_claimed_entries(count))

    def forbidden(*args, **kwargs):
        raise AssertionError("zipfile.ZipFile must not be constructed")

    monkeypatch.setattr(outbox_module.zipfile, "ZipFile", forbidden)
    with pytest.raises(ToolError, match="not a valid Office document"):
        outbox_module.load(outbox, "claims.docx", 1 << 20)


def test_zip64_markers_and_a_missing_end_record_are_refused_without_opening(dirs, monkeypatch):
    from mcp.server.mcpserver.exceptions import ToolError

    from wacli_mcp import outbox as outbox_module

    outbox, _ = dirs
    data = bytearray(ooxml("word/document.xml"))
    eocd = data.rindex(b"PK\x05\x06")
    zip64 = bytearray(data)
    zip64[eocd + 12 : eocd + 16] = b"\xff\xff\xff\xff"
    write(outbox, "zip64.docx", bytes(zip64))
    write(outbox, "noeocd.docx", bytes(data[:eocd]))

    def forbidden(*args, **kwargs):
        raise AssertionError("zipfile.ZipFile must not be constructed")

    monkeypatch.setattr(outbox_module.zipfile, "ZipFile", forbidden)
    for name in ("zip64.docx", "noeocd.docx"):
        with pytest.raises(ToolError, match="not a valid Office document"):
            outbox_module.load(outbox, name, 1 << 20)


async def test_only_one_send_holds_a_snapshot_at_a_time(fake, daemon, dirs, monkeypatch):
    import threading
    import time

    from wacli_mcp import sending

    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    fake.respond(SENT)
    lock, state = threading.Lock(), {"held": 0, "peak": 0}
    real_stage, real_unstage = sending._stage, sending._unstage

    def stage(path, data):
        with lock:
            state["held"] += 1
            state["peak"] = max(state["peak"], state["held"])
        time.sleep(0.1)
        real_stage(path, data)

    def unstage(path):
        real_unstage(path)
        with lock:
            state["held"] -= 1

    monkeypatch.setattr(sending, "_stage", stage)
    monkeypatch.setattr(sending, "_unstage", unstage)
    server = build_server(file_config(fake, dirs, send_confirmation="none", send_per_hour=60))
    async with Client(server) as client:
        results = await asyncio.gather(
            *(
                client.call_tool("send_file", {"recipient": "ada", "file": "a.png", "caption": f"c{i}"})
                for i in range(4)
            )
        )
    assert not any(r.is_error for r in results), [text_of(r) for r in results]
    assert state["peak"] == 1


async def test_a_cancelled_load_keeps_its_permit_until_its_thread_ends(fake, daemon, dirs, monkeypatch):
    import threading

    from wacli_mcp import outbox as outbox_module

    outbox, _ = dirs
    write(outbox, "a.png", PNG)
    release, lock, started = threading.Event(), threading.Lock(), []
    real = outbox_module.load

    def blocked(*args):
        with lock:
            started.append(1)
        release.wait(10)
        return real(*args)

    monkeypatch.setattr(outbox_module, "load", blocked)
    server = build_server(file_config(fake, dirs, send_confirmation="none", send_per_hour=60))
    async with Client(server) as client:

        def call(i):
            return asyncio.ensure_future(
                client.call_tool("send_file", {"recipient": "ada", "file": "a.png", "caption": f"c{i}"})
            )

        first, second = call(0), call(1)
        for _ in range(200):
            if len(started) == 2:
                break
            await asyncio.sleep(0.025)
        assert len(started) == 2
        first.cancel()
        await asyncio.sleep(0.1)
        third = call(2)
        await asyncio.sleep(0.4)
        assert len(started) == 2, "a third load started while two threads were still reading"
        release.set()
        await asyncio.gather(first, second, third, return_exceptions=True)


def test_the_duplicate_window_starts_when_a_send_finishes():
    from wacli_mcp.runner import RateLimiter
    from wacli_mcp.sending import DuplicateGuard, _deliver, _Sender

    now = [0.0]
    guard = DuplicateGuard(window_s=600.0, clock=lambda: now[0])
    sender = _Sender(None, RateLimiter(10, window_s=3600.0), guard)

    async def slow_send():
        now[0] += 700.0  # queued behind other writes for longer than the window
        return {"sent": True}

    asyncio.run(_deliver(sender, "k", {}, slow_send))
    with pytest.raises(ToolError, match="already sent"):
        guard.check("k", "file")
