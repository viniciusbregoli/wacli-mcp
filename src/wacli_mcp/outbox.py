"""Reads and classifies a file from the operator's outbox for `send_file`.

The path comes from the model, so it is treated as hostile: it must be a plain
relative path, every component is opened with O_NOFOLLOW relative to the
previous directory descriptor (no symlink at any level, no race between check
and open), and the file's own bytes decide whether it may be sent: the content
must look like an allowed type and the extension must agree with it.

Refusal messages never contain local paths.
"""

import hashlib
import io
import os
import stat
import struct
import unicodedata
import zipfile
from dataclasses import dataclass

from mcp.server.mcpserver.exceptions import ToolError

from . import media

MAX_PATH_CHARS = 1024
MAX_COMPONENT_BYTES = 255
MAX_NAME_CHARS = 128

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK keeps a FIFO planted in the outbox from hanging the open.
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY

_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"

# extension -> (mime type, wacli --as value)
TYPES: dict[str, tuple[str, str]] = {
    ".jpg": ("image/jpeg", "image"),
    ".jpeg": ("image/jpeg", "image"),
    ".png": ("image/png", "image"),
    ".webp": ("image/webp", "image"),
    ".mp4": ("video/mp4", "video"),
    ".mp3": ("audio/mpeg", "audio"),
    ".ogg": ("audio/ogg", "audio"),
    ".opus": ("audio/ogg", "audio"),
    ".m4a": ("audio/mp4", "audio"),
    ".pdf": ("application/pdf", "document"),
    ".txt": ("text/plain", "document"),
    ".csv": ("text/csv", "document"),
    ".md": ("text/markdown", "document"),
    ".docx": (_DOCX, "document"),
    ".xlsx": (_XLSX, "document"),
    ".pptx": (_PPTX, "document"),
}
_TEXT_MIMES = frozenset({"text/plain", "text/csv", "text/markdown"})
_OOXML_MIMES = frozenset({_DOCX, _XLSX, _PPTX})
# Content types media.sniff knows that are allowed here (GIF, 3GP and QuickTime are not).
_MEDIA_SNIFFED = frozenset({"image/jpeg", "image/png", "image/webp", "video/mp4"})
_ZIP = "application/zip"

# Not Z* or Cf, yet they render as blanks, so a name could look empty or like another name.
_BLANKS = frozenset(map(chr, (0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x180E)))
MAX_ZIP_ENTRIES = 10_000
# What an Office document must hold besides [Content_Types].xml.
_OOXML_DIRS = {_DOCX: "word/", _XLSX: "xl/", _PPTX: "ppt/"}

ALLOWED_TYPES = "JPEG, PNG, WebP, MP4, MP3, OGG/Opus, M4A, PDF, TXT, CSV, MD, DOCX, XLSX, PPTX"


@dataclass(frozen=True)
class OutboxFile:
    data: bytes
    sha256: str
    mime: str
    kind: str  # wacli --as value
    name: str  # display name: the last path component
    ext: str  # lowercase extension, used for the staged copy

    @property
    def size(self) -> int:
        return len(self.data)


def _unprintable(text: str) -> bool:
    for ch in text:
        category = unicodedata.category(ch)
        if category in ("Cc", "Cf", "Cs", "Co") or ch in _BLANKS or (category.startswith("Z") and ch != " "):
            return True
    return False


def validate_path(value: object) -> tuple[str, ...]:
    """Check a relative path lexically, before the filesystem is touched, and split it."""
    if not isinstance(value, str) or not 0 < len(value) <= MAX_PATH_CHARS:
        raise ToolError(f"file must be a path relative to the outbox, 1 to {MAX_PATH_CHARS} characters")
    if _unprintable(value):
        raise ToolError("file contains control or invisible characters")
    if "\\" in value:
        raise ToolError("file must use '/' as the separator, not backslashes")
    if value.startswith("/"):
        raise ToolError("file must be relative to the outbox, not absolute")
    parts = tuple(value.split("/"))
    for part in parts:
        if not part:
            raise ToolError("file must not contain empty path components")
        if part in (".", ".."):
            raise ToolError("file must not contain '.' or '..' components")
        if part.startswith("."):
            raise ToolError("file must not name hidden files or directories (starting with '.')")
        if len(part.encode("utf-8")) > MAX_COMPONENT_BYTES:
            raise ToolError(f"path components must be at most {MAX_COMPONENT_BYTES} bytes")
    if len(parts[-1]) > MAX_NAME_CHARS:
        raise ToolError(f"the file name must be at most {MAX_NAME_CHARS} characters")
    return parts


def read_outbox_file(outbox: str | os.PathLike[str], parts: tuple[str, ...], max_bytes: int) -> bytes:
    """Read outbox/parts without following a symlink at any level, within the size cap."""
    try:
        dir_fd = os.open(outbox, _DIR_FLAGS)
    except OSError:
        raise ToolError("the outbox cannot be opened") from None
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        file_fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        raise ToolError("file not found in the outbox") from None
    except OSError:
        # ELOOP and ENOTDIR: a symlink, or a file used as a directory.
        raise ToolError("file cannot be opened: paths through symlinks or non-directories are refused") from None
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode):
            raise ToolError("file is not a regular file")
        # A second name for the inode could be an alias of a file from outside the outbox.
        if st.st_nlink != 1:
            raise ToolError("file has more than one hard link")
        if st.st_uid not in (os.getuid(), 0):
            raise ToolError("file is not owned by the server's user")
        if st.st_size == 0:
            raise ToolError("file is empty")
        if st.st_size > max_bytes:
            raise ToolError(f"file is larger than the {max_bytes} byte limit")
        try:
            with os.fdopen(file_fd, "rb", closefd=False) as fh:
                data = fh.read(max_bytes + 1)
        except OSError:
            raise ToolError("file could not be read") from None
    finally:
        os.close(file_fd)
    if len(data) > max_bytes:
        raise ToolError(f"file is larger than the {max_bytes} byte limit")
    if not data:
        raise ToolError("file is empty")
    return data


def _sniff(head: bytes) -> str | None:
    """Identify an allowed binary type from the first bytes. Plain text has no signature and returns None."""
    media_type = media.sniff(head)
    if media_type in _MEDIA_SNIFFED:
        return media_type
    if head[4:8] == b"ftyp" and head[8:12] == b"M4A ":
        return "audio/mp4"
    if head.startswith(b"ID3") or (
        # MPEG audio frame sync: 11 set bits, with the reserved version and layer values excluded.
        len(head) >= 2
        and head[0] == 0xFF
        and head[1] & 0xE0 == 0xE0
        and (head[1] >> 3) & 3 != 1
        and (head[1] >> 1) & 3 != 0
    ):
        return "audio/mpeg"
    if head.startswith(b"OggS"):
        return "audio/ogg"
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith(b"PK\x03\x04"):
        return _ZIP
    return None


def _check_ooxml(data: bytes, directory: str) -> None:
    """Look at the zip directory only: nothing is extracted or decompressed.

    The end-of-central-directory record is read by hand first, so an archive claiming a huge entry count
    is refused before zipfile builds its in-memory index of it."""
    tail = data[-(65535 + 22) :]
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or at + 22 > len(tail):
        raise ToolError("the file is not a valid Office document")
    disk_entries, entries, size, offset = struct.unpack_from("<HHII", tail, at + 8)
    if 0xFFFF in (disk_entries, entries) or 0xFFFFFFFF in (size, offset) or entries > MAX_ZIP_ENTRIES:
        raise ToolError("the file is not a valid Office document")
    # The count alone does not bound what zipfile parses: it reads every record in the declared directory size.
    # Walk at most `entries` record headers and require that they end exactly at the end record.
    end = len(data) - len(tail) + at
    pos = end - size
    if pos < 0:
        raise ToolError("the file is not a valid Office document")
    for _ in range(entries):
        if pos + 46 > end or data[pos : pos + 4] != b"PK\x01\x02":
            raise ToolError("the file is not a valid Office document")
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, pos + 28)
        pos += 46 + name_len + extra_len + comment_len
    if pos != end:
        raise ToolError("the file is not a valid Office document")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, ValueError, OSError, RuntimeError):
        raise ToolError("the file is not a valid Office document") from None
    if len(names) > MAX_ZIP_ENTRIES or "[Content_Types].xml" not in names:
        raise ToolError("the file is not a valid Office document")
    if not any(name.startswith(directory) for name in names):
        raise ToolError("the file is not a valid Office document")


_M4A_REFUSED = "an .m4a file must be audio-only: an MP4 container with an audio track and no video track"
MAX_ISO_BOXES = 10_000


def _iso_boxes(data: bytes, start: int, end: int, budget: list[int]):
    """Yield (type, payload start, box end) for the ISO BMFF boxes in data[start:end]; malformed sizes refuse."""
    while start < end:
        budget[0] -= 1
        if budget[0] < 0 or start + 8 > end:
            raise ToolError(_M4A_REFUSED)
        size, kind, header = int.from_bytes(data[start : start + 4]), data[start + 4 : start + 8], 8
        if size == 1:
            if start + 16 > end:
                raise ToolError(_M4A_REFUSED)
            size, header = int.from_bytes(data[start + 8 : start + 16]), 16
        elif size == 0:
            size = end - start
        if size < header or start + size > end:
            raise ToolError(_M4A_REFUSED)
        yield kind, start + header, start + size
        start += size


def _check_audio_only(data: bytes) -> None:
    """The brand of an MP4 file says little (many AAC files use isom or mp42), so the track handlers decide."""
    budget = [MAX_ISO_BOXES]
    handlers: list[bytes] = []
    for kind, start, end in _iso_boxes(data, 0, len(data), budget):
        if kind != b"moov":
            continue
        for trak, t_start, t_end in _iso_boxes(data, start, end, budget):
            if trak != b"trak":
                continue
            for mdia, m_start, m_end in _iso_boxes(data, t_start, t_end, budget):
                if mdia != b"mdia":
                    continue
                for hdlr, h_start, h_end in _iso_boxes(data, m_start, m_end, budget):
                    # hdlr payload: version and flags (4), pre_defined (4), handler_type (4).
                    if hdlr == b"hdlr" and h_end - h_start >= 12:
                        handlers.append(data[h_start + 8 : h_start + 12])
    if b"soun" not in handlers or b"vide" in handlers:
        raise ToolError(_M4A_REFUSED)


def classify(name: str, data: bytes) -> tuple[str, str, str]:
    """Return (mime, wacli kind, extension) when name and content agree on an allowed type."""
    ext = os.path.splitext(name)[1].lower()
    declared = TYPES.get(ext)
    sniffed = _sniff(data[:16])
    if sniffed is None:
        if declared is None or declared[0] not in _TEXT_MIMES:
            raise ToolError(f"this file type is not allowed; allowed types: {ALLOWED_TYPES}")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise ToolError("text files must be valid UTF-8") from None
        if b"\x00" in data:
            raise ToolError("text files must not contain NUL bytes")
        return declared[0], declared[1], ext
    if declared is None:
        raise ToolError(f"this file type is not allowed; allowed types: {ALLOWED_TYPES}")
    if declared[0] == "audio/mp4" and data[4:8] == b"ftyp":
        _check_audio_only(data)
        return declared[0], declared[1], ext
    matches = declared[0] in _OOXML_MIMES if sniffed == _ZIP else declared[0] == sniffed
    if not matches:
        raise ToolError("the file extension does not match the file content")
    if sniffed == _ZIP:
        _check_ooxml(data, _OOXML_DIRS[declared[0]])
    return declared[0], declared[1], ext


def load(outbox: str | os.PathLike[str], value: object, max_bytes: int) -> OutboxFile:
    """Validate the path, read the file and classify it. Blocking: run it in a thread."""
    parts = validate_path(value)
    data = read_outbox_file(outbox, parts, max_bytes)
    mime, kind, ext = classify(parts[-1], data)
    return OutboxFile(data, hashlib.sha256(data).hexdigest(), mime, kind, parts[-1], ext)
