"""Reads photos and videos that wacli already downloaded into the local media directory.

Nothing here talks to WhatsApp. `wacli media download` fetches from the
WhatsApp CDN even with --read-only, so it stays off the command allowlist and
only files already on disk can be served.

The path comes from the wacli database, and the file name inside it can
originate from the sender, so it is treated as untrusted: it must sit lexically
under the media root, every component is opened with O_NOFOLLOW relative to the
previous directory descriptor (no symlink at any level, no TOCTOU between check
and open), and the bytes themselves must look like a photo or video.
"""

from __future__ import annotations

import fcntl
import os
import re
import secrets
import shutil
import stat
import time
from pathlib import Path, PurePosixPath

MESSAGE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")

SERVED_MEDIA_TYPES = frozenset({"image", "video"})

# ISO base media brands that are video. Audio (M4A) and still images (HEIC, AVIF)
# share the container and are deliberately absent.
_VIDEO_BRANDS = {
    **dict.fromkeys(
        (b"isom", b"iso2", b"iso4", b"iso5", b"iso6", b"mp41", b"mp42", b"avc1", b"dash", b"mmp4", b"MSNV"),
        "video/mp4",
    ),
    **dict.fromkeys((b"M4V ", b"M4VH", b"M4VP"), "video/mp4"),
    **dict.fromkeys((b"3gp4", b"3gp5", b"3gp6", b"3gp7", b"3ge6", b"3gg6"), "video/3gpp"),
    b"qt  ": "video/quicktime",
}

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK keeps a FIFO planted under the media root from hanging the open.
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY


class MediaError(Exception):
    """A refusal whose message is safe to show to the model (no local paths)."""


class AlreadySaved(MediaError):
    """Another call or process saved the same message first."""


def sniff(head: bytes) -> str | None:
    """Identify an allowed photo or video type from its first bytes, or None."""
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return _VIDEO_BRANDS.get(head[8:12])
    return None


def media_roots(media_dir: Path, store_dir: Path | None) -> tuple[Path, ...]:
    """Spellings of the media root that a wacli LocalPath may start with.

    The first entry is the configured directory, which is the one opened. The
    others are only compared lexically, so resolving them here never redirects reads.
    """
    real = Path(os.path.realpath(media_dir))
    roots = [media_dir, real]
    if store_dir is not None and Path(os.path.realpath(store_dir / "media")) == real:
        roots.append(store_dir / "media")
    return tuple(dict.fromkeys(roots))


def relative_parts(local_path: str, roots: tuple[Path, ...]) -> tuple[str, ...]:
    """Split a LocalPath into components below one of the roots, refusing anything else."""
    if not local_path:
        raise MediaError("this media is not downloaded locally; this server cannot fetch from WhatsApp")
    if "\x00" in local_path:
        raise MediaError("the media path is invalid")
    pure = PurePosixPath(local_path)
    if not pure.is_absolute() or ".." in pure.parts:
        raise MediaError("the media file is outside the configured media directory")
    for root in roots:
        try:
            rel = pure.relative_to(PurePosixPath(root))
        except ValueError:
            continue
        if rel.parts:
            return rel.parts
    raise MediaError("the media file is outside the configured media directory")


def read_media_file(root: Path, parts: tuple[str, ...], max_bytes: int) -> bytes:
    """Read root/parts without following any symlink below root and within the size cap."""
    try:
        dir_fd = os.open(root, _DIR_FLAGS)
    except OSError as exc:
        raise MediaError("the media directory cannot be opened") from exc
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        file_fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        # ELOOP/ENOTDIR here mean a symlink was met; ENOENT a missing file.
        raise MediaError("the media file is missing or is reached through a symlink") from exc
    finally:
        os.close(dir_fd)

    # Vet the descriptor before wrapping it: Python refuses to wrap a directory at all.
    try:
        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode):
            raise MediaError("the media path is not a regular file")
        # A second name for the inode could be an alias of a file from another chat.
        if st.st_nlink != 1:
            raise MediaError("the media file has more than one hard link")
        if st.st_uid != os.getuid():
            raise MediaError("the media file is not owned by the server's user")
        if st.st_size > max_bytes:
            raise MediaError(f"the media file is larger than the {max_bytes} byte limit")
    except BaseException:
        os.close(file_fd)
        raise
    try:
        with os.fdopen(file_fd, "rb", closefd=True) as fh:
            data = fh.read(max_bytes + 1)
    except OSError as exc:
        raise MediaError("the media file could not be read") from exc
    if len(data) > max_bytes:
        raise MediaError(f"the media file is larger than the {max_bytes} byte limit")
    if not data:
        raise MediaError("the media file is empty")
    return data


EXTENSIONS = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "video/mp4": ".mp4",
    "video/3gpp": ".3gp",
    "video/quicktime": ".mov",
}


# What wacli accepts as a WhatsApp direct path. Anything else could steer the
# download URL away from WhatsApp's CDN host, so it never reaches the network.
DIRECT_PATH_RE = re.compile(r"/(?:o1/)?v/[A-Za-z0-9._~%/-]+(?:\?[A-Za-z0-9._~%=&+-]*)?")
# wacli joins the direct path to its CDN host, so dot segments, empty segments and
# encoded dots or slashes could still reshape the URL path after it passes the pattern.
_DIRECT_PATH_TRICKS = re.compile(r"\.\.|//|%2[ef]", re.IGNORECASE)


def valid_direct_path(value: object) -> bool:
    return isinstance(value, str) and bool(DIRECT_PATH_RE.fullmatch(value)) and not _DIRECT_PATH_TRICKS.search(value)


def saved_stem(group: str, msg_id: str, account: str | None = None) -> str:
    """Server-chosen file name. Group JIDs and message IDs may both contain '-' but never '.',
    so '.' keeps every (group, message) pair on its own name.

    With several accounts the alias (which never contains '.') comes first, so one account
    can never be served another account's copy of the same message."""
    stem = f"{group.split('@', 1)[0]}.{msg_id}"
    return stem if account is None else f"{account}.{stem}"


def _open_dir(directory: Path) -> int:
    try:
        return os.open(directory, _DIR_FLAGS)
    except OSError as exc:
        raise MediaError("the download directory cannot be opened") from exc


def find_saved(directory: Path, stem: str, max_bytes: int) -> tuple[str, bytes] | None:
    """Return (name, bytes) of an earlier download of this message, or None if there is none."""
    dir_fd = _open_dir(directory)
    try:
        for ext in dict.fromkeys(EXTENSIONS.values()):
            try:
                os.stat(stem + ext, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise MediaError("the download directory cannot be read") from exc
            return stem + ext, read_media_file(directory, (stem + ext,), max_bytes)
    finally:
        os.close(dir_fd)
    return None


def read_single_file(directory: Path, max_bytes: int) -> bytes:
    """Read the one file wacli wrote into a fresh private directory."""
    try:
        entries = os.listdir(directory)
    except OSError as exc:
        raise MediaError("the download could not be read") from exc
    if len(entries) != 1:
        raise MediaError("wacli did not produce exactly one file")
    return read_media_file(directory, (entries[0],), max_bytes)


def save_new_file(directory: Path, name: str, data: bytes) -> None:
    """Write data as directory/name (mode 0600) without ever replacing or following an existing entry."""
    dir_fd = _open_dir(directory)
    # Unique per attempt, so a leftover from a killed process can never block a later save.
    part = f".{name}.{secrets.token_hex(8)}.part"
    try:
        try:
            fd = os.open(
                part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd
            )
        except OSError as exc:
            raise MediaError("the downloaded file could not be saved") from exc
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            # link() fails if the name exists, unlike rename(), which would replace it.
            os.link(part, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
        except FileExistsError as exc:
            raise AlreadySaved("a file with the download's name already exists") from exc
        except OSError as exc:
            raise MediaError("the downloaded file could not be saved") from exc
        finally:
            # Always, so a failed write never leaves a .part that blocks the next attempt.
            try:
                os.unlink(part, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(dir_fd)


def save_within_capacity(directory: Path, name: str, data: bytes, max_total_bytes: int) -> None:
    """save_new_file, but refused when the directory would end up over max_total_bytes.

    The check and the write happen under an exclusive lock, so several server processes sharing the
    directory cannot each pass the check and together go over the limit.
    """
    dir_fd = _open_dir(directory)
    try:
        try:
            lock_fd = os.open(
                ".capacity.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd
            )
        except OSError as exc:
            raise MediaError("the download directory cannot be locked") from exc
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            # A copy another process saved meanwhile counts toward usage; it must be served, not called "full".
            try:
                os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise MediaError("the download directory cannot be read") from exc
            else:
                raise AlreadySaved("a file with the download's name already exists")
            if directory_usage(directory) + len(data) > max_total_bytes:
                raise MediaError("the download directory is full (WACLI_MCP_MAX_DOWNLOAD_DIR_BYTES)")
            save_new_file(directory, name, data)
        finally:
            os.close(lock_fd)  # also drops the lock
    finally:
        os.close(dir_fd)


def directory_usage(directory: Path) -> int:
    """Total size of the regular files directly in directory (symlinks are not followed)."""
    total = 0
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                except FileNotFoundError:
                    continue  # removed by a concurrent download's cleanup
    except OSError as exc:
        raise MediaError("the download directory cannot be read") from exc
    return total


def remove_stale(directory: Path, max_age_s: float) -> None:
    """Delete leftovers of interrupted downloads: .download-* directories and .*.part files.

    Only entries older than max_age_s go, because another server process sharing the
    directory may be in the middle of a download right now.
    """
    cutoff = time.time() - max_age_s
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return
    for entry in entries:
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
            if entry.name.startswith(".download-") and is_dir:
                stale = entry.stat(follow_symlinks=False).st_mtime < cutoff
                if stale:
                    shutil.rmtree(entry.path, ignore_errors=True)
            elif entry.name.startswith(".") and entry.name.endswith(".part") and not is_dir:
                if entry.stat(follow_symlinks=False).st_mtime < cutoff:
                    os.unlink(entry.path)
        except OSError:
            continue
