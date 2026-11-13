"""Every parent of a directory the server trusts must be trusted too."""

from __future__ import annotations

import grp
import os
import pwd
import struct
from pathlib import Path

import pytest
from conftest import ADA

from wacli_mcp import config
from wacli_mcp.config import Config, ConfigError


def _check_ancestors(path, what):
    config._check_ancestors(path, what)


ME = pwd.getpwuid(os.getuid())


def make(path: Path, mode: int) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    return path


def only_me(monkeypatch, members=(), other_primary=False):
    """Pretend the user's private group has `members` and, if asked, another user whose primary group it is."""
    monkeypatch.setattr(config.grp, "getgrgid", lambda gid: grp.struct_group(("g", "x", gid, list(members))))
    others = [pwd.struct_passwd((n, "x", u, ME.pw_gid, "", "/", "/bin/sh")) for n, u in (("other", 4242),)]
    me = [pwd.struct_passwd((ME.pw_name, "x", ME.pw_uid, ME.pw_gid, "", "/", "/bin/sh"))]
    monkeypatch.setattr(config.pwd, "getpwall", lambda: me + (others if other_primary else []))


def test_a_world_writable_ancestor_is_refused(tmp_path):
    parent = make(tmp_path / "open", 0o777)
    with pytest.raises(ConfigError, match="writable by others"):
        _check_ancestors(make(parent / "dir", 0o700).resolve(), "X")


def test_a_sticky_world_writable_ancestor_is_accepted(tmp_path):
    parent = make(tmp_path / "sticky", 0o1777)
    _check_ancestors(make(parent / "dir", 0o700).resolve(), "X")


def test_an_ancestor_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(config.os, "getuid", lambda: 12345)
    with pytest.raises(ConfigError, match="owned by uid"):
        _check_ancestors(make(tmp_path / "dir", 0o700).resolve(), "X")


def test_a_group_writable_ancestor_of_a_shared_group_is_refused(tmp_path, monkeypatch):
    only_me(monkeypatch, members=(ME.pw_name, "someone-else"))
    parent = make(tmp_path / "shared", 0o775)
    with pytest.raises(ConfigError, match="group that has other members"):
        _check_ancestors(make(parent / "dir", 0o700).resolve(), "X")


def test_a_group_that_is_another_users_primary_group_is_refused(tmp_path, monkeypatch):
    only_me(monkeypatch, other_primary=True)
    parent = make(tmp_path / "shared", 0o775)
    with pytest.raises(ConfigError, match="group that has other members"):
        _check_ancestors(make(parent / "dir", 0o700).resolve(), "X")


def test_a_group_other_than_the_users_primary_group_is_refused(tmp_path, monkeypatch):
    only_me(monkeypatch)
    monkeypatch.setattr(
        config.pwd, "getpwuid", lambda uid: pwd.struct_passwd((ME.pw_name, "x", uid, 99999, "", "/", "/"))
    )
    parent = make(tmp_path / "shared", 0o775)
    with pytest.raises(ConfigError, match="group that has other members"):
        _check_ancestors(make(parent / "dir", 0o700).resolve(), "X")


def test_the_users_private_group_may_write_an_ancestor(tmp_path, monkeypatch):
    only_me(monkeypatch)
    parent = make(tmp_path / ".local", 0o775)
    _check_ancestors(make(parent / "state", 0o775).resolve(), "X")
    only_me(monkeypatch, members=(ME.pw_name,))
    _check_ancestors((parent / "state").resolve(), "X")


def test_the_path_itself_is_not_an_ancestor(tmp_path):
    _check_ancestors(make(tmp_path / "dir", 0o777).resolve(), "X")


def env_for(fake, tmp_path, **extra) -> dict[str, str]:
    return {
        "HOME": str(fake.home),
        "WACLI_MCP_BIN": str(fake.path),
        "WACLI_MCP_NETWORK_ISOLATION": "off",
        **extra,
    }


def test_an_explicit_media_dir_under_an_open_ancestor_is_refused(fake, tmp_path):
    media = make(make(tmp_path / "open", 0o777) / "media", 0o700)
    with pytest.raises(ConfigError, match="WACLI_MCP_MEDIA_DIR.*writable by others"):
        Config.from_env(env_for(fake, tmp_path, WACLI_MCP_MEDIA_DIR=str(media)))


def test_an_auto_detected_media_dir_under_an_open_ancestor_only_disables_media(fake, tmp_path):
    store = make(make(tmp_path / "open", 0o777) / "store", 0o700)
    make(store / "media", 0o700)
    assert Config.from_env(env_for(fake, tmp_path, WACLI_MCP_STORE=str(store))).media_dir is None


def test_the_download_dir_under_an_open_ancestor_is_refused(fake, tmp_path):
    downloads = make(make(tmp_path / "open", 0o777) / "downloads", 0o700)
    with pytest.raises(ConfigError, match="WACLI_MCP_DOWNLOAD_DIR.*writable by others"):
        Config.from_env(
            env_for(fake, tmp_path, WACLI_MCP_ALLOW_MEDIA_DOWNLOAD="1", WACLI_MCP_DOWNLOAD_DIR=str(downloads))
        )


@pytest.mark.parametrize("which", ["WACLI_MCP_SEND_FILE_DIR", "WACLI_MCP_SEND_STAGING_DIR"])
def test_the_outbox_and_staging_under_an_open_ancestor_are_refused(fake, tmp_path, which):
    env = env_for(
        fake,
        tmp_path,
        WACLI_MCP_STORE=str(fake.home),
        WACLI_MCP_ENABLE_SEND="1",
        WACLI_MCP_SEND_RECIPIENTS=f"ada={ADA}",
        WACLI_MCP_ENABLE_SEND_FILES="1",
        WACLI_MCP_SEND_FILE_DIR=str(make(tmp_path / "outbox", 0o700)),
        WACLI_MCP_SEND_STAGING_DIR=str(make(tmp_path / "staging", 0o700)),
    )
    env[which] = str(make(make(tmp_path / "open", 0o777) / "d", 0o700))
    with pytest.raises(ConfigError, match=f"{which}.*writable by others"):
        Config.from_env(env)


# POSIX ACL extended attribute, as the Linux kernel stores it: a version, then (tag, perm, id) entries.
ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
NO_ID = 0xFFFFFFFF


def acl(*entries: tuple[int, int, int], version: int = 2) -> bytes:
    base = [(ACL_USER_OBJ, 7, NO_ID), (ACL_GROUP_OBJ, 5, NO_ID), (ACL_MASK, 7, NO_ID), (ACL_OTHER, 5, NO_ID)]
    return struct.pack("<I", version) + b"".join(struct.pack("<HHI", *e) for e in [*base, *entries])


def with_acl(monkeypatch, path: Path, value: bytes) -> None:
    real = os.getxattr

    def getxattr(target, name, *args, **kwargs):
        if Path(target) == path and name == "system.posix_acl_access":
            return value
        return real(target, name, *args, **kwargs)

    monkeypatch.setattr(config.os, "getxattr", getxattr)


def test_an_ancestor_whose_acl_lets_another_user_write_is_refused(tmp_path, monkeypatch):
    parent = make(tmp_path / "acl", 0o755)
    with_acl(monkeypatch, parent, acl((ACL_USER, 7, 4242)))
    with pytest.raises(ConfigError, match="access control list"):
        _check_ancestors(make(parent / "dir", 0o700).resolve(), "X")


def test_an_ancestor_whose_acl_lets_a_shared_group_write_is_refused(tmp_path, monkeypatch):
    parent = make(tmp_path / "acl", 0o755)
    with_acl(monkeypatch, parent, acl((ACL_GROUP, 3, 4343)))
    with pytest.raises(ConfigError, match="access control list"):
        _check_ancestors(make(parent / "dir", 0o700).resolve(), "X")


def test_an_acl_that_only_grants_read_or_names_the_user_is_accepted(tmp_path, monkeypatch):
    parent = make(tmp_path / "acl", 0o755)
    with_acl(monkeypatch, parent, acl((ACL_USER, 5, 4242), (ACL_USER, 7, os.getuid())))
    _check_ancestors(make(parent / "dir", 0o700).resolve(), "X")


def test_an_acl_in_an_unknown_format_is_refused(tmp_path, monkeypatch):
    parent = make(tmp_path / "acl", 0o755)
    with_acl(monkeypatch, parent, acl(version=3))
    with pytest.raises(ConfigError, match="access control list"):
        _check_ancestors(make(parent / "dir", 0o700).resolve(), "X")


def test_a_media_dir_whose_own_acl_lets_another_user_write_is_refused(tmp_path, monkeypatch):
    media = make(tmp_path / "media", 0o755).resolve()
    with_acl(monkeypatch, media, acl((ACL_USER, 2, 4242)))
    with pytest.raises(ConfigError, match="access control list"):
        config._media_dir(media, "WACLI_MCP_MEDIA_DIR")


def test_a_private_dir_whose_acl_lets_another_user_read_is_refused(tmp_path, monkeypatch):
    private = make(tmp_path / "private", 0o700).resolve()
    with_acl(monkeypatch, private, acl((ACL_USER, 4, 4242)))
    with pytest.raises(ConfigError, match="access control list"):
        config._private_dir(private, "WACLI_MCP_SEND_STAGING_DIR")
