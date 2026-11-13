"""Configuration of file sending: the outbox, the staging directory and the size limit."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import ADA, BOOK_CLUB

from wacli_mcp.config import Config, ConfigError

MIB = 1024 * 1024


def private_dir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    return path


def env_for(fake, tmp_path, **extra) -> dict[str, str]:
    return {
        "HOME": str(fake.home),
        "WACLI_MCP_BIN": str(fake.path),
        "WACLI_MCP_NETWORK_ISOLATION": "off",
        "WACLI_MCP_STORE": str(fake.home),
        "WACLI_MCP_ENABLE_SEND": "1",
        "WACLI_MCP_SEND_RECIPIENTS": f"ada={ADA}, club={BOOK_CLUB}",
        "WACLI_MCP_ENABLE_SEND_FILES": "1",
        "WACLI_MCP_SEND_FILE_DIR": str(private_dir(tmp_path / "outbox")),
        "WACLI_MCP_SEND_STAGING_DIR": str(private_dir(tmp_path / "staging")),
        **extra,
    }


def test_file_sending_is_off_by_default(fake, tmp_path):
    env = env_for(fake, tmp_path)
    del env["WACLI_MCP_ENABLE_SEND_FILES"]
    cfg = Config.from_env(env)
    assert cfg.send_enabled and not cfg.send_files_enabled
    assert cfg.send_file_dir is None and cfg.send_staging_dir is None


def test_file_settings_from_env(fake, tmp_path):
    cfg = Config.from_env(env_for(fake, tmp_path))
    assert cfg.send_files_enabled
    assert cfg.send_file_dir == (tmp_path / "outbox").resolve()
    assert cfg.send_staging_dir == (tmp_path / "staging").resolve()
    assert cfg.send_file_max_bytes == 16 * MIB


def test_directories_are_resolved(fake, tmp_path):
    (tmp_path / "real-outbox").mkdir(mode=0o700)
    (tmp_path / "link").symlink_to(tmp_path / "real-outbox")
    cfg = Config.from_env(env_for(fake, tmp_path, WACLI_MCP_SEND_FILE_DIR=str(tmp_path / "link")))
    assert cfg.send_file_dir == (tmp_path / "real-outbox").resolve()


def test_files_need_text_sending(fake, tmp_path):
    env = env_for(fake, tmp_path)
    del env["WACLI_MCP_ENABLE_SEND"]
    with pytest.raises(ConfigError, match="requires WACLI_MCP_ENABLE_SEND=1"):
        Config.from_env(env)


def test_invalid_flag_value(fake, tmp_path):
    with pytest.raises(ConfigError, match="WACLI_MCP_ENABLE_SEND_FILES must be 1 or 0"):
        Config.from_env(env_for(fake, tmp_path, WACLI_MCP_ENABLE_SEND_FILES="sure"))


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("WACLI_MCP_SEND_FILE_DIR", "", "requires WACLI_MCP_SEND_FILE_DIR"),
        ("WACLI_MCP_SEND_FILE_DIR", "outbox", "WACLI_MCP_SEND_FILE_DIR must be absolute"),
        ("WACLI_MCP_SEND_FILE_DIR", "/nonexistent/outbox", "does not exist"),
        ("WACLI_MCP_SEND_STAGING_DIR", "", "requires WACLI_MCP_SEND_STAGING_DIR"),
        ("WACLI_MCP_SEND_STAGING_DIR", "staging", "WACLI_MCP_SEND_STAGING_DIR must be absolute"),
        ("WACLI_MCP_SEND_STAGING_DIR", "/nonexistent/staging", "does not exist"),
        ("WACLI_MCP_SEND_FILE_MAX_BYTES", "1023", "between 1024 and"),
        ("WACLI_MCP_SEND_FILE_MAX_BYTES", str(100 * MIB + 1), "between 1024 and"),
        ("WACLI_MCP_SEND_FILE_MAX_BYTES", "lots", "must be an integer"),
    ],
)
def test_file_config_errors(fake, tmp_path, key, value, message):
    with pytest.raises(ConfigError, match=message):
        Config.from_env(env_for(fake, tmp_path, **{key: value}))


def test_max_bytes_bounds_are_inclusive(fake, tmp_path):
    assert Config.from_env(env_for(fake, tmp_path, WACLI_MCP_SEND_FILE_MAX_BYTES="1024")).send_file_max_bytes == 1024
    top = str(100 * MIB)
    assert Config.from_env(env_for(fake, tmp_path, WACLI_MCP_SEND_FILE_MAX_BYTES=top)).send_file_max_bytes == 100 * MIB


@pytest.mark.parametrize("mode", [0o770, 0o707, 0o777])
def test_outbox_must_not_be_writable_by_others(fake, tmp_path, mode):
    env = env_for(fake, tmp_path)
    Path(env["WACLI_MCP_SEND_FILE_DIR"]).chmod(mode)
    with pytest.raises(ConfigError, match="WACLI_MCP_SEND_FILE_DIR .* writable by group or others"):
        Config.from_env(env)


@pytest.mark.parametrize("mode", [0o750, 0o705, 0o770, 0o777, 0o710])
def test_staging_must_have_no_group_or_other_bits(fake, tmp_path, mode):
    env = env_for(fake, tmp_path)
    Path(env["WACLI_MCP_SEND_STAGING_DIR"]).chmod(mode)
    with pytest.raises(ConfigError, match="WACLI_MCP_SEND_STAGING_DIR .* must not be accessible by group or others"):
        Config.from_env(env)


def test_staging_must_not_be_the_outbox(fake, tmp_path):
    env = env_for(fake, tmp_path)
    env["WACLI_MCP_SEND_STAGING_DIR"] = env["WACLI_MCP_SEND_FILE_DIR"]
    with pytest.raises(ConfigError, match="must not be the outbox, inside it, or contain it"):
        Config.from_env(env)


def test_staging_must_not_be_inside_the_outbox(fake, tmp_path):
    env = env_for(fake, tmp_path)
    env["WACLI_MCP_SEND_STAGING_DIR"] = str(private_dir(Path(env["WACLI_MCP_SEND_FILE_DIR"]) / "staging"))
    with pytest.raises(ConfigError, match="must not be the outbox, inside it, or contain it"):
        Config.from_env(env)


def test_staging_must_not_contain_the_outbox(fake, tmp_path):
    staging = private_dir(tmp_path / "staging")
    env = env_for(fake, tmp_path, WACLI_MCP_SEND_STAGING_DIR=str(staging))
    env["WACLI_MCP_SEND_FILE_DIR"] = str(private_dir(staging / "outbox"))
    with pytest.raises(ConfigError, match="must not be the outbox, inside it, or contain it"):
        Config.from_env(env)


def test_staging_overlap_is_checked_after_resolving_symlinks(fake, tmp_path):
    env = env_for(fake, tmp_path)
    (tmp_path / "alias").symlink_to(env["WACLI_MCP_SEND_FILE_DIR"])
    env["WACLI_MCP_SEND_STAGING_DIR"] = str(tmp_path / "alias")
    with pytest.raises(ConfigError, match="must not be the outbox, inside it, or contain it"):
        Config.from_env(env)


def test_staging_path_must_not_contain_the_path_list_separator(fake, tmp_path):
    # The path is passed to wacli in WACLI_MEDIA_ROOTS, a list separated by this character.
    odd = private_dir(tmp_path / "a:b")
    with pytest.raises(ConfigError, match="must not contain ':'"):
        Config.from_env(env_for(fake, tmp_path, WACLI_MCP_SEND_STAGING_DIR=str(odd)))


def test_file_settings_are_ignored_while_files_are_off(fake, tmp_path):
    env = env_for(fake, tmp_path, WACLI_MCP_SEND_FILE_DIR="relative", WACLI_MCP_ENABLE_SEND_FILES="0")
    assert Config.from_env(env).send_files_enabled is False


def accounts_file(tmp_path: Path, stores: dict[str, Path], recipients_for: tuple[str, ...]) -> Path:
    body = ""
    for name, store in stores.items():
        body += f'[accounts.{name}]\nstore = "{store}"\n'
        if name in recipients_for:
            body += f'[accounts.{name}.send]\nrecipients = {{ ada = "{ADA}" }}\n'
    path = tmp_path / "accounts.toml"
    path.write_text(body)
    path.chmod(0o600)
    return path


def multi_env(fake, tmp_path, recipients_for) -> dict[str, str]:
    stores = {}
    for name in ("personal", "work"):
        stores[name] = tmp_path / "stores" / name
        stores[name].mkdir(parents=True, mode=0o700)
    env = env_for(fake, tmp_path, WACLI_MCP_ACCOUNTS_FILE=str(accounts_file(tmp_path, stores, recipients_for)))
    for key in ("WACLI_MCP_STORE", "WACLI_MCP_SEND_RECIPIENTS"):
        del env[key]
    return env


def test_account_views_inherit_file_settings_only_when_they_can_send(fake, tmp_path):
    cfg = Config.from_env(multi_env(fake, tmp_path, ("personal",)))
    assert cfg.send_files_enabled
    personal, work = cfg.account_views()
    assert personal.send_enabled and personal.send_files_enabled
    assert personal.send_file_dir == cfg.send_file_dir and personal.send_staging_dir == cfg.send_staging_dir
    assert personal.send_file_max_bytes == cfg.send_file_max_bytes
    assert not work.send_enabled and not work.send_files_enabled


def test_multi_account_files_need_text_sending(fake, tmp_path):
    env = multi_env(fake, tmp_path, ("personal",))
    del env["WACLI_MCP_ENABLE_SEND"]
    with pytest.raises(ConfigError, match="requires WACLI_MCP_ENABLE_SEND=1"):
        Config.from_env(env)
