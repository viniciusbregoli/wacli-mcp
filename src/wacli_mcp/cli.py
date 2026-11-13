"""Command-line entry point: `wacli-mcp [stdio|http|check]`."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .config import Config, ConfigError, HttpConfig
from .runner import WacliError, WacliRunner
from .server import build_server
from .shaping import shape_doctor


def _store_label(view: Config) -> str:
    if view.store_dir:
        return str(view.store_dir)
    if view.account:
        return f"account:{view.account}"
    return "wacli default (follows wacli's default_account; set WACLI_MCP_STORE to pin it)"


def _check(cfg: Config) -> int:
    """Validate the configuration and run a local `doctor` per account (no WhatsApp connection)."""
    runner = WacliRunner(cfg)

    async def doctor_all() -> list[tuple[Config, object]]:
        return [(view, await runner.run(["doctor"], target=view)) for view in cfg.account_views()]

    try:
        results = asyncio.run(doctor_all())
    except WacliError as exc:
        print(f"wacli doctor failed: {exc}", file=sys.stderr)
        return 1
    reports = []
    for view, data in results:
        report = {
            "store": _store_label(view),
            "media_dir": str(view.media_dir) if view.media_dir else None,
            **shape_doctor(data, view),
        }
        if cfg.multi_account:
            report = {"account": view.alias, **({"label": view.label} if view.label else {}), **report}
        reports.append(report)
    if cfg.multi_account:
        print(json.dumps({"wacli_bin": str(cfg.wacli_bin), "accounts": reports}, indent=2))
    else:
        print(json.dumps({"wacli_bin": str(cfg.wacli_bin), **reports[0]}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wacli-mcp", description="MCP server over local wacli stores.")
    parser.add_argument("mode", nargs="?", choices=["stdio", "http", "check"], default="stdio")
    args = parser.parse_args(argv)

    # stdout carries the MCP protocol in stdio mode, so all logging goes to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format="wacli-mcp: %(levelname)s %(message)s")

    try:
        cfg = Config.from_env()
        http = HttpConfig.from_env() if args.mode == "http" else None
    except ConfigError as exc:
        print(f"wacli-mcp: configuration error: {exc}", file=sys.stderr)
        return 2

    if not cfg.network_isolated:
        logging.warning("network isolation is off: wacli children can reach the network")
    if not cfg.multi_account and cfg.store_dir is None and cfg.account is None:
        logging.warning(
            "no store pinned: wacli picks its default store, which changes if a default account is added; "
            "set WACLI_MCP_STORE"
        )

    if args.mode == "check":
        return _check(cfg)

    server = build_server(cfg)
    if http is not None:
        from .http import run_http

        run_http(server, http)
    else:
        server.run("stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
