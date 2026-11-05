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


def _check(cfg: Config) -> int:
    """Validate the configuration and run a local `doctor` (no WhatsApp connection)."""
    try:
        data = asyncio.run(WacliRunner(cfg).run(["doctor"]))
    except WacliError as exc:
        print(f"wacli doctor failed: {exc}", file=sys.stderr)
        return 1
    report = {
        "wacli_bin": str(cfg.wacli_bin),
        "store": str(cfg.store_dir)
        if cfg.store_dir
        else (f"account:{cfg.account}" if cfg.account else "wacli default"),
        **shape_doctor(data, cfg),
    }
    print(json.dumps(report, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wacli-mcp", description="Read-only MCP server over a local wacli store.")
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
