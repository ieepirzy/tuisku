"""Command line: `tuisku api` and `tuisku migrate`."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from pydantic import ValidationError

from tuisku.config import ConfigError, Settings


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tuisku")
    sub = parser.add_subparsers(dest="command", required=True)

    api = sub.add_parser("api", help="serve the HTTP API (never runs migrations)")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8080)

    sub.add_parser("migrate", help="apply database migrations (alembic upgrade head)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("alembic.runtime.plugins").setLevel(logging.WARNING)
    try:
        settings = Settings()
        if args.command == "api":
            import uvicorn

            from tuisku.api.app import create_app

            uvicorn.run(create_app(settings), host=args.host, port=args.port)
        elif args.command == "migrate":
            from tuisku.migrate import run_migrations

            run_migrations(settings)
    except (ConfigError, ValidationError) as exc:
        # Settings hide input values in errors, so this never prints secrets.
        print(f"tuisku: configuration error: {exc}", file=sys.stderr)
        return 2
    return 0
