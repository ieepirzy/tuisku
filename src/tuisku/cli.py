"""Command line: `tuisku api`, `tuisku migrate`, and source / operator token administration.

New tokens are printed once, on stdout and nowhere else; only their SHA-256 is stored. Tokens
are never logged.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg import AsyncConnection
from pydantic import ValidationError

from tuisku.config import ConfigError, Settings


class UsageError(Exception):
    """Bad command-line input; printed without a traceback, exit status 2."""


def _key_value(text: str) -> tuple[str, str]:
    key, sep, value = text.partition("=")
    if not sep or not key:
        raise argparse.ArgumentTypeError(f"expected KEY=VALUE, got {text!r}")
    return key, value


def _key_json(text: str) -> tuple[str, Any]:
    key, value = _key_value(text)
    try:
        return key, json.loads(value)
    except json.JSONDecodeError:
        raise argparse.ArgumentTypeError(f"option {key!r}: value is not valid JSON") from None


def _timestamp(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an ISO 8601 timestamp: {text!r}") from None
    if value.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamp needs a UTC offset, e.g. 2027-01-01T00:00Z")
    return value


def _add_admin_commands(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    source = sub.add_parser("source", help="manage ingest sources and their tokens")
    source_sub = source.add_subparsers(dest="source_command", required=True)

    add = source_sub.add_parser("add", help="register a source and print its first token")
    add.add_argument("name")
    add.add_argument("--adapter", required=True)
    add.add_argument(
        "--option",
        action="append",
        default=[],
        type=_key_value,
        metavar="KEY=VALUE",
        help="adapter option with a string value (repeatable)",
    )
    add.add_argument(
        "--option-json",
        action="append",
        default=[],
        type=_key_json,
        metavar="KEY=JSON",
        help="adapter option with a JSON value (repeatable)",
    )
    add.add_argument("--token-label")
    add.add_argument("--token-expires-at", type=_timestamp)

    disable = source_sub.add_parser("disable", help="disable a source: its tokens stop working")
    disable.add_argument("name")

    token = source_sub.add_parser("token", help="manage a source's tokens")
    token_sub = token.add_subparsers(dest="token_command", required=True)
    token_add = token_sub.add_parser("add", help="add a token (printed once)")
    token_add.add_argument("source")
    token_add.add_argument("--label")
    token_add.add_argument("--expires-at", type=_timestamp)
    token_revoke = token_sub.add_parser("revoke", help="revoke a token by its uid")
    token_revoke.add_argument("source")
    token_revoke.add_argument("token_uid", type=UUID)
    token_list = token_sub.add_parser("list", help="list a source's tokens (never the secrets)")
    token_list.add_argument("source")

    op = sub.add_parser("operator-token", help="manage operator tokens")
    op_sub = op.add_subparsers(dest="operator_command", required=True)
    op_add = op_sub.add_parser("add", help="create an operator token (printed once)")
    op_add.add_argument("--name", required=True)
    op_add.add_argument(
        "--role",
        action="append",
        required=True,
        choices=["read", "triage", "admin"],
        help="repeatable; read < triage < admin (approve tokens: `tuisku approver add`)",
    )
    op_add.add_argument(
        "--person",
        help="bind the token to a named person; only the database owner may do this (ADR 0005)",
    )
    op_add.add_argument("--expires-at", type=_timestamp)
    op_sub.add_parser("list", help="list operator and approve tokens (never the secrets)")
    op_revoke = op_sub.add_parser("revoke", help="revoke an operator token by its uid")
    op_revoke.add_argument("token_uid", type=UUID)

    approver = sub.add_parser(
        "approver", help="issue approve tokens (database owner only, out of band; ADR 0005)"
    )
    approver_sub = approver.add_subparsers(dest="approver_command", required=True)
    approver_add = approver_sub.add_parser("add", help="create an approve token (printed once)")
    approver_add.add_argument("--person", required=True, help="the named person who approves")
    approver_add.add_argument("--name", help="a label for the token (default: the person)")
    approver_add.add_argument("--expires-at", type=_timestamp)
    approver_revoke = approver_sub.add_parser(
        "revoke", help="revoke an approve token (database owner only, out of band)"
    )
    approver_revoke.add_argument("token_uid", type=UUID)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tuisku")
    sub = parser.add_subparsers(dest="command", required=True)

    api = sub.add_parser("api", help="serve the HTTP API (never runs migrations)")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8080)

    sub.add_parser("migrate", help="apply database migrations (alembic upgrade head)")
    _add_admin_commands(sub)
    return parser


def _with_connection[T](
    settings: Settings, work: Callable[[AsyncConnection[Any]], Awaitable[T]]
) -> T:
    """Run ``work`` in one transaction on a fresh connection, committing on success."""

    async def run() -> T:
        conn = await AsyncConnection.connect(settings.require_database_url(), connect_timeout=5)
        async with conn:  # commits on success, rolls back on error, then closes
            return await work(conn)

    return asyncio.run(run())


def _print_token(token: str, what: str) -> None:
    print(token)  # stdout: the only place the token ever appears
    print(f"tuisku: {what}; store the token now, it is not shown again", file=sys.stderr)


def _run_admin(args: argparse.Namespace, settings: Settings) -> None:
    from tuisku import adapters
    from tuisku.adapters import builtin as _builtin  # noqa: F401  (registers adapters)
    from tuisku.store import admin
    from tuisku.store.tokens import Role

    if args.command == "approver" and args.approver_command == "revoke":
        _with_connection(
            settings,
            lambda conn: admin.revoke_operator_token(conn, args.token_uid, approver=True),
        )
        print(f"tuisku: revoked approve token {args.token_uid}", file=sys.stderr)
        return
    if args.command == "operator-token" and args.operator_command == "list":
        rows = _with_connection(settings, admin.list_operator_tokens)
        for row in rows:
            print(json.dumps(row, default=str, sort_keys=True))
        return
    if args.command == "operator-token" and args.operator_command == "revoke":
        _with_connection(settings, lambda conn: admin.revoke_operator_token(conn, args.token_uid))
        print(f"tuisku: revoked operator token {args.token_uid}", file=sys.stderr)
        return
    if args.command == "approver":
        issued = _with_connection(
            settings,
            lambda conn: admin.create_operator_token(
                conn,
                name=args.name or args.person,
                roles=[Role.APPROVE],
                person=args.person,
                expires_at=args.expires_at,
            ),
        )
        _print_token(issued.token, f"created approve token {issued.uid} for {args.person}")
        return
    if args.command == "operator-token":
        roles = [Role(r) for r in args.role]
        issued = _with_connection(
            settings,
            lambda conn: admin.create_operator_token(
                conn, name=args.name, roles=roles, person=args.person, expires_at=args.expires_at
            ),
        )
        _print_token(issued.token, f"created operator token {issued.uid}")
        return

    command = args.source_command
    if command == "add":
        if args.adapter not in adapters.names():
            available = ", ".join(adapters.names()) or "none"
            raise UsageError(f"unknown adapter {args.adapter!r} (available: {available})")
        options = dict(args.option) | dict(args.option_json)

        async def add(conn: AsyncConnection[Any]) -> tuple[Any, Any]:
            source = await admin.create_source(conn, args.name, args.adapter, options)
            issued = await admin.add_source_token(
                conn, args.name, label=args.token_label, expires_at=args.token_expires_at
            )
            return source, issued

        source, issued = _with_connection(settings, add)
        _print_token(issued.token, f"created source {source.name} with token {issued.uid}")
    elif command == "disable":
        _with_connection(settings, lambda conn: admin.disable_source(conn, args.name))
        print(f"tuisku: disabled source {args.name}", file=sys.stderr)
    elif args.token_command == "add":
        issued = _with_connection(
            settings,
            lambda conn: admin.add_source_token(
                conn, args.source, label=args.label, expires_at=args.expires_at
            ),
        )
        _print_token(issued.token, f"created token {issued.uid} for source {args.source}")
    elif args.token_command == "revoke":
        _with_connection(
            settings, lambda conn: admin.revoke_source_token(conn, args.source, args.token_uid)
        )
        print(f"tuisku: revoked token {args.token_uid}", file=sys.stderr)
    elif args.token_command == "list":
        rows = _with_connection(settings, lambda conn: admin.list_source_tokens(conn, args.source))
        for row in rows:
            print(json.dumps(row, default=str, sort_keys=True))


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
        else:
            _run_admin(args, settings)
    except (ConfigError, ValidationError) as exc:
        # Settings hide input values in errors, so this never prints secrets.
        print(f"tuisku: configuration error: {exc}", file=sys.stderr)
        return 2
    except UsageError as exc:
        print(f"tuisku: {exc}", file=sys.stderr)
        return 2
    except psycopg.errors.InsufficientPrivilege as exc:
        # e.g. a person-bound token requested without connecting as the database owner
        print(f"tuisku: refused by the database: {exc.diag.message_primary}", file=sys.stderr)
        return 1
    except LookupError as exc:  # store.admin.NotFoundError
        print(f"tuisku: {exc}", file=sys.stderr)
        return 1
    return 0
