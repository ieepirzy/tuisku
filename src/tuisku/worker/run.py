"""``tuisku worker``: load the packs, record them, then evaluate the queue."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from psycopg import AsyncConnection

from tuisku.adapters import builtin as _builtin_adapters  # noqa: F401  (registers adapters)
from tuisku.config import Settings
from tuisku.rules.packs import RuleSet, load_rule_set
from tuisku.worker.engine import Worker, WorkerConfig

log = logging.getLogger(__name__)


def pack_roots(settings: Settings) -> list[Path]:
    roots = [Path(settings.builtin_packs_dir)]
    roots += [Path(p) for p in settings.rule_pack_paths.split(os.pathsep) if p.strip()]
    return roots


def load_configured_rules(settings: Settings) -> RuleSet:
    params = Path(settings.rule_params_file) if settings.rule_params_file else None
    return load_rule_set(pack_roots(settings), params, require_rules=True)


def worker_config(settings: Settings) -> WorkerConfig:
    return WorkerConfig(
        batch_size=settings.worker_batch_size,
        lease=timedelta(seconds=settings.worker_lease_seconds),
        statement_timeout_ms=int(settings.worker_statement_timeout_seconds * 1000),
        max_open_findings=settings.worker_max_open_findings,
        max_live_incidents=settings.worker_max_live_incidents,
        export_interval=timedelta(seconds=settings.worker_export_interval_seconds),
        allowed_lateness=timedelta(seconds=settings.worker_allowed_lateness_seconds),
    )


def _system_clock() -> datetime:
    return datetime.now(UTC)


def run_worker(settings: Settings, *, once: bool = False, check_only: bool = False) -> int:
    rule_set = load_configured_rules(settings)
    for pack in rule_set.packs:
        log.info(
            "loaded pack %s@%s sha256=%s rules=%d",
            pack.info.id,
            pack.info.version,
            pack.info.sha256,
            len(pack.rules),
        )
    if check_only:
        return 0
    worker = Worker(rule_set=rule_set, clock=_system_clock, config=worker_config(settings))

    async def main() -> None:
        conn = await AsyncConnection.connect(
            settings.require_database_url(), autocommit=True, connect_timeout=5
        )
        async with conn:
            await worker.record_pack_loads(conn)
            while True:
                stats = await worker.run_until_idle(conn)
                if stats.claimed:
                    log.info("worker pass: %s", stats)
                if once:
                    return
                await asyncio.sleep(settings.worker_poll_seconds)

    asyncio.run(main())
    return 0
