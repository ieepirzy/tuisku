"""``tuisku worker``: load the packs, record them, then evaluate the queue."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from psycopg import AsyncConnection

from tuisku.adapters import builtin as _builtin_adapters  # noqa: F401  (registers adapters)
from tuisku.config import ConfigError, Settings
from tuisku.rules.packs import RuleSet, load_rule_set
from tuisku.worker import health, notify
from tuisku.worker.engine import Worker, WorkerConfig
from tuisku.worker.export import ExportConfig, Exporter

log = logging.getLogger(__name__)
MAX_BACKOFF_SECONDS = 60.0


def pack_roots(settings: Settings) -> list[Path]:
    """The configured (non-built-in) pack directories."""
    return [Path(p) for p in settings.rule_pack_paths.split(os.pathsep) if p.strip()]


def load_configured_rules(settings: Settings) -> RuleSet:
    params = Path(settings.rule_params_file) if settings.rule_params_file else None
    return load_rule_set(
        pack_roots(settings),
        params,
        builtin=[Path(settings.builtin_packs_dir)],
        require_rules=True,
    )


def worker_config(settings: Settings) -> WorkerConfig:
    return WorkerConfig(
        batch_size=settings.worker_batch_size,
        lease=timedelta(seconds=settings.worker_lease_seconds),
        statement_timeout_ms=int(settings.worker_statement_timeout_seconds * 1000),
        max_open_findings=settings.worker_max_open_findings,
        max_live_incidents=settings.worker_max_live_incidents,
        export_interval=timedelta(seconds=settings.worker_export_interval_seconds),
        allowed_lateness=timedelta(seconds=settings.worker_allowed_lateness_seconds),
        backlog_after=timedelta(seconds=settings.worker_backlog_seconds),
        notify_drain_budget=timedelta(seconds=settings.notify_drain_budget_seconds),
    )


def build_notifier(settings: Settings) -> notify.Notifier:
    """The structured log always; Alertmanager too when its URL is set (ADR 0007)."""
    if settings.notify_alertmanager_url is None:
        return notify.LogNotifier()
    from tuisku.worker.alertmanager import AlertmanagerNotifier

    return notify.FanOutNotifier(
        (
            notify.LogNotifier(),
            AlertmanagerNotifier(
                settings.notify_alertmanager_url,
                static_labels=settings.notify_alertmanager_labels_json,
                include_entities=settings.notify_alertmanager_include_entities,
                timeout_seconds=settings.notify_alertmanager_timeout_seconds,
            ),
        )
    )


def exporter(settings: Settings) -> Exporter:
    """The event exporter (ADR 0012). Always present: with export off it removes what was
    queued while it was on, and with export on it needs the pseudonym key (ADR 0008)."""
    url = settings.export_otlp_logs_url
    key = settings.export_pseudonym_key
    if url is not None and key is None:
        raise ConfigError(
            "TUISKU_EXPORT_PSEUDONYM_KEY is required with TUISKU_EXPORT_OTLP_LOGS_URL (ADR 0008)"
        )
    return Exporter(
        ExportConfig(
            url=url.get_secret_value() if url is not None else None,
            pseudonym_key=key.get_secret_value().encode() if key is not None else b"",
            pseudonymize_kinds=settings.export_pseudonymized_kinds,
            headers=settings.export_headers,
            batch_size=settings.export_batch_size,
            timeout_seconds=settings.export_timeout_seconds,
            build_revision=settings.build_revision,
            statement_timeout_seconds=settings.worker_statement_timeout_seconds,
        )
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
    exp = exporter(settings)
    worker = Worker(
        rule_set=rule_set,
        clock=_system_clock,
        config=worker_config(settings),
        notifier=build_notifier(settings),
    )
    if not exp.enabled:
        log.info("event export off (TUISKU_EXPORT_OTLP_LOGS_URL unset)")
    backlog_after = timedelta(seconds=settings.worker_backlog_seconds)

    async def connect() -> AsyncConnection:
        return await AsyncConnection.connect(
            settings.require_database_url(), autocommit=True, connect_timeout=5
        )

    async def main() -> None:
        server = None
        if settings.worker_health_port is not None and not once:
            server = await health.serve(
                lambda: worker.healthy_at,
                settings.worker_heartbeat_stale_seconds,
                settings.worker_health_host,
                settings.worker_health_port,
            )
        # The exporter runs beside evaluation, on its own connection, so a slow sink never
        # delays evaluation or paging (ADR 0012).
        export_task = None
        if not once:
            export_task = asyncio.create_task(
                exp.run_forever(connect, backlog_after, settings.worker_poll_seconds)
            )
        try:
            await loop()
            if once:
                conn = await connect()
                async with conn:
                    await exp.round(conn, backlog_after)
        finally:
            if export_task is not None:
                export_task.cancel()
            if server is not None:
                server.close()

    async def loop() -> None:
        deadman = settings.worker_deadman_url
        recorded = False
        failures = 0
        while True:
            try:
                conn = await AsyncConnection.connect(
                    settings.require_database_url(), autocommit=True, connect_timeout=5
                )
                async with conn:
                    if not recorded:
                        await worker.record_pack_loads(conn)
                        recorded = True
                    while True:
                        before = worker.healthy_at
                        stats = await worker.run_until_idle(conn)
                        failures = 0
                        if deadman is not None and worker.healthy_at != before:
                            # This round's passes ended healthy: tell the dead-man's switch.
                            await health.ping(deadman.get_secret_value())
                        if stats.claimed:
                            log.info("worker pass: %s", stats)
                        if once:
                            return
                        await asyncio.sleep(settings.worker_poll_seconds)
            except Exception as exc:  # one bad pass must not stop the worker
                failures += 1
                if once:
                    raise
                delay = min(MAX_BACKOFF_SECONDS, settings.worker_poll_seconds * 2**failures)
                log.exception(
                    "worker pass failed (%s); retrying in %.0fs", type(exc).__name__, delay
                )
                await asyncio.sleep(delay)

    asyncio.run(main())
    return 0
