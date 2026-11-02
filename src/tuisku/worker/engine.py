"""The rule worker (ADR 0006 "Evaluation").

One pass (:meth:`Worker.run_once`):

1. **Sweep**: expire findings past ``window`` or ``max_lifetime`` and lift expired
   suppressions (ADR 0007).
2. **Claim** a batch of queue rows in a short transaction that commits: ``FOR UPDATE SKIP
   LOCKED``, ``attempts + 1`` and a lease (``claimed_until``). Expired leases are claimable
   again, so a crashed worker loses nothing.
3. **Evaluate** each row in its own transaction. Rows of a non-current parse attempt are
   skipped. The worker matches every rule (pure Python), takes
   ``pg_advisory_xact_lock`` for every group key and rule key the row touches, **in sorted
   order**, then evaluates each *(row, rule)* pair under its own ``SAVEPOINT``. Deadlocks,
   serialization failures and lock timeouts are retried without counting as attempts. A pair
   that still fails is rolled back to its savepoint; after 5 counted attempts it is
   dead-lettered, raises a ``tuisku.meta.evaluation_failed`` meta-detection naming the rule and
   sends a notification. Attempts are counted per *(row, rule)* in ``evaluation_attempts``, so
   lease expiries and crashes never burn them; lock conflicts become counted failures after 20.
   The queue row is deleted once every rule has succeeded or been dead-lettered for it.
4. **Deliver** the notifications the committed transactions queued.

Idempotency: every firing and link inserts a ``rule_firings`` key (``(rule, rev, row)``, plus
``(rule, rev, group, window start)`` for correlations) in the same transaction as its effects,
and a row that already has a key for a rule is not evaluated again for it. A lease that
expires mid-evaluation therefore never writes a second detection or pages twice.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, LiteralString

import psycopg
from psycopg import AsyncConnection, errors, sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from tuisku import db
from tuisku.adapters import OCSF_VERSION
from tuisku.rules.fingerprint import lock_key
from tuisku.rules.match import Match, match
from tuisku.rules.packs import Correlation, Rule, RuleSet
from tuisku.rules.predicates import MISSING, NULL, FieldPath
from tuisku.store import meta
from tuisku.store.ingest import enqueue
from tuisku.store.lifecycle import set_finding_status
from tuisku.worker import fold, notify
from tuisku.worker.metrics import compute_deltas

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 5  # counted failures per (row, rule) before the pair is dead-lettered
MAX_TRANSIENT_RETRIES = 5  # in-process retries of one pair within one evaluation
MAX_UNCOUNTED_TRANSIENT = 20  # evaluations a pair may lose to lock conflicts before they count
MAX_EXPLAINED_ROWS = 100
TRANSIENT = (errors.DeadlockDetected, errors.SerializationFailure, errors.LockNotAvailable)

Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    batch_size: int = 100
    lease: timedelta = timedelta(seconds=120)
    statement_timeout_ms: int = 10_000
    lock_timeout_ms: int = 5_000
    max_open_findings: int = 1000
    max_live_incidents: int = 100
    export_interval: timedelta = timedelta(seconds=60)
    allowed_lateness: timedelta = timedelta(hours=24)
    max_window_rows: int = 50_000
    retry_backoff: timedelta = timedelta(seconds=30)
    notify_backoff: notify.Backoff = field(default_factory=notify.Backoff)


@dataclass(slots=True)
class Stats:
    claimed: int = 0
    evaluated: int = 0
    skipped_stale: int = 0
    fired: int = 0
    linked: int = 0
    failed_pairs: int = 0
    dead_lettered: int = 0
    retried_later: int = 0
    expired_findings: int = 0
    delivered: int = 0


class _Transient(Exception):
    """The row's advisory locks could not be taken in time; nothing was evaluated."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        super().__init__("lock timeout")
        self.rules = list(rules)


@dataclass(frozen=True, slots=True)
class _Failure:
    rule: Rule
    error: str
    counted: bool  # False for lock conflicts, until MAX_UNCOUNTED_TRANSIENT of them


@dataclass(slots=True)
class _Outcome:
    fired: bool = False
    linked: bool = False


# --- row envelopes ------------------------------------------------------------------------------

_CURRENT: LiteralString = (
    "(t.parse_attempt_id IS NULL OR t.parse_attempt_id = (SELECT c.id FROM parse_attempts c "
    "WHERE c.raw_record_id = t.raw_record_id AND c.status = 'ok' ORDER BY c.id DESC LIMIT 1))"
)
_OBS_COLUMNS: LiteralString = (
    "SELECT 'observation' AS layer, t.id, t.uid, t.kind, t.source_id, s.name AS source, "
    "NULL::text AS evaluator, NULL::text AS authorship, NULL::text AS identity, "
    "NULL::smallint AS severity_id, t.entity_keys, t.attributes, t.event_time, t.received_at, "
    "t.eval_time, t.raw_record_id, t.parse_attempt_id, t.flags, " + _CURRENT + " AS current "
    "FROM observations t LEFT JOIN sources s ON s.id = t.source_id "
)
_DET_COLUMNS: LiteralString = (
    "SELECT 'detection' AS layer, t.id, t.uid, t.kind, t.source_id, s.name AS source, "
    "t.evaluator, t.authorship, t.identity, t.severity_id, t.entity_keys, t.attributes, "
    "t.event_time, t.received_at, t.eval_time, t.raw_record_id, t.parse_attempt_id, t.flags, "
    + _CURRENT
    + " AS current FROM detections t LEFT JOIN sources s ON s.id = t.source_id "
)


async def load_row(conn: AsyncConnection[Any], queue_row: Mapping[str, Any]) -> dict | None:
    if queue_row["observation_id"] is not None:
        return await db.fetch_one(
            conn, _OBS_COLUMNS + "WHERE t.id = %s", (queue_row["observation_id"],)
        )
    return await db.fetch_one(conn, _DET_COLUMNS + "WHERE t.id = %s", (queue_row["detection_id"],))


class WindowTooLarge(Exception):
    """A correlation window holds more rows than the cap. The pair fails (counted): a partial
    window is never evaluated."""


def _sql_expr(path: FieldPath, layer: str) -> sql.Composable | None:
    """A text-valued SQL expression for ``path``, or None when it cannot be pushed down."""
    head, rest = path.segments[0], path.segments[1:]
    if head == "attributes":
        if len(rest) == 1 and isinstance(rest[0], str):  # matches the metric expression index
            return sql.SQL("(t.attributes ->> {})").format(sql.Literal(rest[0]))
        return sql.SQL("(t.attributes #>> {})").format(sql.Literal([str(k) for k in rest]))
    if head == "entity_keys":
        if len(rest) == 1 and isinstance(rest[0], int):
            return sql.SQL("t.entity_keys[{}]").format(sql.Literal(rest[0] + 1))
        return None
    if rest:
        return None
    if head == "kind":
        return sql.SQL("t.kind")
    if head == "source":
        return sql.SQL("s.name")
    if layer == "detection" and head in ("evaluator", "authorship", "identity"):
        return sql.Identifier("t", head)
    if layer == "detection" and head == "severity_id":
        return sql.SQL("t.severity_id::text")
    return None


def _sql_text(value: Any, path: FieldPath) -> str | None:
    """The text form SQL compares with, only where SQL equality is exactly Python's: strings,
    and the severity_id integer column. Anything else is left to the Python predicate."""
    if isinstance(value, str):
        return value
    if path.text == "severity_id" and isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def window_filters(rule: Rule, env: Mapping[str, Any]) -> list[sql.Composable]:
    """SQL conditions that every row of ``env``'s group must meet: the rule's static ``eq`` and
    ``in`` predicates and the group's values. They only narrow the read; the Python predicates
    still decide, so each condition must hold for every row Python would accept."""
    layer = rule.select.layer
    out: list[sql.Composable] = []
    for p in rule.select.where:
        expr = _sql_expr(p.path, layer)
        if expr is None:
            continue
        if p.op == "eq":
            text = _sql_text(p.value, p.path)
            if text is not None:
                out.append(sql.SQL("{} = {}").format(expr, sql.Literal(text)))
        elif p.op == "in":
            texts = [_sql_text(v, p.path) for v in p.value]
            if texts and all(t is not None for t in texts):
                out.append(sql.SQL("{} = ANY({})").format(expr, sql.Literal(texts)))
    for path in rule.finding.group_by:
        expr = _sql_expr(path, layer)
        if expr is None:
            continue
        raw = path.resolve(env)
        if raw is MISSING or raw is NULL:
            out.append(sql.SQL("{} IS NULL").format(expr))
        else:
            text = _sql_text(raw, path)
            if text is not None:
                out.append(sql.SQL("{} = {}").format(expr, sql.Literal(text)))
    return out


async def _window_rows(
    conn: AsyncConnection[Any],
    layer: str,
    kind: str,
    lo: datetime,
    hi: datetime,
    limit: int,
    filters: Sequence[sql.Composable] = (),
) -> list[dict[str, Any]]:
    """Current rows of ``kind`` with ``lo < eval_time < hi`` meeting ``filters``, in time order.

    Raises :class:`WindowTooLarge` rather than return a truncated window."""
    columns = _OBS_COLUMNS if layer == "observation" else _DET_COLUMNS
    where = [
        sql.SQL("t.kind = {}").format(sql.Literal(kind)),
        sql.SQL("t.eval_time > {}").format(sql.Literal(lo)),
        sql.SQL("t.eval_time < {}").format(sql.Literal(hi)),
        sql.SQL(_CURRENT),
        *filters,
    ]
    query = sql.SQL("{} WHERE {} ORDER BY t.eval_time, t.id LIMIT {}").format(
        sql.SQL(columns), sql.SQL(" AND ").join(where), sql.Literal(limit + 1)
    )
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(query)
        rows = await cur.fetchall()
    if len(rows) > limit:
        raise WindowTooLarge(f"more than {limit} rows in the correlation window")
    return rows


def _row_ref(env: Mapping[str, Any]) -> dict[str, Any]:
    return {"layer": env["layer"], "uid": str(env["uid"])}


def _row_cols(env: Mapping[str, Any]) -> tuple[int | None, int | None]:
    """(observation_id, detection_id) for a row."""
    return (env["id"], None) if env["layer"] == "observation" else (None, env["id"])


# --- correlation --------------------------------------------------------------------------------


def _compare(op: str, value: float, threshold: float) -> bool:
    return {
        "gt": value > threshold,
        "gte": value >= threshold,
        "lt": value < threshold,
        "lte": value <= threshold,
        "eq": value == threshold,
    }[op]


@dataclass(frozen=True, slots=True)
class _Point:
    env: dict[str, Any]
    t: datetime
    value: Any  # 1 for counts, the field value for value_count, a number for sums


def _aggregate(c: Correlation, points: Sequence[_Point]) -> float:
    if c.type == "value_count":
        return float(len({repr(p.value) for p in points if p.value is not None}))
    if c.type == "event_count" or (c.type == "baseline" and c.field is None and not c.delta):
        return float(len(points))
    return float(sum(p.value for p in points if isinstance(p.value, int | float)))


def _in(points: Sequence[_Point], lo: datetime, hi: datetime) -> list[_Point]:
    return [p for p in points if lo < p.t <= hi]


def _decide(c: Correlation, points: Sequence[_Point], end: datetime) -> dict[str, Any] | None:
    """The correlation's verdict for the window ending at ``end``: figures when it holds."""
    window = _in(points, end - c.timespan, end)
    value = _aggregate(c, window)
    figures: dict[str, Any] = {
        "type": c.type,
        "timespan_seconds": int(c.timespan.total_seconds()),
        "window_start": (end - c.timespan).isoformat(),
        "window_end": end.isoformat(),
        "value": value,
    }
    if c.baseline is not None:
        previous = [
            _aggregate(c, _in(points, end - (k + 1) * c.timespan, end - k * c.timespan))
            for k in range(1, c.baseline.windows + 1)
        ]
        mean = sum(previous) / len(previous)
        threshold = max(c.baseline.factor * mean, c.baseline.floor)
        figures["baseline"] = {
            "windows": c.baseline.windows,
            "factor": c.baseline.factor,
            "floor": c.baseline.floor,
            "previous": previous,
            "mean": mean,
            "threshold": threshold,
        }
        holds = value > 0 and value >= threshold
    else:
        assert c.condition_op is not None and c.condition_value is not None
        figures["condition"] = {c.condition_op: c.condition_value}
        holds = _compare(c.condition_op, value, c.condition_value)
    return figures | {"rows": window} if holds else None


# --- the worker ---------------------------------------------------------------------------------


@dataclass
class Worker:
    rule_set: RuleSet
    clock: Clock
    notifier: notify.Notifier = field(default_factory=notify.LogNotifier)
    config: WorkerConfig = field(default_factory=WorkerConfig)
    # Test hook: called at the start of each pair evaluation (rule, row envelope).
    before_pair: Callable[[Rule, Mapping[str, Any]], None] | None = None

    @property
    def limits(self) -> fold.Limits:
        return fold.Limits(self.config.max_open_findings, self.config.max_live_incidents)

    # -- packs ---------------------------------------------------------------------------------

    async def record_pack_loads(self, conn: AsyncConnection[Any]) -> None:
        """One append-only ``pack_loads`` row per loaded pack (ADR 0004, 0006)."""
        params_sha = (
            bytes.fromhex(self.rule_set.params_sha256) if self.rule_set.params_sha256 else None
        )
        async with conn.transaction():
            for pack in self.rule_set.packs:
                await conn.execute(
                    "INSERT INTO pack_loads (pack, version, authorship, sha256, params_sha256, "
                    "max_lookback_seconds, rules) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (
                        pack.info.id,
                        pack.info.version,
                        pack.info.authorship,
                        bytes.fromhex(pack.info.sha256),
                        params_sha,
                        int(pack.max_lookback.total_seconds()),
                        Jsonb([r.ref for r in pack.rules]),
                    ),
                )

    # -- one pass ------------------------------------------------------------------------------

    async def run_once(self, conn: AsyncConnection[Any]) -> Stats:
        """Sweep, claim one batch, evaluate it and deliver notifications. ``conn`` must be in
        autocommit mode; every step manages its own transaction."""
        stats = Stats()
        stats.expired_findings = await self.sweep(conn)
        for queue_row in await self.claim(conn):
            stats.claimed += 1
            await self._process(conn, queue_row, stats)
        stats.delivered = await notify.drain(
            conn, self.notifier, self.clock(), backoff=self.config.notify_backoff
        )
        return stats

    async def run_until_idle(self, conn: AsyncConnection[Any], max_passes: int = 100) -> Stats:
        total = Stats()
        for _ in range(max_passes):
            stats = await self.run_once(conn)
            for name in Stats.__slots__:  # type: ignore[attr-defined]
                setattr(total, name, getattr(total, name) + getattr(stats, name))
            if stats.claimed == 0:
                break
        return total

    async def sweep(self, conn: AsyncConnection[Any]) -> int:
        now = self.clock()
        async with conn.transaction():
            expired = await db.fetch_all(
                conn,
                "SELECT * FROM findings WHERE status IN ('open', 'acknowledged', 'suppressed') "
                "AND (last_seen + make_interval(secs => window_seconds) < %s "
                "OR first_seen + make_interval(secs => max_lifetime_seconds) < %s) "
                "ORDER BY id FOR UPDATE SKIP LOCKED",
                (now, now),
            )
            for finding in expired:
                await set_finding_status(
                    conn,
                    finding,
                    "expired",
                    actor="system",
                    reason="window or max_lifetime passed",
                    now=now,
                )
            lifted = await db.fetch_all(
                conn,
                "SELECT * FROM findings WHERE status = 'suppressed' AND suppressed_until <= %s "
                "ORDER BY id FOR UPDATE SKIP LOCKED",
                (now,),
            )
            for finding in lifted:
                await set_finding_status(
                    conn,
                    finding,
                    "open",
                    actor="system",
                    reason="suppression expired",
                    now=now,
                    event_kind="suppression_expired",
                )
        return len(expired)

    async def claim(self, conn: AsyncConnection[Any]) -> list[dict[str, Any]]:
        now = self.clock()
        async with conn.transaction():
            return await db.fetch_all(
                conn,
                "UPDATE evaluation_queue q SET attempts = q.attempts + 1, claimed_until = %s "
                "FROM (SELECT id FROM evaluation_queue WHERE claimed_until IS NULL "
                "OR claimed_until < %s ORDER BY id LIMIT %s FOR UPDATE SKIP LOCKED) c "
                "WHERE q.id = c.id RETURNING q.*",
                (now + self.config.lease, now, self.config.batch_size),
            )

    # -- one queue row -------------------------------------------------------------------------

    async def _process(
        self, conn: AsyncConnection[Any], queue_row: dict[str, Any], stats: Stats
    ) -> None:
        try:
            async with conn.transaction():
                await self._evaluate_row(conn, queue_row, stats)
        except _Transient as exc:
            # The advisory locks timed out, so the transaction is gone and nothing was
            # evaluated. Record an uncounted conflict per rule (capped) in a new one.
            stats.retried_later += 1
            async with conn.transaction():
                env = await load_row(conn, queue_row)
                failures = [_Failure(r, "lock timeout", counted=False) for r in exc.rules]
                done = env is not None and await self._record_failures(
                    conn, queue_row, env, failures, stats
                )
                await self._finish(conn, queue_row, done, failures)

    async def _lock(self, conn: AsyncConnection[Any], keys: Iterable[int]) -> None:
        for key in sorted(keys):  # sorted: two workers can never deadlock on these
            await conn.execute("SELECT pg_advisory_xact_lock(%s)", (key,))

    async def _finish(
        self,
        conn: AsyncConnection[Any],
        queue_row: dict[str, Any],
        done: bool,
        failures: Sequence[_Failure],
    ) -> None:
        """Delete the queue row once every rule succeeded or was dead-lettered for it;
        otherwise lease it out again after the backoff."""
        if done:
            await conn.execute("DELETE FROM evaluation_queue WHERE id = %s", (queue_row["id"],))
            await conn.execute(
                "DELETE FROM evaluation_attempts WHERE queue_id = %s", (queue_row["id"],)
            )
            return
        await conn.execute(
            "UPDATE evaluation_queue SET last_error = %s, claimed_until = %s WHERE id = %s",
            (
                "; ".join(f"{f.rule.ref}: {f.error}" for f in failures)[:1000],
                self.clock() + self.config.retry_backoff,
                queue_row["id"],
            ),
        )

    async def _evaluate_row(
        self, conn: AsyncConnection[Any], queue_row: dict[str, Any], stats: Stats
    ) -> None:
        await conn.execute(
            "SELECT set_config('statement_timeout', %s, true), "
            "set_config('lock_timeout', %s, true)",
            (f"{self.config.statement_timeout_ms}ms", f"{self.config.lock_timeout_ms}ms"),
        )
        env = await load_row(conn, queue_row)
        if env is None or not env["current"]:
            stats.skipped_stale += 1  # a newer parse attempt supersedes this row
            await self._finish(conn, queue_row, True, [])
            return
        dead = {
            str(r["rule_id"])
            for r in await db.fetch_all(
                conn,
                "SELECT rule_id FROM evaluation_dead_letter_rules WHERE queue_id = %s",
                (queue_row["id"],),
            )
        }
        matches = [
            m
            for m in (match(r, env) for r in self.rule_set.rules if r.id not in dead)
            if m is not None
        ]
        keys: set[int] = set()
        for m in matches:
            fingerprint = fold.fingerprint_for(m.rule, m.group_values)
            keys.add(lock_key("group", m.rule.id, m.rule.rev, fingerprint))
            keys.add(lock_key("rule", m.rule.id))
        try:
            await self._lock(conn, keys)
        except TRANSIENT as exc:
            raise _Transient([m.rule for m in matches]) from exc
        failures: list[_Failure] = []
        for m in matches:
            failure = await self._evaluate_pair_with_retries(conn, m, env, stats)
            if failure is not None:
                failures.append(failure)
        stats.evaluated += 1
        done = not failures or await self._record_failures(conn, queue_row, env, failures, stats)
        await self._finish(conn, queue_row, done, failures)

    async def _evaluate_pair_with_retries(
        self, conn: AsyncConnection[Any], m: Match, env: dict[str, Any], stats: Stats
    ) -> _Failure | None:
        """None on success, else the failure (counted, or an uncounted lock conflict)."""
        last = "transient"
        for _ in range(MAX_TRANSIENT_RETRIES):
            try:
                async with conn.transaction():  # SAVEPOINT for this (row, rule) pair
                    if self.before_pair is not None:
                        self.before_pair(m.rule, env)
                    outcome = await self._evaluate_pair(conn, m, env)
                stats.fired += outcome.fired
                stats.linked += outcome.linked
                return None
            except _AlreadyFired:
                return None  # another evaluation already wrote this firing; nothing to redo
            except TRANSIENT as exc:
                last = type(exc).__name__
                continue  # not counted as an attempt
            except psycopg.Error as exc:
                if conn.info.transaction_status == psycopg.pq.TransactionStatus.INERROR:
                    raise  # the outer transaction is gone
                return _Failure(m.rule, f"{type(exc).__name__}: {exc.diag.sqlstate or ''}", True)
            except Exception as exc:  # a bug in a rule's evaluation must not stop the others
                log.exception("rule %s failed on %s %s", m.rule.ref, env["layer"], env["id"])
                return _Failure(m.rule, type(exc).__name__, True)
        return _Failure(m.rule, f"transient: {last}", counted=False)

    async def _record_failures(
        self,
        conn: AsyncConnection[Any],
        queue_row: dict[str, Any],
        env: dict[str, Any],
        failures: Sequence[_Failure],
        stats: Stats,
    ) -> bool:
        """Count failures per (row, rule) (ADR 0006), dead-letter pairs that reached
        MAX_ATTEMPTS, and say whether every failing pair is now dead-lettered. Lease expiries and
        crashes never reach here, so they never burn attempts; lock conflicts count only after
        MAX_UNCOUNTED_TRANSIENT of them."""
        dead: list[tuple[Rule, str, int]] = []
        for f in failures:
            row = await db.fetch_one(
                conn,
                "INSERT INTO evaluation_attempts (queue_id, rule_id, attempts, transient, "
                "last_error) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (queue_id, rule_id) DO UPDATE "
                "SET attempts = evaluation_attempts.attempts + EXCLUDED.attempts, "
                "transient = evaluation_attempts.transient + EXCLUDED.transient, "
                "last_error = EXCLUDED.last_error RETURNING attempts, transient",
                (queue_row["id"], f.rule.id, int(f.counted), int(not f.counted), f.error[:1000]),
            )
            assert row is not None
            if not f.counted and row["transient"] >= MAX_UNCOUNTED_TRANSIENT:
                row = await db.fetch_one(
                    conn,
                    "UPDATE evaluation_attempts SET attempts = attempts + 1, transient = 0 "
                    "WHERE queue_id = %s AND rule_id = %s RETURNING attempts, transient",
                    (queue_row["id"], f.rule.id),
                )
                assert row is not None
            if row["attempts"] >= MAX_ATTEMPTS:
                dead.append((f.rule, f.error, row["attempts"]))
        stats.failed_pairs += len(failures)
        if dead:
            await self._dead_letter(conn, queue_row, env, dead)
            stats.dead_lettered += len(dead)
        return len(dead) == len(failures)

    async def _dead_letter(
        self,
        conn: AsyncConnection[Any],
        queue_row: dict[str, Any],
        env: dict[str, Any],
        dead: list[tuple[Rule, str, int]],
    ) -> None:
        """Dead-letter each pair: a record, a ``tuisku.meta.evaluation_failed`` meta-detection
        naming the rule, and a notification, so a failing rule is never silent (ADR 0006)."""
        now = self.clock()
        await conn.execute(
            "INSERT INTO evaluation_dead_letter (id, observation_id, detection_id, enqueued_at, "
            "attempts, last_error, moved_at) VALUES (%s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (id) DO NOTHING",
            (
                queue_row["id"],
                queue_row["observation_id"],
                queue_row["detection_id"],
                queue_row["enqueued_at"],
                max(a for _, _, a in dead),
                "; ".join(f"{r.ref}: {e}" for r, e, _ in dead)[:1000],
                now,
            ),
        )
        for rule, error, attempts in dead:
            await conn.execute(
                "INSERT INTO evaluation_dead_letter_rules (queue_id, observation_id, "
                "detection_id, rule_id, rule_rev, attempts, last_error, moved_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (
                    queue_row["id"],
                    queue_row["observation_id"],
                    queue_row["detection_id"],
                    rule.id,
                    rule.rev,
                    attempts,
                    error[:1000],
                    now,
                ),
            )
            await meta.record_evaluation_failed(
                conn,
                source_id=env["source_id"],
                source_name=env["source"],
                rule_id=rule.id,
                details={
                    "rule": rule.ref,
                    "rule_name": rule.name,
                    "row": _row_ref(env),
                    "attempts": attempts,
                    "error": error[:200],
                },
                now=now,
            )
            await notify.emit(
                conn,
                dedupe_key=f"dead_letter:{queue_row['id']}:{rule.id}",
                kind="evaluation_dead_lettered",
                severity_id=4,
                payload={
                    "rule": rule.ref,
                    "rule_name": rule.name,
                    "row": _row_ref(env),
                    "attempts": attempts,
                    "error": error[:200],
                    "entity_keys": [f"source:{env['source']}"] if env["source"] else [],
                },
                now=now,
            )

    # -- one (row, rule) pair ------------------------------------------------------------------

    def _effective_time(self, env: Mapping[str, Any]) -> tuple[datetime, dict[str, Any] | None]:
        """The row's evaluation time; a row later than the allowed lateness is evaluated at
        ``received_at``, and its lateness is recorded in the explanation (ADR 0006)."""
        t: datetime = env["eval_time"]
        lateness = env["received_at"] - t
        if lateness > self.config.allowed_lateness:
            return env["received_at"], {
                "event_eval_time": t.isoformat(),
                "lateness_seconds": int(lateness.total_seconds()),
                "evaluated_at": "received_at",
            }
        return t, None

    async def _already_done(self, conn: AsyncConnection[Any], rule: Rule, env: dict) -> bool:
        obs_id, det_id = _row_cols(env)
        row = await db.fetch_one(
            conn,
            "SELECT 1 AS hit FROM rule_firings WHERE rule_id = %s AND rule_rev = %s "
            "AND observation_id IS NOT DISTINCT FROM %s AND detection_id IS NOT DISTINCT FROM %s",
            (rule.id, rule.rev, obs_id, det_id),
        )
        return row is not None

    async def _evaluate_pair(
        self, conn: AsyncConnection[Any], m: Match, env: dict[str, Any]
    ) -> _Outcome:
        rule = m.rule
        if await self._already_done(conn, rule, env):
            return _Outcome()
        t, late = self._effective_time(env)
        fingerprint = fold.fingerprint_for(rule, m.group_values)
        if rule.correlation is None:
            await self._fire(conn, m, env, t, fingerprint, [env], None, late, kind="row")
            return _Outcome(fired=True)
        return await self._correlate(conn, m, env, t, fingerprint, late)

    async def _points(
        self, conn: AsyncConnection[Any], m: Match, env: dict[str, Any], t: datetime
    ) -> list[_Point]:
        rule = m.rule
        c = rule.correlation
        assert c is not None
        lo, hi = t - c.lookback, t + c.timespan
        rows = await _window_rows(
            conn,
            rule.select.layer,
            rule.select.kind,
            lo,
            hi,
            self.config.max_window_rows,
            window_filters(rule, env),
        )
        members: list[dict[str, Any]] = []
        for row in rows:
            if row["id"] == env["id"]:
                continue  # added below with its effective time
            other = match(rule, row)
            if other is not None and other.group_values == m.group_values:
                members.append(row)
        members.append(env)
        deltas = await compute_deltas(conn, members, self.config.export_interval) if c.delta else {}
        points: list[_Point] = []
        for row in members:
            row_t = t if row is env else row["eval_time"]
            if c.delta:
                value: Any = deltas.get(row["id"], 0.0)
            elif c.field is not None:
                raw = c.field.resolve(row)
                if c.type == "value_count":
                    # Missing and null fields are not values to count.
                    value = None if raw is MISSING or raw is NULL else repr(raw)
                else:
                    ok = isinstance(raw, int | float) and not isinstance(raw, bool)
                    value = float(raw) if ok else 0.0
            else:
                value = 1
            points.append(_Point(env=row, t=row_t, value=value))
        points.sort(key=lambda p: (p.t, p.env["id"]))
        return points

    async def _last_firing(
        self, conn: AsyncConnection[Any], rule: Rule, fingerprint: bytes
    ) -> dict[str, Any] | None:
        return await db.fetch_one(
            conn,
            "SELECT id, eval_time, firing_detection_id FROM rule_firings WHERE rule_id = %s "
            "AND rule_rev = %s AND group_key = %s AND kind IN ('row', 'correlation') "
            "ORDER BY id DESC LIMIT 1",
            (rule.id, rule.rev, fingerprint),
        )

    async def _armed(
        self, conn: AsyncConnection[Any], rule: Rule, fingerprint: bytes, end: datetime
    ) -> bool:
        """A correlation may fire at ``end`` unless a firing for the group whose window overlaps
        ``(end - timespan, end + timespan)`` still has an attachable finding (ADR 0006
        "Firing"). Checking every overlapping firing, not only the newest, keeps a late row from
        firing a second time over evidence an older firing already covers."""
        c = rule.correlation
        assert c is not None
        rows = await db.fetch_all(
            conn,
            "SELECT firing_detection_id FROM rule_firings WHERE rule_id = %s AND rule_rev = %s "
            "AND group_key = %s AND kind IN ('row', 'correlation') "
            "AND eval_time > %s AND eval_time < %s ORDER BY id",
            (rule.id, rule.rev, fingerprint, end - c.timespan, end + c.timespan),
        )
        for row in rows:
            finding = await fold.finding_of_detection(conn, row["firing_detection_id"])
            if finding is not None and fold.attachable_at(finding, end):
                return False
        return True

    async def _correlate(
        self,
        conn: AsyncConnection[Any],
        m: Match,
        env: dict[str, Any],
        t: datetime,
        fingerprint: bytes,
        late: dict[str, Any] | None,
    ) -> _Outcome:
        rule = m.rule
        c = rule.correlation
        assert c is not None
        points = await self._points(conn, m, env, t)
        last = await self._last_firing(conn, rule, fingerprint)
        last_finding = (
            await fold.finding_of_detection(conn, last["firing_detection_id"]) if last else None
        )
        # Every window containing the row: ends at t and at each later member before t+timespan.
        ends = sorted({t} | {p.t for p in points if t < p.t < t + c.timespan})
        for end in ends:
            verdict = _decide(c, points, end)
            if verdict is None:
                continue
            if await self._armed(conn, rule, fingerprint, end):
                window_rows = [p.env for p in verdict.pop("rows")]
                await self._fire(
                    conn, m, env, end, fingerprint, window_rows, verdict, late, kind="correlation"
                )
                return _Outcome(fired=True)
        if last is not None and last_finding is not None and fold.attachable_at(last_finding, t):
            await self._link(conn, m, env, t, fingerprint, last, last_finding)
            return _Outcome(linked=True)
        return _Outcome()

    async def _insert_firing_key(
        self,
        conn: AsyncConnection[Any],
        rule: Rule,
        env: Mapping[str, Any],
        *,
        kind: str,
        fingerprint: bytes,
        window_start: datetime | None,
        t: datetime,
        firing_detection_id: int,
    ) -> int | None:
        obs_id, det_id = _row_cols(env)
        row = await db.fetch_one(
            conn,
            "INSERT INTO rule_firings (rule_id, rule_rev, kind, observation_id, detection_id, "
            "group_key, window_start, eval_time, firing_detection_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING RETURNING id",
            (
                rule.id,
                rule.rev,
                kind,
                obs_id,
                det_id,
                fingerprint,
                window_start,
                t,
                firing_detection_id,
            ),
        )
        return None if row is None else row["id"]

    async def _fire(
        self,
        conn: AsyncConnection[Any],
        m: Match,
        env: dict[str, Any],
        t: datetime,
        fingerprint: bytes,
        rows: Sequence[dict[str, Any]],
        correlation: dict[str, Any] | None,
        late: dict[str, Any] | None,
        *,
        kind: str,
    ) -> None:
        rule = m.rule
        now = self.clock()
        # The triggering row's keys first, then the rest in sorted order; cut is recorded.
        entity_keys, keys_cut = fold.merge_keys(
            list(env["entity_keys"] or []),
            [k for r in rows if r is not env for k in (r["entity_keys"] or [])],
        )
        explanation: dict[str, Any] = {
            "rule": rule.ref,
            "rule_name": rule.name,
            "pack": {"id": rule.pack.id, "version": rule.pack.version, "sha256": rule.pack.sha256},
            "params": dict(rule.params_used),
            "params_sha256": self.rule_set.params_sha256,
            "predicates": list(m.predicate_results),
            "group_by": [p.text for p in rule.finding.group_by],
            "group_values": list(m.group_values),
            "row_count": len(rows),
            "rows": [_row_ref(r) for r in rows[-MAX_EXPLAINED_ROWS:]],
            "triggered_by": _row_ref(env),
        }
        if correlation is not None:
            explanation["correlation"] = correlation
        if late is not None:
            explanation["late"] = late
        if keys_cut:
            explanation["entity_keys_truncated"] = True
        det = await db.fetch_one(
            conn,
            "INSERT INTO detections (source_id, evaluator, authorship, kind, identity, title, "
            "severity_id, event_time, received_at, eval_time, ocsf_version, rule_ref, attack, "
            "entity_keys, explanation, flags) VALUES (%s, 'tuisku', %s, %s, %s, %s, %s, %s, %s, "
            "%s, %s, %s, %s, %s, %s, %s) RETURNING id, uid",
            (
                env["source_id"],
                rule.pack.authorship,
                rule.name,
                rule.id,
                rule.title,
                rule.severity_id,
                t,
                now,
                t,
                OCSF_VERSION,
                Jsonb(rule.rule_ref()),
                list(rule.attack),
                entity_keys,
                Jsonb(explanation),
                ["entity_keys_truncated"] if keys_cut else [],
            ),
        )
        assert det is not None
        # Link what satisfied it, downwards (ADR 0002 rule 2), before any firing key: the
        # database accepts a key only for a row linked to its detection in this transaction.
        obs = sorted({r["id"] for r in rows if r["layer"] == "observation"})
        if obs:
            await conn.execute(
                "INSERT INTO detection_observations (detection_id, observation_id) "
                "SELECT %s, unnest(%s::bigint[])",
                (det["id"], obs),
            )
        dets = sorted({r["id"] for r in rows if r["layer"] == "detection"})
        if dets:
            await conn.execute(
                "INSERT INTO detection_evidence (detection_id, detection_ref_id, linked_at) "
                "SELECT %s, unnest(%s::bigint[]), %s",
                (det["id"], dets, now),
            )
        window_start = t - rule.correlation.timespan if rule.correlation and kind != "row" else None
        key = await self._insert_firing_key(
            conn,
            rule,
            env,
            kind=kind,
            fingerprint=fingerprint,
            window_start=window_start,
            t=t,
            firing_detection_id=det["id"],
        )
        if key is None:
            raise _AlreadyFired()
        # Mark the window's other rows as members so none of them is counted again as linked.
        for r in rows:
            if r is not env:
                await self._insert_firing_key(
                    conn,
                    rule,
                    r,
                    kind="member",
                    fingerprint=fingerprint,
                    window_start=None,
                    t=r["eval_time"],
                    firing_detection_id=det["id"],
                )
        await enqueue(conn, observation_ids=[], detection_ids=[det["id"]], enqueued_at=now)
        await fold.fold_firing(
            conn,
            fold.Firing(
                rule=rule,
                detection_id=det["id"],
                detection_uid=str(det["uid"]),
                eval_time=t,
                group_values=m.group_values,
                fingerprint=fingerprint,
                entity_keys=entity_keys,
                explanation=explanation,
                row_count=len(rows),
            ),
            self.limits,
            now,
        )

    async def _link(
        self,
        conn: AsyncConnection[Any],
        m: Match,
        env: dict[str, Any],
        t: datetime,
        fingerprint: bytes,
        last: dict[str, Any],
        finding: dict[str, Any],
    ) -> None:
        now = self.clock()
        obs_id, det_id = _row_cols(env)
        await conn.execute(
            "INSERT INTO detection_evidence (detection_id, observation_id, detection_ref_id, "
            "linked_at) VALUES (%s, %s, %s, %s)",
            (last["firing_detection_id"], obs_id, det_id, now),
        )
        key = await self._insert_firing_key(
            conn,
            m.rule,
            env,
            kind="link",
            fingerprint=fingerprint,
            window_start=None,
            t=t,
            firing_detection_id=last["firing_detection_id"],
        )
        if key is None:
            raise _AlreadyFired()
        await fold.link_row(
            conn,
            m.rule,
            finding,
            firing_detection_id=last["firing_detection_id"],
            link_id=key,
            row_uid=str(env["uid"]),
            t=t,
            entity_keys=list(env["entity_keys"] or []),
            limits=self.limits,
            now=now,
        )


class _AlreadyFired(Exception):
    """The firing key existed: another evaluation already did this. Roll back the savepoint."""
