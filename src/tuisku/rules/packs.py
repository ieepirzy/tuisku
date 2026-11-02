"""Rule packs: loading, strict schema validation and load-time checks (ADR 0006).

A pack is a directory with a ``pack.yaml`` manifest and ``rules/*.yaml`` rule files, parsed with
a safe loader that also rejects duplicate keys. Rules are data: no expressions, no templating,
no code. Every unknown key is an error, so a typo cannot silently disable part of a rule.

Packs come from the built-in ``packs/`` directory and from the directories in
``TUISKU_RULE_PACK_PATHS``; ``TUISKU_RULE_PARAMS_FILE`` overrides params per pack. Each pack is
hashed (SHA-256 over its manifest and rule files) so a finding names exactly which content
produced it.

Load-time checks (a pack that fails any of them is rejected, and so is the whole load):

- hard limits: ``timespan`` and ``window`` <= 7 days, ``max_lifetime`` <= 30 days, baseline
  ``windows`` <= 30, ``group_by`` <= 4 fields
- ``finding.window >= correlation.timespan`` and ``finding.max_lifetime >= correlation.timespan``
- no rule selects its own output, and the graph of rules that include rule output is acyclic
- rule ids are UUIDs, unique across every loaded pack
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from tuisku.rules.predicates import FieldPath, PathError, prepare_value

MAX_TIMESPAN = timedelta(days=7)
MAX_LIFETIME = timedelta(days=30)
MAX_BASELINE_WINDOWS = 30
MAX_GROUP_BY = 4
MAX_FILE_BYTES = 1024 * 1024
MAX_PREDICATES = 32

SEVERITIES = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
CORRELATION_TYPES = ("event_count", "value_count", "value_sum", "baseline")
CONDITION_OPS = ("gt", "gte", "lt", "lte", "eq")
DELTA_FIELD = "delta"  # value_sum over metric.sample: the computed counter delta (ADR 0006)
METRIC_KIND = "metric.sample"

_PACK_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]{1,32})?$")
_NAME_TAIL = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")
_KIND = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_PARAM = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ATTACK = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_DURATION = re.compile(r"^([0-9]{1,6})([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class PackError(ValueError):
    """A pack (or params file) failed validation; the message names the file and the problem."""


@dataclass(frozen=True, slots=True)
class Predicate:
    path: FieldPath
    op: str
    value: Any  # evaluation form (see predicates.prepare_value)
    shown: Any  # the resolved value as written, for explanations
    param: str | None = None


@dataclass(frozen=True, slots=True)
class Selection:
    layer: str  # observation | detection
    kind: str
    where: tuple[Predicate, ...]
    include_rule_output: bool = False


@dataclass(frozen=True, slots=True)
class Baseline:
    windows: int
    factor: float
    floor: float


@dataclass(frozen=True, slots=True)
class Correlation:
    type: str
    timespan: timedelta
    field: FieldPath | None = None  # value_count / value_sum (and baseline over a sum)
    delta: bool = False  # value_sum of metric sample deltas
    condition_op: str | None = None
    condition_value: float | None = None
    baseline: Baseline | None = None

    @property
    def lookback(self) -> timedelta:
        """How far back an evaluation reads: the window, plus the baseline windows."""
        windows = self.baseline.windows if self.baseline else 0
        return self.timespan * (windows + 1)


@dataclass(frozen=True, slots=True)
class FindingSpec:
    group_by: tuple[FieldPath, ...]
    window: timedelta
    max_lifetime: timedelta
    notify: str  # each | thresholds


@dataclass(frozen=True, slots=True)
class PackInfo:
    id: str
    version: str
    authorship: str
    license: str
    description: str
    sha256: str
    path: str
    params: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    rev: int
    name: str
    title: str
    severity_id: int
    attack: tuple[str, ...]
    license: str
    select: Selection
    correlation: Correlation | None
    finding: FindingSpec
    incident: bool
    pack: PackInfo
    params_used: Mapping[str, Any] = field(default_factory=dict)

    @property
    def ref(self) -> str:
        return f"{self.id}@{self.rev}"

    @property
    def actor(self) -> str:
        return f"rule:{self.ref}"

    def rule_ref(self) -> dict[str, Any]:
        return {
            "engine": "tuisku",
            "rule_id": self.id,
            "rev": self.rev,
            "name": self.name,
            "pack": self.pack.id,
            "pack_version": self.pack.version,
            "pack_sha256": self.pack.sha256,
            "license": self.license,
        }


@dataclass(frozen=True, slots=True)
class Pack:
    info: PackInfo
    rules: tuple[Rule, ...]

    @property
    def max_lookback(self) -> timedelta:
        spans = [r.correlation.lookback for r in self.rules if r.correlation is not None]
        return max(spans, default=timedelta(0))


@dataclass(frozen=True, slots=True)
class RuleSet:
    packs: tuple[Pack, ...]
    params_sha256: str | None = None

    @property
    def rules(self) -> tuple[Rule, ...]:
        return tuple(r for p in self.packs for r in p.rules)


# --- YAML ---------------------------------------------------------------------------------------


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""


def _no_duplicates(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False) -> Any:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)  # type: ignore[arg-type]
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node, deep)


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _no_duplicates,  # type: ignore[arg-type]
)


def _read_yaml(path: Path) -> tuple[Any, bytes]:
    data = path.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        raise PackError(f"{path}: larger than {MAX_FILE_BYTES} bytes")
    try:
        return yaml.load(data, Loader=_StrictLoader), data  # noqa: S506 (strict SafeLoader)
    except yaml.YAMLError as exc:
        raise PackError(f"{path}: invalid YAML: {exc}") from None
    except RecursionError:
        raise PackError(f"{path}: YAML nested too deeply") from None


# --- validation helpers -------------------------------------------------------------------------


class _Ctx:
    """Where we are (for messages) and the pack's params, recording which ones a rule uses."""

    def __init__(self, where: str, params: Mapping[str, Any]) -> None:
        self.where = where
        self.params = params
        self.used: dict[str, Any] = {}

    def fail(self, message: str) -> PackError:
        return PackError(f"{self.where}: {message}")

    def resolve(self, value: Any, what: str) -> tuple[Any, str | None]:
        """A literal, or ``{param: name}`` resolved against the pack's params."""
        if isinstance(value, dict):
            if set(value) != {"param"} or not isinstance(value["param"], str):
                raise self.fail(f"{what}: a mapping value must be exactly {{param: <name>}}")
            name = value["param"]
            if name not in self.params:
                raise self.fail(f"{what}: unknown param {name!r}")
            self.used[name] = self.params[name]
            return self.params[name], name
        return value, None


def _mapping(value: Any, ctx: _Ctx, what: str, required: set[str], optional: set[str]) -> dict:
    if not isinstance(value, dict):
        raise ctx.fail(f"{what} must be a mapping")
    keys = {k for k in value if isinstance(k, str)}
    if len(keys) != len(value):
        raise ctx.fail(f"{what}: keys must be strings")
    missing = required - keys
    if missing:
        raise ctx.fail(f"{what}: missing {', '.join(sorted(missing))}")
    unknown = keys - required - optional
    if unknown:
        raise ctx.fail(f"{what}: unknown key(s) {', '.join(sorted(unknown))}")
    return value


def _str(value: Any, ctx: _Ctx, what: str, pattern: re.Pattern[str] | None = None, n=1024) -> str:
    if not isinstance(value, str) or not value or len(value) > n:
        raise ctx.fail(f"{what} must be a non-empty string of at most {n} characters")
    if pattern is not None and not pattern.fullmatch(value):
        raise ctx.fail(f"{what} {value!r} does not match {pattern.pattern}")
    return value


def _duration(value: Any, ctx: _Ctx, what: str) -> timedelta:
    m = _DURATION.fullmatch(value) if isinstance(value, str) else None
    if m is None:
        raise ctx.fail(f"{what} must be a duration like 30s, 15m, 1h or 7d")
    seconds = int(m.group(1)) * _UNITS[m.group(2)]
    if seconds <= 0:
        raise ctx.fail(f"{what} must be positive")
    return timedelta(seconds=seconds)


def _number(value: Any, ctx: _Ctx, what: str) -> float:
    resolved, _ = ctx.resolve(value, what)
    if isinstance(resolved, bool) or not isinstance(resolved, int | float):
        raise ctx.fail(f"{what} must be a number")
    return float(resolved)


def _path(value: Any, ctx: _Ctx, what: str) -> FieldPath:
    try:
        return FieldPath.parse(value)
    except PathError as exc:
        raise ctx.fail(f"{what}: {exc}") from None


# --- rule parsing -------------------------------------------------------------------------------


def _predicate(raw: Any, ctx: _Ctx, i: int) -> Predicate:
    what = f"select.where[{i}]"
    obj = _mapping(raw, ctx, what, {"field", "op"}, {"value"})
    path = _path(obj["field"], ctx, f"{what}.field")
    op = obj["op"]
    resolved, param = ctx.resolve(obj.get("value"), f"{what}.value")
    try:
        value = prepare_value(op, resolved)
    except ValueError as exc:
        raise ctx.fail(f"{what}: {exc}") from None
    return Predicate(path=path, op=op, value=value, shown=resolved, param=param)


def _selection(raw: Any, ctx: _Ctx) -> Selection:
    obj = _mapping(raw, ctx, "select", {"layer", "kind"}, {"where", "include_rule_output"})
    layer = obj["layer"]
    if layer not in ("observation", "detection"):
        raise ctx.fail("select.layer must be observation or detection")
    kind = _str(obj["kind"], ctx, "select.kind", _KIND, 128)
    where_raw = obj.get("where", [])
    if not isinstance(where_raw, list) or len(where_raw) > MAX_PREDICATES:
        raise ctx.fail(f"select.where must be a list of at most {MAX_PREDICATES} predicates")
    include = obj.get("include_rule_output", False)
    if not isinstance(include, bool):
        raise ctx.fail("select.include_rule_output must be a boolean")
    if include and layer != "detection":
        raise ctx.fail("select.include_rule_output applies only to layer detection")
    where = tuple(_predicate(p, ctx, i) for i, p in enumerate(where_raw))
    return Selection(layer=layer, kind=kind, where=where, include_rule_output=include)


def _correlation(raw: Any, ctx: _Ctx, select: Selection) -> Correlation:
    obj = _mapping(
        raw, ctx, "correlation", {"type", "timespan"}, {"field", "condition", "baseline"}
    )
    ctype = obj["type"]
    if ctype not in CORRELATION_TYPES:
        raise ctx.fail(f"correlation.type must be one of {', '.join(CORRELATION_TYPES)}")
    timespan = _duration(obj["timespan"], ctx, "correlation.timespan")
    if timespan > MAX_TIMESPAN:
        raise ctx.fail("correlation.timespan exceeds the 7-day hard limit")
    field_path: FieldPath | None = None
    delta = False
    raw_field = obj.get("field")
    if ctype == "event_count":
        if raw_field is not None:
            raise ctx.fail("correlation.field does not apply to event_count")
    elif ctype in ("value_count", "value_sum") and raw_field is None:
        raise ctx.fail(f"correlation.field is required for {ctype}")
    if raw_field is not None:
        if raw_field == DELTA_FIELD:
            if ctype == "value_count" or select.kind != METRIC_KIND:
                raise ctx.fail("field 'delta' is a value_sum/baseline over metric.sample only")
            delta = True
        else:
            field_path = _path(raw_field, ctx, "correlation.field")
    if ctype == "baseline":
        if "condition" in obj:
            raise ctx.fail("a baseline correlation has no condition; it takes baseline:")
        b = _mapping(
            obj.get("baseline"), ctx, "correlation.baseline", {"windows", "factor"}, {"floor"}
        )
        windows = _number(b["windows"], ctx, "correlation.baseline.windows")
        if windows != int(windows) or not 1 <= windows <= MAX_BASELINE_WINDOWS:
            raise ctx.fail(f"correlation.baseline.windows must be 1..{MAX_BASELINE_WINDOWS}")
        factor = _number(b["factor"], ctx, "correlation.baseline.factor")
        floor = _number(b.get("floor", 0), ctx, "correlation.baseline.floor")
        if factor <= 0 or floor < 0:
            raise ctx.fail("correlation.baseline needs factor > 0 and floor >= 0")
        return Correlation(
            type=ctype,
            timespan=timespan,
            field=field_path,
            delta=delta,
            baseline=Baseline(windows=int(windows), factor=factor, floor=floor),
        )
    if "baseline" in obj:
        raise ctx.fail("correlation.baseline applies only to type baseline")
    cond = obj.get("condition")
    if not isinstance(cond, dict) or len(cond) != 1:
        raise ctx.fail(f"correlation.condition must be one of {{{', '.join(CONDITION_OPS)}: N}}")
    [(op, raw_value)] = cond.items()
    if op not in CONDITION_OPS:
        raise ctx.fail(f"correlation.condition operator must be one of {', '.join(CONDITION_OPS)}")
    value = _number(raw_value, ctx, f"correlation.condition.{op}")
    return Correlation(
        type=ctype,
        timespan=timespan,
        field=field_path,
        delta=delta,
        condition_op=op,
        condition_value=value,
    )


def _finding(raw: Any, ctx: _Ctx) -> FindingSpec:
    obj = _mapping(raw, ctx, "finding", {"window", "max_lifetime"}, {"group_by", "notify"})
    group_raw = obj.get("group_by", [])
    if not isinstance(group_raw, list) or len(group_raw) > MAX_GROUP_BY:
        raise ctx.fail(f"finding.group_by must be a list of at most {MAX_GROUP_BY} fields")
    group_by = tuple(_path(p, ctx, f"finding.group_by[{i}]") for i, p in enumerate(group_raw))
    window = _duration(obj["window"], ctx, "finding.window")
    lifetime = _duration(obj["max_lifetime"], ctx, "finding.max_lifetime")
    if window > MAX_TIMESPAN:
        raise ctx.fail("finding.window exceeds the 7-day hard limit")
    if lifetime > MAX_LIFETIME:
        raise ctx.fail("finding.max_lifetime exceeds the 30-day hard limit")
    notify = obj.get("notify", "thresholds")
    if notify not in ("each", "thresholds"):
        raise ctx.fail("finding.notify must be each or thresholds")
    return FindingSpec(group_by=group_by, window=window, max_lifetime=lifetime, notify=notify)


_RULE_REQUIRED = {"id", "rev", "name", "title", "severity", "select", "finding"}
_RULE_OPTIONAL = {"attack", "license", "description", "correlation", "incident"}


def _rule(raw: Any, path: Path, info: PackInfo) -> Rule:
    ctx = _Ctx(str(path), info.params)
    obj = _mapping(raw, ctx, "rule", _RULE_REQUIRED, _RULE_OPTIONAL)
    rule_id = _str(obj["id"], ctx, "id", n=36)
    try:
        if str(uuid.UUID(rule_id)) != rule_id:
            raise ValueError
    except ValueError:
        raise ctx.fail("id must be a lowercase hyphenated UUID") from None
    rev = obj["rev"]
    if isinstance(rev, bool) or not isinstance(rev, int) or not 1 <= rev <= 1_000_000:
        raise ctx.fail("rev must be a positive integer")
    name = _str(obj["name"], ctx, "name", n=128)
    prefix, _, tail = name.partition(".")
    if prefix != info.id or not _NAME_TAIL.fullmatch(tail):
        raise ctx.fail(f"name must be '{info.id}.<lowercase_name>' (it is the detection kind)")
    title = _str(obj["title"], ctx, "title", n=1024)
    severity = obj["severity"]
    if severity not in SEVERITIES:
        raise ctx.fail(f"severity must be one of {', '.join(SEVERITIES)}")
    attack_raw = obj.get("attack", [])
    if not isinstance(attack_raw, list) or not all(
        isinstance(a, str) and _ATTACK.fullmatch(a) for a in attack_raw
    ):
        raise ctx.fail("attack must be a list of ATT&CK technique ids such as T1567")
    license_ = _str(obj.get("license", info.license), ctx, "license", n=128)
    if "description" in obj:
        _str(obj["description"], ctx, "description", n=4096)
    select = _selection(obj["select"], ctx)
    correlation = (
        _correlation(obj["correlation"], ctx, select)
        if obj.get("correlation") is not None
        else None
    )
    finding = _finding(obj["finding"], ctx)
    if correlation is not None:
        if finding.window < correlation.timespan:
            raise ctx.fail("finding.window must be >= correlation.timespan")
        if finding.max_lifetime < correlation.timespan:
            raise ctx.fail("finding.max_lifetime must be >= correlation.timespan")
    incident = obj.get("incident", "none")
    if incident not in ("open", "none"):
        raise ctx.fail("incident must be open or none")
    if select.include_rule_output and select.kind == name:
        raise ctx.fail("a rule can never select its own output")
    return Rule(
        id=rule_id,
        rev=rev,
        name=name,
        title=title,
        severity_id=SEVERITIES[severity],
        attack=tuple(attack_raw),
        license=license_,
        select=select,
        correlation=correlation,
        finding=finding,
        incident=incident == "open",
        pack=info,
        params_used=dict(ctx.used),
    )


# --- packs --------------------------------------------------------------------------------------


def _pack_files(directory: Path) -> list[Path]:
    rules_dir = directory / "rules"
    rule_files = sorted(
        p for p in rules_dir.glob("*") if p.suffix in (".yaml", ".yml") and p.is_file()
    )
    return [directory / "pack.yaml", *rule_files]


def _sha256(directory: Path, files: Sequence[Path], contents: Sequence[bytes]) -> str:
    """Over every file's relative path and bytes, length-prefixed so boundaries cannot move."""
    h = hashlib.sha256()
    for path, data in zip(files, contents, strict=True):
        name = path.relative_to(directory).as_posix().encode()
        h.update(len(name).to_bytes(4, "big") + name + len(data).to_bytes(8, "big") + data)
    return h.hexdigest()


_PARAM_TYPES: tuple[type, ...] = (bool, int, float, str, list)


def _param_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int | float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "list"
    return "unsupported"


def _check_params(params: Any, where: str) -> dict[str, Any]:
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise PackError(f"{where}: params must be a mapping")
    for name, value in params.items():
        if not isinstance(name, str) or not _PARAM.fullmatch(name):
            raise PackError(f"{where}: param name {name!r} must match {_PARAM.pattern}")
        if _param_type(value) == "unsupported":
            raise PackError(f"{where}: param {name!r} must be a boolean, number, string or list")
    return dict(params)


def load_pack(
    directory: Path, overrides: Mapping[str, Any] | None = None, *, builtin: bool = False
) -> Pack:
    manifest_path = directory / "pack.yaml"
    if not manifest_path.is_file():
        raise PackError(f"{directory}: no pack.yaml")
    files = _pack_files(directory)
    loaded = [_read_yaml(p) for p in files]
    manifest = loaded[0][0]
    ctx = _Ctx(str(manifest_path), {})
    obj = _mapping(
        manifest,
        ctx,
        "pack.yaml",
        {"pack", "version", "authorship", "license"},
        {"description", "params"},
    )
    pack_id = _str(obj["pack"], ctx, "pack", _PACK_ID, 63)
    version = _str(obj["version"], ctx, "version", _VERSION, 64)
    authorship = obj["authorship"]
    if authorship not in ("tuisku", "community", "local"):
        raise ctx.fail("authorship must be tuisku, community or local")
    if authorship == "tuisku" and not builtin:
        raise ctx.fail("authorship tuisku is reserved for the built-in packs directory")
    license_ = _str(obj["license"], ctx, "license", n=128)
    description = obj.get("description", "")
    if not isinstance(description, str) or len(description) > 4096:
        raise ctx.fail("description must be a string of at most 4096 characters")
    params = _check_params(obj.get("params"), str(manifest_path))
    for name, value in (overrides or {}).items():
        if name not in params:
            raise PackError(f"params override for pack {pack_id!r}: unknown param {name!r}")
        if _param_type(value) != _param_type(params[name]):
            raise PackError(
                f"params override for pack {pack_id!r}: {name!r} must be a "
                f"{_param_type(params[name])}"
            )
        params[name] = value
    info = PackInfo(
        id=pack_id,
        version=version,
        authorship=authorship,
        license=license_,
        description=description,
        sha256=_sha256(directory, files, [data for _, data in loaded]),
        path=str(directory),
        params=params,
    )
    if len(files) == 1:
        raise PackError(f"{directory}: pack has no rules/*.yaml")
    rules = tuple(
        _rule(doc, path, info) for (doc, _), path in zip(loaded[1:], files[1:], strict=True)
    )
    return Pack(info=info, rules=rules)


def _discover(root: Path) -> list[Path]:
    if not root.is_dir():
        raise PackError(f"{root}: rule pack directory does not exist")
    if (root / "pack.yaml").is_file():
        return [root]
    return sorted(p for p in root.iterdir() if p.is_dir() and (p / "pack.yaml").is_file())


def _check_graph(rules: Sequence[Rule]) -> None:
    """Rules that include rule output must not form a selection cycle (ADR 0006 "Feedback")."""
    by_name = {r.name: r for r in rules}
    edges: dict[str, list[str]] = {}
    for r in rules:
        if r.select.include_rule_output and r.select.kind in by_name:
            edges.setdefault(r.name, []).append(r.select.kind)
    state: dict[str, int] = {}  # 1 visiting, 2 done

    def visit(name: str, trail: list[str]) -> None:
        state[name] = 1
        for nxt in edges.get(name, []):
            if state.get(nxt) == 1:
                cycle = " -> ".join([*trail[trail.index(nxt) :], nxt]) if nxt in trail else nxt
                raise PackError(f"rule selection cycle through rule output: {cycle}")
            if state.get(nxt) is None:
                visit(nxt, [*trail, nxt])
        state[name] = 2

    for name in sorted(edges):
        if state.get(name) is None:
            visit(name, [name])


def load_params_file(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    doc, data = _read_yaml(path)
    if doc is None:
        doc = {}
    if not isinstance(doc, dict):
        raise PackError(f"{path}: params file must map pack ids to param mappings")
    out: dict[str, dict[str, Any]] = {}
    for pack_id, params in doc.items():
        if not isinstance(pack_id, str) or not isinstance(params, dict):
            raise PackError(f"{path}: entry {pack_id!r} must map a pack id to a mapping")
        out[pack_id] = _check_params(params, f"{path} [{pack_id}]")
    return out, hashlib.sha256(data).hexdigest()


def load_rule_set(
    roots: Sequence[Path],
    params_file: Path | None = None,
    *,
    builtin: Sequence[Path] = (),
    require_rules: bool = False,
) -> RuleSet:
    """Load every pack under ``builtin`` (the shipped ``packs/``), then under ``roots`` (the
    configured paths). Only built-in packs may declare ``authorship: tuisku``."""
    overrides: dict[str, dict[str, Any]] = {}
    params_sha: str | None = None
    if params_file is not None:
        overrides, params_sha = load_params_file(params_file)
    packs: list[Pack] = []
    seen_packs: dict[str, str] = {}
    seen_rules: dict[str, str] = {}
    seen_names: dict[str, str] = {}
    sources = [(root, True) for root in builtin] + [(root, False) for root in roots]
    for root, is_builtin in sources:
        for directory in _discover(root):
            pack = load_pack(
                directory, overrides.get(_peek_pack_id(directory) or ""), builtin=is_builtin
            )
            if pack.info.id in seen_packs:
                raise PackError(
                    f"pack {pack.info.id!r} loaded twice ({seen_packs[pack.info.id]}, {directory})"
                )
            seen_packs[pack.info.id] = str(directory)
            for rule in pack.rules:
                if rule.id in seen_rules:
                    raise PackError(f"rule id {rule.id} used twice ({seen_rules[rule.id]})")
                if rule.name in seen_names:
                    raise PackError(f"rule name {rule.name} used twice ({seen_names[rule.name]})")
                seen_rules[rule.id] = seen_names[rule.name] = f"{pack.info.id}:{rule.name}"
            packs.append(pack)
    unknown = set(overrides) - set(seen_packs)
    if unknown:
        raise PackError(f"params file names unknown pack(s): {', '.join(sorted(unknown))}")
    rule_set = RuleSet(packs=tuple(packs), params_sha256=params_sha)
    _check_graph(rule_set.rules)
    if require_rules and not rule_set.rules:
        raise PackError("no rules loaded")
    return rule_set


def _peek_pack_id(directory: Path) -> str | None:
    doc, _ = _read_yaml(directory / "pack.yaml")
    value = doc.get("pack") if isinstance(doc, dict) else None
    return value if isinstance(value, str) else None
