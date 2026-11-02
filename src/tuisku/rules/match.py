"""Does a row feed a rule? Selection, feedback rules and predicates (ADR 0006). Pure."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tuisku.rules.fingerprint import group_value
from tuisku.rules.packs import Rule
from tuisku.rules.predicates import evaluate

META_PREFIX = "tuisku.meta."


@dataclass(frozen=True, slots=True)
class Match:
    rule: Rule
    group_values: tuple[Any, ...]
    predicate_results: tuple[dict[str, Any], ...]


def selectable(rule: Rule, envelope: Mapping[str, Any]) -> bool:
    """Layer, kind and the feedback rules, before any predicate."""
    select = rule.select
    if envelope.get("layer") != select.layer or envelope.get("kind") != select.kind:
        return False
    if select.layer == "detection":
        # A rule can never select detections whose identity is its own id.
        if envelope.get("identity") == rule.id:
            return False
        # Other rules' output is opt-in; meta-detections can always be selected by kind.
        if (
            envelope.get("evaluator") == "tuisku"
            and not str(envelope.get("kind", "")).startswith(META_PREFIX)
            and not select.include_rule_output
        ):
            return False
    return True


def match(rule: Rule, envelope: Mapping[str, Any]) -> Match | None:
    """The match (with group values and predicate results) or None. Never raises."""
    if not selectable(rule, envelope):
        return None
    results: list[dict[str, Any]] = []
    for p in rule.select.where:
        ok = evaluate(p.op, p.path.resolve(envelope), p.value)
        results.append({"field": p.path.text, "op": p.op, "value": p.shown, "result": ok})
        if not ok:
            return None
    values = tuple(group_value(path.resolve(envelope)) for path in rule.finding.group_by)
    return Match(rule=rule, group_values=values, predicate_results=tuple(results))
