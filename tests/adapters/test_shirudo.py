from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from tuisku.adapters import registry
from tuisku.adapters.base import AdapterError, Authorship, ParseResult, RawRecord, Severity
from tuisku.adapters.shirudo import (
    ADAPTER,
    CONDITIONS,
    INTEGRITY_COUNTERS,
    KEYS,
    MAX_KEEPALIVE_BYTES,
    TAMPER_COUNTERS,
)
from tuisku.adapters.testing import FIXED_RECEIVED_AT, assert_golden, run_fixture_file

FIXTURES = Path(__file__).parent.parent / "fixtures" / "shirudo"


def _lines(name: str) -> list[str]:
    return (FIXTURES / f"{name}.ndjson").read_text().splitlines()


def _body(name: str, index: int = 0) -> dict[str, Any]:
    return json.loads(_lines(name)[index])


def _parse(record: dict[str, Any] | str, received_at=FIXED_RECEIVED_AT) -> ParseResult:
    body = record if isinstance(record, str) else json.dumps(record, separators=(",", ":"))
    raw = RawRecord(source="t", body=body.encode(), received_at=received_at)
    return ADAPTER.parse(raw, {})


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.ndjson")), ids=lambda p: p.stem)
def test_golden(path: Path) -> None:
    actual = run_fixture_file(ADAPTER, path)
    assert_golden(actual, path.with_suffix(".expected.json"))


def test_registered() -> None:
    assert registry.get("shirudo") is ADAPTER
    assert ADAPTER.version == "1.0.0"


def test_format_tables_match_the_keepalive_schema() -> None:
    # Shirudo's /1 schema: 23 keys, 7 conditions, 43 tamper and 22 integrity counters.
    assert len(KEYS) == 23 and len(set(KEYS)) == 23
    assert len(CONDITIONS) == 7
    assert len(TAMPER_COUNTERS) == 43 and len(set(TAMPER_COUNTERS)) == 43
    assert len(INTEGRITY_COUNTERS) == 22 and len(set(INTEGRITY_COUNTERS)) == 22


class TestOkKeepalive:
    def test_one_keepalive_two_samples_no_detection(self) -> None:
        result = _parse(_body("ok"))
        kinds = [o.kind for o in result.observations]
        assert kinds == ["shirudo.keepalive", "metric.sample", "metric.sample"]
        assert result.detections == ()

    def test_event_time_is_receipt(self) -> None:
        later = FIXED_RECEIVED_AT + timedelta(minutes=3)
        result = _parse(_body("ok"), received_at=later)
        assert all(o.event_time == later for o in result.observations)
        assert result.observations[0].attributes["time_source"] == "received_at"

    def test_all_conditions_ok(self) -> None:
        attrs = _parse(_body("ok")).observations[0].attributes
        assert attrs["cond"] == 5461
        assert set(attrs["conditions"].values()) == {"ok"}
        assert list(attrs["conditions"]) == list(CONDITIONS)

    def test_samples_are_per_boot_counters_without_start_time(self) -> None:
        body = _body("ok")
        _, tamper, integrity = _parse(body).observations
        assert tamper.attributes["metric"] == "shirudo.tamper"
        assert tamper.attributes["value"] == sum(body["tamper"]) == 24
        assert tamper.attributes["labels"] == {"boot_id": body["boot_id"]}
        assert tamper.attributes["start_time"] is None
        assert tamper.attributes["temporality"] == "cumulative"
        assert tamper.attributes["is_monotonic"] is True
        assert tamper.attributes["counters"] == {
            "LoadNotLoader": 15,
            "MapCreate": 1,
            "BpfCommand": 8,
        }
        assert integrity.attributes["metric"] == "shirudo.integrity"
        assert integrity.attributes["value"] == 0
        assert integrity.attributes["counters"] == {}

    def test_tree_and_loaded_set(self) -> None:
        attrs = _parse(_body("ok", 1)).observations[0].attributes
        assert attrs["tree"]["tree_id"] == "fleet-a"
        assert attrs["tree"]["generation"] == 7
        assert attrs["loaded"] == {"set_sha256": "d" * 64, "count": 3, "not_ok": 0}


class TestVerdicts:
    def test_tampered_is_a_critical_builtin_detection(self) -> None:
        result = _parse(_body("tampered"))
        (det,) = result.detections
        assert det.kind == "shirudo.status"
        assert det.authorship is Authorship.BUILTIN
        assert det.identity == "shirudo:verdict:tampered"
        assert det.severity is Severity.CRITICAL
        assert det.observation_refs == (0,)
        assert det.attributes["conditions_alert"] == ["ChainIntact"]
        assert det.explanation["flag_names"] == ["register_rebound"]

    def test_lsm_off_is_critical(self) -> None:
        (det,) = _parse(_body("tampered", 1)).detections
        assert det.severity is Severity.CRITICAL
        assert det.attributes["conditions_alert"] == ["LsmAttached"]

    def test_tampered_counters_are_named(self) -> None:
        attrs = _parse(_body("tampered")).observations[0].attributes
        assert attrs["tamper_nonzero"] == {
            "LoadNotLoader": 15,
            "LoadUnverified": 2,
            "MapCreate": 1,
            "BpfCommand": 8,
            "SealRlimit": 1,
        }
        assert attrs["integrity_nonzero"] == {"DevMem": 1}

    @pytest.mark.parametrize(
        ("index", "severity", "flag"),
        [
            (0, Severity.MEDIUM, None),
            (1, Severity.LOW, None),
            (2, Severity.HIGH, "unknown_verdict"),
        ],
        ids=["degraded", "reboot-pending", "new-verdict"],
    )
    def test_severity(self, index: int, severity: Severity, flag: str | None) -> None:
        result = _parse(_body("verdicts", index))
        (det,) = result.detections
        assert det.severity is severity
        flags = result.observations[0].flags
        assert (flag in flags) if flag else ("unknown_verdict" not in flags)

    def test_degraded_names_the_warning_condition(self) -> None:
        (det,) = _parse(_body("verdicts")).detections
        assert det.attributes["conditions_warn"] == ["XdpCovered"]


class TestForwardCompatible:
    def test_unreadable_counters_give_no_sample(self) -> None:
        result = _parse(_body("forward_compatible"))
        assert [o.kind for o in result.observations] == ["shirudo.keepalive"]
        attrs = result.observations[0].attributes
        assert attrs["tamper_total"] is None
        assert attrs["flag_names"] == ["tamper_unavailable", "integrity_unavailable"]

    def test_appended_counters_conditions_flags_and_keys(self) -> None:
        result = _parse(_body("forward_compatible", 1))
        ka, tamper, integrity = result.observations
        assert ka.attributes["conditions"]["condition_7"] == "ok"
        assert ka.attributes["flag_names"] == ["bit_9"]
        assert tamper.attributes["counters"]["counter_44"] == 4
        assert integrity.attributes["counters"] == {"counter_22": 2}
        assert {"unknown_counter", "unknown_keys"} <= set(ka.flags)
        assert ka.unmapped == {"future_key": "x"}


class TestInvalid:
    @pytest.mark.parametrize("index", range(6))
    def test_broken_keepalive_is_kept_as_unknown(self, index: int) -> None:
        result = _parse(_lines("invalid")[index])
        (obs,) = result.observations
        assert obs.kind == "shirudo.unknown"
        assert obs.attributes["reason"] == "invalid_keepalive"
        assert result.detections == ()

    def test_oversized_keepalive_is_invalid(self) -> None:
        body = _body("ok") | {"image_version": "v" * MAX_KEEPALIVE_BYTES}
        (obs,) = _parse(body).observations
        assert "longer than" in obs.attributes["error"]

    @pytest.mark.parametrize(
        ("index", "reason"),
        [(0, "unsupported_schema"), (1, "not_a_keepalive"), (2, "otlp_metrics_not_interpreted")],
    )
    def test_other_json_objects(self, index: int, reason: str) -> None:
        (obs,) = _parse(_lines("other_records")[index]).observations
        assert obs.kind == "shirudo.unknown"
        assert obs.attributes["reason"] == reason

    @pytest.mark.parametrize("index", [3, 4, 5])
    def test_parse_failures(self, index: int) -> None:
        with pytest.raises(AdapterError):
            _parse(_lines("other_records")[index])
