"""Falco JSON output adapter (ADR 0005).

Input is one Falco alert as written with ``json_output: true``::

    {"time": "...Z", "rule": "...", "priority": "Notice", "source": "syscall",
     "tags": [...], "hostname": "...", "output": "...", "output_fields": {...}}

falcosidekick adds an optional ``uuid``. Per https://falco.org/docs/concepts/outputs/channels/
``time`` is ISO 8601 with nanoseconds and ``output_fields["evt.time"]`` is epoch nanoseconds as
a JSON number. Field names follow https://falco.org/docs/reference/rules/supported-fields/.

Each alert becomes one observation (the facts in ``output_fields``) and one detection (the rule
match) that references it. Falco's internal records (rule ``Falco internal: metrics snapshot``
or source ``internal``) are not verdicts: they become one ``falco.internal`` observation and no
detection. A JSON object with no ``rule`` key is not a Falco alert; it becomes a
``falco.unknown`` observation and is never dropped.

Everything here is attacker-influenced, the rendered ``output`` string most of all: it is the
rule author's template filled with command lines and file names, so it is interpretation, not
fact. It is kept bounded in the detection's ``explanation`` and never parsed.

For non-syscall sources (k8s_audit, cloud plugins) the top-level ``hostname`` is the Falco
collector, not the asset, so it is kept in ``unmapped`` and never becomes a ``host:`` key.

Options: ``local_rules`` (list of full rule names authored by the estate) and
``attack_version`` (the ATT&CK version the estate's rule tags are mapped against).
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from tuisku.adapters.base import (
    AdapterError,
    Authorship,
    DetectionDraft,
    ObservationDraft,
    ParseResult,
    RawRecord,
    Severity,
)
from tuisku.adapters.entities import (
    host_key,
    image_digest_key,
    image_key,
    ip_key,
    k8s_namespace_key,
    k8s_pod_key,
    process_key,
    unique,
)
from tuisku.adapters.flows import community_id
from tuisku.adapters.jsonsafe import bounded_str, loads_object_flagged
from tuisku.adapters.registry import register
from tuisku.adapters.timeparse import parse_timestamp_or_none, parse_timestamp_with_zone_flag

MAX_RULE = 256
MAX_OUTPUT = 4096
MAX_TAGS = 64
MAX_TAG = 128
MAX_LOCAL_RULES = 10_000
MAX_ATTACK_VERSION = 32
IDENTITY_PREFIX = 200
IDENTITY_HASH = 16

# Falco's own housekeeping records (metrics snapshots, drop reports) are not rule matches.
INTERNAL_RULE = "Falco internal: metrics snapshot"
INTERNAL_SOURCE = "internal"

OCSF_PROCESS_ACTIVITY = 1007
OCSF_FILE_SYSTEM_ACTIVITY = 1001

_SEVERITY: dict[str, Severity] = {
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "notice": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,  # the spelling Falco's own docs use for good-practice rules
    "debug": Severity.INFORMATIONAL,
}

# ASCII-only classes: ``\d`` would also match non-ASCII digits. Used with fullmatch on input
# already capped at MAX_TAG, so a trailing newline never sneaks past ``$``.
_TECHNIQUE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
_TACTIC = re.compile(r"mitre_[a-z_]{1,64}")
_UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")

_EXEC_EVENTS = frozenset({"execve", "execveat"})
# Syscalls that act on a file path; with file fields present they make a file.access.
_FILE_EVENTS = frozenset(
    {
        "open", "openat", "openat2", "creat", "unlink", "unlinkat", "rename", "renameat",
        "renameat2", "mkdir", "mkdirat", "rmdir", "chmod", "fchmod", "fchmodat", "chown",
        "fchown", "fchownat", "lchown", "link", "linkat", "symlink", "symlinkat", "truncate",
        "ftruncate",
    }
)  # fmt: skip
_IP_FIELDS = ("fd.cip", "fd.sip", "fd.rip", "fd.lip")
# Only an explicit "syscall" source is a syscall record; a missing or invalid source is unknown.
_SYSCALL_SOURCES = ("syscall",)
# Syscalls whose fd is a socket: fd.name is a socket tuple or a unix socket path, not a file.
_SOCKET_EVENTS = frozenset(
    {
        "socket", "socketpair", "connect", "accept", "accept4", "bind", "listen", "sendto",
        "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "getsockopt", "setsockopt",
        "shutdown",
    }
)  # fmt: skip
_SOCKET_FD_TYPES = frozenset({"unix", "ipv4", "ipv6"})
_KNOWN_TOP = frozenset(
    {"time", "rule", "priority", "source", "tags", "hostname", "output", "output_fields", "uuid"}
)


def _text(max_len: int) -> Callable[[object], str | None]:
    def conv(value: object) -> str | None:
        s = bounded_str(value, max_len)
        return s if s else None

    return conv


def _int_range(lo: int, hi: int) -> Callable[[object], int | None]:
    def conv(value: object) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value if lo <= value <= hi else None

    return conv


def _uid(value: object) -> str | None:
    # OCSF ``user.uid`` is a string; Falco reports a UINT32.
    n = _int_range(0, 2**32 - 1)(value)
    return None if n is None else str(n)


def _ip(value: object) -> str | None:
    key = ip_key(value)
    return key.removeprefix("ip:") if key else None


def _container_id(value: object) -> str | None:
    # Falco reports container.id "host" for processes outside any container.
    s = _text(128)(value)
    return None if s == "host" else s


def _path(value: object) -> str | None:
    s = _text(4096)(value)
    return s if s and s.startswith("/") else None


_NAME = _text(256)
_LONG = _text(4096)
_PID = _int_range(0, 2**63 - 1)
_PORT = _int_range(0, 65535)

# output_fields key -> (attribute path, converter). A field is "mapped" only when its value
# passes the converter and lands in attributes; anything else stays in unmapped verbatim.
_FIELD_MAP: dict[str, tuple[tuple[str, ...], Callable[[object], Any]]] = {
    "proc.name": (("process", "name"), _NAME),
    "proc.pid": (("process", "pid"), _PID),
    "proc.cmdline": (("process", "cmd_line"), _LONG),
    "proc.exepath": (("process", "file", "path"), _LONG),
    "proc.pname": (("process", "parent_process", "name"), _NAME),
    "proc.ppid": (("process", "parent_process", "pid"), _PID),
    "user.name": (("actor", "user", "name"), _NAME),
    "user.uid": (("actor", "user", "uid"), _uid),
    "container.id": (("container", "uid"), _container_id),
    "container.name": (("container", "name"), _NAME),
    "container.image.repository": (("container", "image", "name"), _text(512)),
    "container.image.tag": (("container", "image", "tag"), _NAME),
    "k8s.ns.name": (("k8s", "namespace"), _text(253)),
    "k8s.pod.name": (("k8s", "pod"), _text(253)),
    "fd.cip": (("src_endpoint", "ip"), _ip),
    "fd.cport": (("src_endpoint", "port"), _PORT),
    "fd.sip": (("dst_endpoint", "ip"), _ip),
    "fd.sport": (("dst_endpoint", "port"), _PORT),
    "fd.l4proto": (("connection_info", "protocol_name"), _text(16)),
}


def _put(target: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    node = target
    for part in path[:-1]:
        node = node.setdefault(part, {})
    node[path[-1]] = value


def _local_rules(options: Mapping[str, Any]) -> frozenset[str]:
    value = options.get("local_rules", ())
    if isinstance(value, str) or not isinstance(value, list | tuple | set | frozenset):
        raise AdapterError("adapter option local_rules must be a list of rule names")
    if len(value) > MAX_LOCAL_RULES or not all(isinstance(v, str) for v in value):
        raise AdapterError("adapter option local_rules must be a list of rule names")
    return frozenset(value)


def _attack_version(options: Mapping[str, Any]) -> str | None:
    value = options.get("attack_version")
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > MAX_ATTACK_VERSION:
        raise AdapterError("adapter option attack_version must be a short string")
    return value


def _epoch_ns(value: object) -> int | None:
    """A Falco epoch-nanosecond field (evt.time, proc.pid.ts) that parses to a valid time.

    A small int would be misread as seconds, so nanosecond magnitude is required.
    """
    if isinstance(value, int) and not isinstance(value, bool) and value > 10**17:
        if parse_timestamp_or_none(value) is not None:
            return value
    return None


def _event_time(
    fields: Mapping[str, Any], record_time: object
) -> tuple[datetime | None, int | None, bool]:
    """Return (event_time, evt.time in epoch ns when used, zone assumed UTC)."""
    evt = _epoch_ns(fields.get("evt.time"))
    if evt is not None:
        return parse_timestamp_or_none(evt), evt, False
    try:
        dt, zone_given = parse_timestamp_with_zone_flag(record_time)
    except ValueError:  # AdapterError is a ValueError
        return None, None, False
    return dt, None, not zone_given


def _start_time(fields: Mapping[str, Any]) -> datetime | None:
    ns = _epoch_ns(fields.get("proc.pid.ts"))
    return parse_timestamp_or_none(ns) if ns is not None else None


def _escape_char(ch: str) -> str:
    """Escape one character of a rule name; returns it unchanged when it is safe to show.

    The backslash is escaped first (as ``\\\\``) so the escaping is unambiguous: a literal
    ``A\\x01`` and ``A`` followed by U+0001 render differently.
    """
    if ch == "\\":
        return "\\\\"
    code = ord(ch)
    if code < 0x20 or 0x7F <= code < 0xA0:
        return f"\\x{code:02x}"
    if unicodedata.category(ch) == "Cf":  # bidi overrides, zero-width and other format chars
        return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"
    return ch


def _rule_identity(rule_full: str) -> tuple[str, str, bool, bool]:
    """Return (display rule, identity, truncated, had control or format characters)."""
    parts = [_escape_char(ch) for ch in rule_full]
    escaped = "".join(parts)
    control = any(len(p) > 1 and p != "\\\\" for p in parts)
    if len(escaped) <= MAX_RULE:
        return escaped, f"falco:{escaped}", False, control
    digest = hashlib.sha256(rule_full.encode("utf-8", "surrogatepass")).hexdigest()
    identity = f"falco:{escaped[:IDENTITY_PREFIX]}#{digest[:IDENTITY_HASH]}"
    return escaped[:MAX_RULE], identity, True, control


def _tags(value: object) -> tuple[list[str] | None, list[str], list[str]]:
    """Return (valid tags or None if not a list, ATT&CK technique ids, mitre_ tactic tags)."""
    if not isinstance(value, list):
        return None, [], []
    tags: list[str] = []
    attack: list[str] = []
    tactics: list[str] = []
    for item in value[:MAX_TAGS]:
        tag = bounded_str(item, MAX_TAG)
        if tag is None:
            continue
        tags.append(tag)
        if _TECHNIQUE.fullmatch(tag):
            if tag not in attack:
                attack.append(tag)
        elif _TACTIC.fullmatch(tag) and tag not in tactics:
            tactics.append(tag)
    return tags, attack, tactics


def _classify(source: str | None, fields: Mapping[str, Any], attrs: Mapping[str, Any]) -> str:
    """An OCSF class is only claimed when the event type says so and its attributes exist."""
    if source not in _SYSCALL_SOURCES:
        return "falco.event"
    evt_type = bounded_str(fields.get("evt.type"), 64)
    if evt_type in _EXEC_EVENTS and "process" in attrs:
        return "process.exec"
    if evt_type in _FILE_EVENTS and "file" in attrs:
        return "file.access"
    return "falco.event"


def _remote_source_ip(value: object) -> tuple[object, bool]:
    """Return (the address the API server saw, whether forwarded entries were present).

    The Kubernetes API server fills ``sourceIPs`` from X-Forwarded-For and X-Real-Ip first and
    appends the real remote address last, so every entry but the last is client-controlled.
    Only the last entry is trusted, however long the list is.
    """
    if isinstance(value, list):
        return (value[-1] if value else None), len(value) > 1
    return (value if isinstance(value, str) else None), False


def _plugin_keys(fields: Mapping[str, Any]) -> tuple[tuple[str | None, ...], bool]:
    """Entity keys from k8s_audit and cloud plugin fields (validated by the entities helpers),
    and whether ``ka.sourceips`` carried forwarded (untrusted) entries."""
    namespace = fields.get("ka.target.namespace")
    pod = fields.get("ka.target.name") if fields.get("ka.target.resource") == "pods" else None
    remote, forwarded = _remote_source_ip(fields.get("ka.sourceips"))
    keys = (
        k8s_pod_key(namespace, pod),
        k8s_namespace_key(namespace),
        ip_key(fields.get("ct.srcip")),
        ip_key(remote),
    )
    return keys, forwarded


class FalcoAdapter:
    name = "falco"
    version = "1.0.0"

    def parse(self, raw: RawRecord, options: Mapping[str, Any]) -> ParseResult:
        local_rules = _local_rules(options)
        attack_version = _attack_version(options)
        record, json_flags = loads_object_flagged(raw.text())
        if "rule" not in record:
            return self._unknown(record, json_flags)

        rule_full = record["rule"]
        if not isinstance(rule_full, str) or not rule_full.strip():
            raise AdapterError("field 'rule' must be a non-empty string")
        rule, identity, rule_truncated, control = _rule_identity(rule_full)

        extras: dict[str, Any] = {k: v for k, v in record.items() if k not in _KNOWN_TOP}
        flags: list[str] = list(json_flags)
        if control:
            flags.append("control_chars")

        priority = bounded_str(record.get("priority"), 32)
        if priority is None and "priority" in record:
            extras["priority"] = record["priority"]
        severity = (
            _SEVERITY.get(priority.lower(), Severity.UNKNOWN) if priority else Severity.UNKNOWN
        )

        source = bounded_str(record.get("source"), 64) or None
        if source is None and "source" in record:
            extras["source"] = record["source"]

        raw_tags = record.get("tags")
        tags, attack, tactics = _tags(raw_tags)
        if "tags" in record and (
            not isinstance(raw_tags, list) or len(tags or []) != len(raw_tags)
        ):
            # Not a list, or some entries were not bounded strings: keep the original verbatim.
            extras["tags"] = raw_tags

        hostname = bounded_str(record.get("hostname"), 253) or None
        if hostname is None and "hostname" in record:
            extras["hostname"] = record["hostname"]

        uuid = record.get("uuid")
        correlation: dict[str, str] = {}
        if isinstance(uuid, str) and len(uuid) == 36 and _UUID.fullmatch(uuid):
            correlation["falco.uuid"] = uuid
        elif "uuid" in record:
            extras["uuid"] = uuid

        raw_fields = record.get("output_fields")
        fields: dict[str, Any]
        if isinstance(raw_fields, dict):
            fields = raw_fields
        else:
            fields = {}
            if raw_fields is None:
                flags.append("output_fields_missing")
            else:
                extras["output_fields"] = raw_fields
                flags.append("output_fields_invalid")

        event_time, event_time_ns, zone_assumed = _event_time(fields, record.get("time"))
        if event_time is None:
            flags.append("event_time_missing")
        if zone_assumed:
            flags.append("timezone_assumed_utc")
        if "time" in record:
            # The record time keeps its full (nanosecond) precision as Falco rendered it.
            extras["time"] = record["time"]

        attrs: dict[str, Any] = {}
        unmapped_fields: dict[str, Any] = {}
        for key, value in fields.items():
            spec = _FIELD_MAP.get(key)
            converted = spec[1](value) if spec else None
            if spec is None or converted is None:
                unmapped_fields[key] = value
                continue
            _put(attrs, spec[0], converted)
        if event_time_ns is not None:
            attrs["event_time_ns"] = event_time_ns

        fd_path = _path(fields.get("fd.name"))
        socket_fd = (
            "src_endpoint" in attrs
            or "dst_endpoint" in attrs
            or bounded_str(fields.get("fd.type"), 16) in _SOCKET_FD_TYPES
            or bounded_str(fields.get("evt.type"), 64) in _SOCKET_EVENTS
        )
        if fd_path is not None and not socket_fd:
            attrs["file"] = {"path": fd_path}
            unmapped_fields.pop("fd.name", None)
        elif (fs_path := _path(fields.get("fs.path.name"))) is not None:
            attrs["file"] = {"path": fs_path}
            unmapped_fields.pop("fs.path.name", None)

        internal = rule_full == INTERNAL_RULE or source == INTERNAL_SOURCE
        # For syscall and internal records the hostname is the monitored node; for plugin
        # sources, or a missing/invalid source, it is only the Falco instance that reported.
        asset_host = hostname if (internal or source in _SYSCALL_SOURCES) else None
        if asset_host is not None:
            attrs["device"] = {"hostname": asset_host}
        elif hostname is not None:
            attrs["metadata"] = {"collector": hostname}
        kind = "falco.internal" if internal else _classify(source, fields, attrs)
        ocsf_class = {
            "process.exec": OCSF_PROCESS_ACTIVITY,
            "file.access": OCSF_FILE_SYSTEM_ACTIVITY,
        }.get(kind)

        cid = community_id(
            fields.get("fd.l4proto"),
            fields.get("fd.cip"),
            fields.get("fd.cport"),
            fields.get("fd.sip"),
            fields.get("fd.sport"),
        )

        unmapped: dict[str, Any] = {}
        if unmapped_fields:
            unmapped["output_fields"] = unmapped_fields
        output = record.get("output")
        output_text = output[:MAX_OUTPUT] if isinstance(output, str) else None
        output_truncated = isinstance(output, str) and len(output) > MAX_OUTPUT
        if output_text is None and "output" in record:
            extras["output"] = output
        elif internal and output_text is not None:
            # No detection carries it, and Falco itself (not a rule author) wrote it.
            unmapped["output"] = output_text
            if output_truncated:
                flags.append("output_truncated")
        if internal:
            # With no detection to carry them, the rule identity fields stay on the observation.
            extras["rule"] = rule
            for key in ("priority", "source", "tags"):
                if key in record:
                    extras.setdefault(key, record[key])
        if extras:
            unmapped["record"] = extras

        namespace = fields.get("k8s.ns.name")
        plugin_keys, forwarded = _plugin_keys(fields)
        if forwarded:
            flags.append("source_ips_forwarded")
        entity_keys = unique(
            host_key(asset_host),
            k8s_pod_key(namespace, fields.get("k8s.pod.name")),
            k8s_namespace_key(namespace),
            image_key(fields.get("container.image.repository")),
            image_digest_key(fields.get("container.image.digest")),
            process_key(asset_host, fields.get("proc.pid"), _start_time(fields)),
            *(ip_key(fields.get(k)) for k in _IP_FIELDS),
            *plugin_keys,
        )

        observation = ObservationDraft(
            kind=kind,
            event_time=event_time,
            attributes=attrs,
            ocsf_class_uid=ocsf_class,
            unmapped=unmapped,
            entity_keys=entity_keys,
            community_id=cid,
            correlation=correlation,
            flags=tuple(flags),
        )

        if internal:
            # Not a security verdict: keep the facts, emit no detection.
            return ParseResult(observations=(observation,))

        local = rule_full in local_rules
        explanation: dict[str, Any] = {
            "summary": "Falco rule matched",
            "matched_rule": rule,
            "priority": priority,
            "source": source,
        }
        if output_text is not None:
            # The rule author's template, filled with attacker-influenced values.
            explanation["output"] = output_text
            if output_truncated:
                explanation["output_truncated"] = True
        if attack:
            explanation["attack_tags"] = attack
        if tactics:
            explanation["mitre_tactics"] = tactics
        if rule_truncated:
            explanation["rule_truncated"] = True
        if control:
            explanation["rule_control_chars_escaped"] = True
        if local:
            explanation["authorship_reason"] = "rule listed in adapter option local_rules"

        detection = DetectionDraft(
            kind="falco.rule",
            authorship=Authorship.LOCAL if local else Authorship.COMMUNITY,
            identity=identity,
            title=rule,
            severity=severity,
            event_time=event_time,
            rule_ref={
                "engine": "falco",
                "rule": rule,
                "priority": priority,
                "source": source,
                "tags": tags if tags is not None else [],
                "attack_version": attack_version,
            },
            attack=tuple(attack),
            entity_keys=entity_keys,
            observation_refs=(0,),
            explanation=explanation,
        )
        return ParseResult(observations=(observation,), detections=(detection,))

    def _unknown(self, record: dict[str, Any], flags: tuple[str, ...]) -> ParseResult:
        return ParseResult(
            observations=(
                ObservationDraft(
                    kind="falco.unknown",
                    event_time=parse_timestamp_or_none(record.get("time")),
                    attributes={},
                    unmapped=record,
                    flags=("no_rule", *flags),
                ),
            )
        )


ADAPTER = FalcoAdapter()
register(ADAPTER)
