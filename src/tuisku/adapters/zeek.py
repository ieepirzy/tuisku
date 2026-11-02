"""Zeek JSON log adapter (ADR 0005).

Input is one line of a Zeek JSON log (``LogAscii::use_json=T``): a flat object with dotted
connection keys (``"id.orig_h"``) and ``ts`` as epoch seconds (the default), ISO 8601
(``JSON::TS_ISO8601``) or integer epoch milliseconds (``JSON::TS_MILLIS``).

The log type comes from the adapter option ``log`` (one source per log stream), then the record's
own ``_path`` field, then a valid notice ``note`` or weird ``name`` (verdicts are never demoted to
unknown; extra fields only add a ``log_type_ambiguous`` flag), then the record's characteristic
fields. A record that matches no type, or several, becomes a ``zeek.unknown`` observation; nothing
is guessed. ``collector.path`` is receipt metadata and is never used.

Field names follow the ``Info`` records of the upstream scripts (``base/protocols/{conn,dns,http,
ssl}/main.zeek``, ``base/frameworks/files/main.zeek``, ``base/files/hash/main.zeek``,
``base/protocols/http/entities.zeek``, ``base/frameworks/notice/{main,weird}.zeek`` and
``policy/protocols/conn/community-id-logging.zeek``).

Facts become observations (``network.flow``, ``dns.answer``, ``http.request``,
``tls.handshake``, ``file.transfer``); ``notice`` and ``weird`` are Zeek's own verdicts and become
``builtin`` detections that reference an observation of their connection context.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import math
import re
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
from tuisku.adapters.entities import domain_key, ip_key, sha256_key, unique
from tuisku.adapters.flows import check_reported, community_id, protocol_number
from tuisku.adapters.jsonsafe import bounded_str, loads_object_flagged
from tuisku.adapters.registry import register
from tuisku.adapters.timeparse import parse_timestamp_with_zone_flag

LOG_TYPES = ("conn", "dns", "http", "ssl", "files", "notice", "weird")

MAX_BODY = 256 * 1024  # ADR 0005 line limit, re-checked here
MAX_STR = 4096
MAX_URI = 8192
MAX_HOST = 1024
MAX_LIST = 1024  # list entries mapped; longer lists stay in unmapped
MAX_CORRELATED_FUIDS = 16
MAX_COUNT = 2**63 - 1

# Zeek uids/fuids are short base62 strings ("CHhAvVGS1DHFjwGM9", "F2xow8TIkvHG4Zz41").
_ZEEK_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# Notice types are enum names ("Scan::Port_Scan"); weird names are identifiers.
_NOTE = re.compile(r"^[A-Za-z0-9_]{1,64}(?:::[A-Za-z0-9_]{1,64}){0,4}$")
_WEIRD_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_HOST_PORT = re.compile(r"^([^:\[\]/]{1,1000}):(\d{1,5})$")

# (field, OCSF algorithm_id, algorithm, hex digits) from base/files/hash/main.zeek
_HASH_ALGORITHMS = (
    ("md5", 1, "MD5", 32),
    ("sha1", 2, "SHA-1", 40),
    ("sha256", 3, "SHA-256", 64),
)
_HEX = re.compile(r"^[0-9A-Fa-f]{32,64}$")

# Inference markers. signatures.log also has ``note``; krb.log has ``cipher``; snmp.log has a
# string ``version`` (base/frameworks/signatures/main.zeek, base/protocols/{krb,snmp}/main.zeek).
_SIGNATURE_MARKERS = (
    "sig_id",
    "event_msg",
    "sub_msg",
    "sig_count",
    "host_count",
    "src_addr",
    "dst_addr",
)
_KRB_MARKERS = (
    "request_type",
    "client",
    "success",
    "error_msg",
    "from",
    "till",
    "forwardable",
    "renewable",
)
_SNMP_MARKERS = (
    "community",
    "get_requests",
    "get_bulk_requests",
    "get_responses",
    "set_requests",
    "display_string",
    "up_since",
)
# ssl.log also records DTLS (UDP); only these version strings (base/protocols/ssl/consts.zeek)
# prove TLS over TCP.
_TCP_TLS_VERSION = re.compile(r"^(?:SSLv[23]|TLSv1[0-3](?:-draft\d{1,3})?)$")
# ``_path`` names that carry one of the supported formats.
_PATH_ALIASES = {"notice_alarm": "notice"}

Check = Callable[[Any], bool]

# Correlation values are tuples of exact ids, never joined.
Correlation = dict[str, tuple[str, ...]]


# --- value checks -------------------------------------------------------------------------------


def _is_str(max_len: int = MAX_STR) -> Check:
    return lambda v: bounded_str(v, max_len) is not None


def _is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_COUNT


def _is_number(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return 0 <= v <= MAX_COUNT
    return isinstance(v, float) and math.isfinite(v) and 0 <= v <= MAX_COUNT


def _is_bool(v: Any) -> bool:
    return isinstance(v, bool)


def _is_ip(v: Any) -> bool:
    if not isinstance(v, str) or len(v) > 64 or "%" in v:
        return False  # no IPv6 scope ids (``fe80::1%eth0``): not an address on the wire
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return False
    return True


def _is_port(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 65535


def _is_zeek_id(v: Any) -> bool:
    return isinstance(v, str) and _ZEEK_ID.match(v) is not None


def _is_str_list(max_len: int = MAX_STR) -> Check:
    def check(v: Any) -> bool:
        return (
            isinstance(v, list)
            and len(v) <= MAX_LIST
            and all(bounded_str(x, max_len) is not None for x in v)
        )

    return check


def _is_hex(digits: int) -> Check:
    return lambda v: isinstance(v, str) and len(v) == digits and _HEX.match(v) is not None


def _is_number_list(v: Any) -> bool:
    return isinstance(v, list) and len(v) <= MAX_LIST and all(_is_number(x) for x in v)


def _is_zeek_id_list(v: Any) -> bool:
    return isinstance(v, list) and len(v) <= MAX_LIST and all(_is_zeek_id(x) for x in v)


# --- record access ------------------------------------------------------------------------------


class _Record:
    """A decoded record that remembers which fields were mapped; the rest are ``unmapped``."""

    def __init__(self, data: dict[str, Any], input_flags: tuple[str, ...] = ()) -> None:
        self.data = data
        self.used: set[str] = set()
        self.input_flags = input_flags  # e.g. invalid_unicode_replaced from decoding

    def has(self, key: str) -> bool:
        return key in self.data

    def peek(self, key: str, check: Check) -> Any:
        value = self.data.get(key)
        return value if key in self.data and check(value) else None

    def take(self, key: str, check: Check) -> Any:
        """Return the value and mark it mapped if it passes ``check``; else leave it unmapped."""
        value = self.peek(key, check)
        if value is not None:
            self.used.add(key)
        return value

    def leftover(self) -> dict[str, Any]:
        return {k: v for k, v in self.data.items() if k not in self.used}


def _put(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None and value != {} and value != []:
        target[key] = value


def _event_time(rec: _Record) -> tuple[datetime | None, tuple[str, ...]]:
    if not rec.has("ts"):
        return None, ()
    value = rec.data["ts"]
    # JSON::TS_MILLIS writes integer epoch milliseconds; epoch seconds stay below 10**11.
    if isinstance(value, int) and not isinstance(value, bool) and 10**11 <= value < 10**14:
        value = value / 1000
    try:
        dt, zone_given = parse_timestamp_with_zone_flag(value)
    except AdapterError:
        return None, ("invalid_ts",)
    rec.used.add("ts")
    return dt, (() if zone_given else ("timezone_assumed_utc",))


def _ms(seconds: Any) -> int | None:
    return round(seconds * 1000) if seconds is not None else None


# --- log type selection -------------------------------------------------------------------------


def _has_conn_id(rec: _Record) -> bool:
    return any(rec.has(k) for k in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"))


def _has_any(rec: _Record, keys: tuple[str, ...]) -> bool:
    return any(rec.has(k) for k in keys)


def _is_signature(rec: _Record) -> bool:
    return rec.has("note") and _has_any(rec, _SIGNATURE_MARKERS)


def _is_valid_note(rec: _Record) -> bool:
    note = rec.data.get("note")
    return isinstance(note, str) and len(note) <= 256 and _NOTE.match(note) is not None


def _is_valid_weird_name(rec: _Record) -> bool:
    name = rec.data.get("name")
    return isinstance(name, str) and len(name) <= 256 and _WEIRD_NAME.match(name) is not None


def _candidates(rec: _Record) -> list[str]:
    """Every log type whose characteristic required fields the record carries."""
    found: list[str] = []
    if (rec.has("conn_state") or rec.has("history")) and _has_conn_id(rec):
        found.append("conn")
    if rec.has("query") or rec.has("trans_id"):
        found.append("dns")
    if rec.has("trans_depth") and (rec.has("method") or rec.has("status_code")):
        found.append("http")
    # ``cipher`` alone is krb.log and ``version`` alone is snmp.log (or http.log's "1.1", or
    # ssh.log's count), so ssl needs ``server_name`` or both, and no krb/snmp/http markers.
    ssl_fields = rec.has("server_name") or (
        rec.has("cipher") and isinstance(rec.data.get("version"), str)
    )
    if (
        ssl_fields
        and not rec.has("trans_depth")
        and not _has_any(rec, _KRB_MARKERS)
        and not _has_any(rec, _SNMP_MARKERS)
    ):
        found.append("ssl")
    # notice.log may carry a ``fuid`` too; ``note`` is notice-only.
    if rec.has("fuid") and not rec.has("note"):
        found.append("files")
    if rec.has("note") and not _is_signature(rec):
        found.append("notice")
    if rec.has("name") and (rec.has("addl") or isinstance(rec.data.get("notice"), bool)):
        found.append("weird")
    return found


# --- shared connection context ------------------------------------------------------------------


def _endpoint(ip: Any, port: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    _put(out, "ip", ip)
    _put(out, "port", port)
    return out


class _Conn:
    """The connection tuple, uid and community id shared by most Zeek logs."""

    def __init__(self, rec: _Record, *, map_proto: bool = True, assume_tcp: bool = False) -> None:
        self.orig_h = rec.take("id.orig_h", _is_ip)
        self.orig_p = rec.take("id.orig_p", _is_port)
        self.resp_h = rec.take("id.resp_h", _is_ip)
        self.resp_p = rec.take("id.resp_p", _is_port)
        self.uid = rec.take("uid", _is_zeek_id)
        self.proto = rec.take("proto", _is_str(32)) if map_proto else None
        self.proto_num = protocol_number(self.proto) if self.proto is not None else None
        flow_proto = self.proto_num
        assumed: tuple[str, ...] = ()
        if flow_proto is None and assume_tcp and not rec.has("proto"):
            # The log has no proto field but its analyzer only runs over TCP.
            flow_proto, assumed = 6, ("proto_assumed_tcp",)
        computed = None
        if flow_proto is not None:
            computed = community_id(flow_proto, self.orig_h, self.orig_p, self.resp_h, self.resp_p)
        # computed wins; a well-formed reported id is kept as unverified when there is no
        # complete tuple to check it against (e.g. weird.log has no proto).
        self.community_id, flags = check_reported(computed, rec.data.get("community_id"))
        self.flags = (assumed if computed is not None else ()) + flags

    def present(self) -> bool:
        return any(v is not None for v in (self.orig_h, self.orig_p, self.resp_h, self.resp_p))

    def attributes(self, extra_info: dict[str, Any] | None = None) -> dict[str, Any]:
        attrs: dict[str, Any] = {}
        _put(attrs, "src_endpoint", _endpoint(self.orig_h, self.orig_p))
        _put(attrs, "dst_endpoint", _endpoint(self.resp_h, self.resp_p))
        info: dict[str, Any] = {}
        _put(info, "uid", self.uid)
        _put(info, "protocol_name", self.proto)
        _put(info, "protocol_num", self.proto_num)
        _put(info, "community_uid", self.community_id)
        for key, value in (extra_info or {}).items():
            _put(info, key, value)
        _put(attrs, "connection_info", info)
        return attrs

    def entity_keys(self) -> list[str | None]:
        return [ip_key(self.orig_h), ip_key(self.resp_h)]

    def correlation(self) -> Correlation:
        return {"zeek.uid": (self.uid,)} if self.uid is not None else {}


def _ids(*lists: Any) -> tuple[str, ...]:
    """Exact ids from one or more id lists, deduplicated in first-seen order."""
    ids: dict[str, None] = {}
    for values in lists:
        for v in values or ():
            ids.setdefault(v, None)
    return tuple(ids)[:MAX_CORRELATED_FUIDS]


def _observation(
    kind: str,
    ocsf_class_uid: int | None,
    rec: _Record,
    conn: _Conn,
    event_time: datetime | None,
    attributes: dict[str, Any],
    *,
    info: dict[str, Any] | None = None,
    keys: list[str | None] | None = None,
    correlation: Correlation | None = None,
    flags: tuple[str, ...] = (),
    unmapped: dict[str, Any] | None = None,
) -> ObservationDraft:
    return ObservationDraft(
        kind=kind,
        event_time=event_time,
        attributes=conn.attributes(info) | attributes,
        ocsf_class_uid=ocsf_class_uid,
        unmapped=rec.leftover() if unmapped is None else unmapped,
        entity_keys=unique(*conn.entity_keys(), *(keys or [])),
        community_id=conn.community_id,
        correlation=conn.correlation() | (correlation or {}),
        flags=flags + conn.flags + rec.input_flags,
    )


# --- per-log mappings ---------------------------------------------------------------------------


def _parse_conn(rec: _Record) -> ParseResult:
    event_time, flags = _event_time(rec)
    conn = _Conn(rec)
    attrs: dict[str, Any] = {}
    _put(attrs, "duration", _ms(rec.take("duration", _is_number)))
    traffic: dict[str, Any] = {}
    _put(traffic, "bytes_out", rec.take("orig_bytes", _is_count))
    _put(traffic, "bytes_in", rec.take("resp_bytes", _is_count))
    _put(traffic, "packets_out", rec.take("orig_pkts", _is_count))
    _put(traffic, "packets_in", rec.take("resp_pkts", _is_count))
    _put(attrs, "traffic", traffic)
    info = {"flag_history": rec.take("history", _is_str(256))}
    obs = _observation("network.flow", 4001, rec, conn, event_time, attrs, info=info, flags=flags)
    return ParseResult(observations=(obs,))


def _parse_dns(rec: _Record) -> ParseResult:
    event_time, flags = _event_time(rec)
    conn = _Conn(rec)
    hostname = rec.take("query", _is_str(MAX_HOST))
    query: dict[str, Any] = {}
    _put(query, "hostname", hostname)
    _put(query, "type", rec.take("qtype_name", _is_str(64)))
    _put(query, "class", rec.take("qclass_name", _is_str(64)))
    _put(query, "packet_uid", rec.take("trans_id", _is_count))
    attrs: dict[str, Any] = {}
    _put(attrs, "query", query)
    rcode = rec.take("rcode", _is_count)
    if rcode is not None and rcode <= 23:  # OCSF rcode_id mirrors the IANA codes 0-23
        attrs["rcode_id"] = rcode
    elif rcode is not None:
        rec.used.discard("rcode")
    _put(attrs, "rcode", rec.take("rcode_name", _is_str(64)))
    answers = rec.take("answers", _is_str_list(MAX_HOST))
    ttls = rec.peek("TTLs", _is_number_list)
    keys: list[str | None] = []
    if answers is not None:
        if ttls is not None and len(ttls) == len(answers):
            rec.used.add("TTLs")
            attrs["answers"] = [
                {"rdata": a, "ttl": round(t)} for a, t in zip(answers, ttls, strict=True)
            ]
        else:
            attrs["answers"] = [{"rdata": a} for a in answers]
        keys.extend(ip_key(a) for a in answers if _is_ip(a))
    obs = _observation(
        "dns.answer",
        4003,
        rec,
        conn,
        event_time,
        attrs,
        keys=[domain_key(hostname), *keys],
        flags=flags,
    )
    return ParseResult(observations=(obs,))


def _split_host(host: str) -> tuple[str, int | None]:
    m = _HOST_PORT.match(host)
    if m is not None and int(m.group(2)) <= 65535:
        return m.group(1), int(m.group(2))
    return host, None


def _parse_http(rec: _Record) -> ParseResult:
    event_time, flags = _event_time(rec)
    conn = _Conn(rec, map_proto=False, assume_tcp=True)  # Zeek's HTTP analyzer is TCP-only
    url: dict[str, Any] = {}
    host = rec.take("host", _is_str(MAX_HOST))
    hostname = None
    if host is not None:
        hostname, port = _split_host(host)
        url["hostname"] = hostname
        _put(url, "port", port)
    uri = rec.take("uri", _is_str(MAX_URI))
    if uri is not None:
        path, sep, query_string = uri.partition("?")
        url["path"] = path
        if sep:
            url["query_string"] = query_string
    request: dict[str, Any] = {}
    _put(request, "http_method", rec.take("method", _is_str(64)))
    _put(request, "url", url)
    _put(request, "user_agent", rec.take("user_agent", _is_str()))
    _put(request, "referrer", rec.take("referrer", _is_str(MAX_URI)))
    _put(request, "version", rec.take("version", _is_str(32)))
    _put(request, "length", rec.take("request_body_len", _is_count))
    response: dict[str, Any] = {}
    _put(response, "code", rec.take("status_code", _is_count))
    _put(response, "message", rec.take("status_msg", _is_str()))
    _put(response, "length", rec.take("response_body_len", _is_count))
    attrs: dict[str, Any] = {}
    _put(attrs, "http_request", request)
    _put(attrs, "http_response", response)
    fuids = _ids(rec.peek("resp_fuids", _is_zeek_id_list), rec.peek("orig_fuids", _is_zeek_id_list))
    obs = _observation(
        "http.request",
        4002,
        rec,
        conn,
        event_time,
        attrs,
        keys=[domain_key(hostname)],
        correlation={"zeek.fuid": fuids} if fuids else {},
        flags=flags,
    )
    return ParseResult(observations=(obs,))


def _parse_ssl(rec: _Record) -> ParseResult:
    event_time, flags = _event_time(rec)
    version = rec.peek("version", _is_str(64))
    # ssl.log also records DTLS; assume TCP only when the version string rules that out.
    tcp_only = version is not None and _TCP_TLS_VERSION.match(version) is not None
    conn = _Conn(rec, map_proto=False, assume_tcp=tcp_only)
    sni = rec.take("server_name", _is_str(MAX_HOST))
    tls: dict[str, Any] = {}
    _put(tls, "version", rec.take("version", _is_str(64)))
    _put(tls, "cipher", rec.take("cipher", _is_str(256)))
    _put(tls, "sni", sni)
    attrs: dict[str, Any] = {}
    _put(attrs, "tls", tls)
    obs = _observation(
        "tls.handshake",
        4001,
        rec,
        conn,
        event_time,
        attrs,
        keys=[domain_key(sni)],
        flags=flags,
    )
    return ParseResult(observations=(obs,))


def _parse_files(rec: _Record) -> ParseResult:
    event_time, flags = _event_time(rec)
    conn = _Conn(rec, map_proto=False)
    fuid = rec.take("fuid", _is_zeek_id)
    file: dict[str, Any] = {}
    _put(file, "uid", fuid)
    _put(file, "name", rec.take("filename", _is_str()))
    _put(file, "mime_type", rec.take("mime_type", _is_str(256)))
    _put(file, "size", rec.take("total_bytes", _is_count))
    hashes: list[dict[str, Any]] = []
    for field, algorithm_id, algorithm, digits in _HASH_ALGORITHMS:
        value = rec.take(field, _is_hex(digits))
        if value is not None:
            hashes.append({"algorithm_id": algorithm_id, "algorithm": algorithm, "value": value})
    _put(file, "hashes", hashes)
    attrs: dict[str, Any] = {}
    _put(attrs, "file", file)
    keys: list[str | None] = [sha256_key(rec.data.get("sha256"))]
    # Zeek < 5 logged hosts and connections as sets instead of ``id``/``uid``.
    for legacy in ("tx_hosts", "rx_hosts"):
        hosts = rec.peek(legacy, _is_str_list(64))
        keys.extend(ip_key(h) for h in hosts or () if _is_ip(h))
    correlation: Correlation = {}
    if fuid is not None:
        correlation["zeek.fuid"] = (fuid,)
    if conn.uid is None:
        uids = _ids(rec.peek("conn_uids", _is_zeek_id_list))
        if uids:
            correlation["zeek.uid"] = uids
    obs = _observation(
        "file.transfer",
        1001,
        rec,
        conn,
        event_time,
        attrs,
        keys=keys,
        correlation=correlation,
        flags=flags,
    )
    return ParseResult(observations=(obs,))


def _context(
    rec: _Record, event_time: datetime | None, extra_correlation: Correlation
) -> tuple[_Conn, ObservationDraft | None]:
    """The connection a notice or weird was raised on, as a ``network.flow`` fact."""
    used = set(rec.used)
    conn = _Conn(rec)
    if not conn.present():
        # No connection to describe: uid/proto stay with the detection's unmapped fields.
        rec.used = used
        return conn, None
    obs = _observation(
        "network.flow",
        4001,
        rec,
        conn,
        event_time,
        {},
        correlation=extra_correlation,
        flags=("connection_context",),
        unmapped={},
    )
    return conn, obs


def _local_names(options: Mapping[str, Any], key: str) -> frozenset[str]:
    value = options.get(key)
    if value is None:
        return frozenset()
    if not isinstance(value, list | tuple) or not all(isinstance(v, str) for v in value):
        raise AdapterError(f"adapter option {key!r} must be a list of strings")
    return frozenset(value)


def _verdict(
    rec: _Record,
    *,
    log: str,
    identity_field: str,
    identity_check: re.Pattern[str],
    explanation_fields: tuple[tuple[str, Check], ...],
    severity: Severity,
    authorship: Authorship,
    candidates: list[str],
) -> ParseResult:
    name = rec.peek(identity_field, _is_str(256))
    if name is None or identity_check.match(name) is None:
        raise AdapterError(f"{log} record has a missing or invalid {identity_field!r}")
    rec.used.add(identity_field)
    event_time, flags = _event_time(rec)
    attributes: dict[str, Any] = {}
    if candidates:
        # The record also looks like another log; the verdict is kept, the doubt recorded.
        flags += ("log_type_ambiguous",)
        attributes["log_type_candidates"] = candidates
    if flags or rec.input_flags:
        attributes["flags"] = [*flags, *rec.input_flags]
    fuid = rec.peek("fuid", _is_zeek_id)
    conn, context = _context(rec, event_time, {"zeek.fuid": (fuid,)} if fuid else {})
    if context is not None and flags:
        context = dataclasses.replace(context, flags=context.flags + flags)
    explanation: dict[str, Any] = {"sensor": "zeek", "log": log, identity_field: name}
    keys: list[str | None] = list(conn.entity_keys())
    for field, check in explanation_fields:
        value = rec.take(field, check)
        if value is not None:
            explanation[field] = value
    if log == "notice":
        keys += [ip_key(explanation.get("src")), ip_key(explanation.get("dst"))]
    leftover = rec.leftover()
    detection = DetectionDraft(
        kind=f"zeek.{log}",
        authorship=authorship,
        identity=f"zeek:{log}:{name}",
        title=f"Zeek {log}: {name}",
        severity=severity,
        event_time=event_time,
        rule_ref={"engine": "zeek", "log": log, identity_field: name},
        attributes=attributes | ({"unmapped": leftover} if leftover else {}),
        entity_keys=unique(*keys),
        observation_refs=(0,) if context is not None else (),
        explanation=explanation,
    )
    return ParseResult(
        observations=(context,) if context is not None else (), detections=(detection,)
    )


_NOTICE_EXPLANATION: tuple[tuple[str, Check], ...] = (
    ("msg", _is_str()),
    ("sub", _is_str()),
    ("src", _is_ip),
    ("dst", _is_ip),
    ("p", _is_port),
    ("n", _is_count),
    ("actions", _is_str_list(128)),
)
_WEIRD_EXPLANATION: tuple[tuple[str, Check], ...] = (
    ("addl", _is_str()),
    ("notice", _is_bool),
    ("peer", _is_str(256)),
    ("source", _is_str(64)),
)


def _parse_notice(rec: _Record, options: Mapping[str, Any], candidates: list[str]) -> ParseResult:
    note = rec.data.get("note")
    local = isinstance(note, str) and note in _local_names(options, "local_notes")
    return _verdict(
        rec,
        log="notice",
        identity_field="note",
        identity_check=_NOTE,
        explanation_fields=_NOTICE_EXPLANATION,
        severity=Severity.MEDIUM,
        authorship=Authorship.LOCAL if local else Authorship.BUILTIN,
        candidates=candidates,
    )


def _parse_weird(rec: _Record, candidates: list[str]) -> ParseResult:
    return _verdict(
        rec,
        log="weird",
        identity_field="name",
        identity_check=_WEIRD_NAME,
        explanation_fields=_WEIRD_EXPLANATION,
        severity=Severity.INFORMATIONAL,
        authorship=Authorship.BUILTIN,
        candidates=candidates,
    )


def _parse_unknown(rec: _Record, candidates: list[str], *, path: str | None = None) -> ParseResult:
    event_time, ts_flags = _event_time(rec)
    conn = _Conn(rec)
    attrs: dict[str, Any] = {}
    flag = "log_type_unknown"
    if path is not None:
        flag = "log_type_unsupported"  # the record's own _path names a log we do not parse
    elif candidates:
        attrs["log_type_candidates"] = candidates
        flag = "log_type_ambiguous"
    obs = ObservationDraft(
        kind="zeek.unknown",
        event_time=event_time,
        attributes=attrs,
        ocsf_class_uid=None,
        unmapped=dict(rec.data),  # nothing is mapped for an unknown record
        entity_keys=unique(*conn.entity_keys()),
        community_id=conn.community_id,
        correlation=conn.correlation(),
        flags=(flag, *ts_flags, *conn.flags, *rec.input_flags),
    )
    return ParseResult(observations=(obs,))


class ZeekAdapter:
    name = "zeek"
    version = "1.0.0"

    def parse(self, raw: RawRecord, options: Mapping[str, Any]) -> ParseResult:
        if len(raw.body) > MAX_BODY:
            raise AdapterError(f"record larger than {MAX_BODY} bytes")
        log = options.get("log")
        if log is not None and log not in LOG_TYPES:
            raise AdapterError("adapter option 'log' must be one of " + ", ".join(LOG_TYPES))
        rec = _Record(*loads_object_flagged(raw.text()))
        candidates = _candidates(rec)
        ambiguous: list[str] = []  # only an inferred type can be ambiguous
        if log is None:
            # Precedence: the source's ``log`` option, the record's own ``_path``, a valid notice
            # ``note`` or weird ``name`` (sites extend these logs, and a verdict is never
            # demoted to unknown), then the characteristic fields.
            path = rec.peek("_path", _is_str(64))
            if path is not None:
                log = _PATH_ALIASES.get(path, path)
                if log not in LOG_TYPES:
                    return _parse_unknown(rec, candidates, path=path)
            elif "notice" in candidates and _is_valid_note(rec):
                log = "notice"
                ambiguous = candidates if len(candidates) > 1 else []
            elif "weird" in candidates and _is_valid_weird_name(rec):
                log = "weird"
                ambiguous = candidates if len(candidates) > 1 else []
            elif len(candidates) == 1:
                log = candidates[0]
            else:
                return _parse_unknown(rec, candidates)
        if log == "conn":
            return _parse_conn(rec)
        if log == "dns":
            return _parse_dns(rec)
        if log == "http":
            return _parse_http(rec)
        if log == "ssl":
            return _parse_ssl(rec)
        if log == "files":
            return _parse_files(rec)
        if log == "notice":
            return _parse_notice(rec, options, ambiguous)
        return _parse_weird(rec, ambiguous)


ADAPTER = ZeekAdapter()
register(ADAPTER)
