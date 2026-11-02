"""Suricata EVE JSON adapter (ADR 0005).

One EVE line is one raw record. Handled ``event_type`` values: ``alert``, ``flow``, ``dns``
(v2 and the Suricata 8 default v3 shape), ``http``, ``tls``, ``fileinfo`` and ``anomaly``. Any
other type, and records without one, become ``suricata.unknown`` observations.

Layer split (ADR 0002): an ``alert`` becomes one observation holding the packet/flow facts
(5-tuple, flow counters, app-layer fields) and one ``suricata.alert`` detection that references
it and holds the rule verdict. An ``anomaly`` becomes an observation (the packet facts and
what Suricata's engine reported) plus a ``builtin`` ``suricata.anomaly`` detection.

Orientation: observations always present the flow's client as ``src_endpoint``. The evidence,
in order: an alert's ``flow`` object (Suricata 7+ logs the flow's src/dest there), the alert's
``direction``, then what Suricata's logger guarantees for the event type (``flow``, ``http``
and ``tls`` are written client->server; DNS requests are client->server and v3 responses come
from the responder). Otherwise the packet direction is kept and ``orientation_unknown`` is set
(``fileinfo`` and ``anomaly`` are written in packet/transfer direction without saying which).

Mapping style: every mapped field is removed from the decoded record (which the adapter owns);
nested items are mapped from copies, so whatever is left, including values that failed
validation, is kept verbatim in ``unmapped``.

Field names follow https://docs.suricata.io/en/latest/output/eve/eve-json-format.html and
https://docs.suricata.io/en/latest/upgrade/8.0-dns-logging-changes.html.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from tuisku.adapters.base import (
    AdapterError,
    Authorship,
    DetectionDraft,
    LimitExceeded,
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

MAX_BODY = 256 * 1024
Ranges = tuple[tuple[int, int], ...]
DEFAULT_LOCAL_SID_RANGES: Ranges = ((1_000_000, 1_999_999),)
# Suricata's own decoder, stream and app-layer event rules (ADR 0002).
DEFAULT_BUILTIN_SID_RANGES: Ranges = ((2_200_000, 2_299_999),)
_MAX_SID = 2**32 - 1
_MAX_U64 = 2**64 - 1
_MAX_ATTACK_IDS = 32
_MAX_SID_RANGES = 64

_ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$", re.ASCII)
_EVENT_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,128}", re.ASCII)
_NAME_PART = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)  # anomaly identity parts: no ':'
_ATTACK_VERSION = re.compile(r"v?[0-9]{1,3}(\.[0-9]{1,3}){0,2}", re.ASCII)
_SHA1_COLONS = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){19}", re.ASCII)
_MD5 = re.compile(r"[0-9a-f]{32}", re.ASCII)
_SHA1 = re.compile(r"[0-9a-f]{40}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)

_ALERT_SEVERITY = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}
# OCSF dns rcode_id follows the DNS RCODE registry for 0-10.
_RCODE_IDS = {
    "NOERROR": 0,
    "FORMERR": 1,
    "SERVFAIL": 2,
    "NXDOMAIN": 3,
    "NOTIMP": 4,
    "REFUSED": 5,
    "YXDOMAIN": 6,
    "YXRRSET": 7,
    "NXRRSET": 8,
    "NOTAUTH": 9,
    "NOTZONE": 10,
}

OCSF_NETWORK = 4001
OCSF_HTTP = 4002
OCSF_DNS = 4003
OCSF_FILE = 1001

Record = dict[str, Any]
Keys = list[str | None]


# --- small validators: return the cleaned value, or None if the value is unusable ----------


def _str(max_len: int) -> Callable[[object], str | None]:
    def conv(value: object) -> str | None:
        s = bounded_str(value, max_len)
        return s if s else None

    return conv


def _uint(max_value: int) -> Callable[[object], int | None]:
    def conv(value: object) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value if 0 <= value <= max_value else None

    return conv


def _ip(value: object) -> str | None:
    # Length is capped before parsing; scoped IPv6 (``fe80::1%eth0``) is not an endpoint
    # address Suricata writes, and its scope would be attacker text inside a key.
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        # CPython patch releases disagree on how .compressed renders these; pin one form.
        return f"::ffff:{addr.ipv4_mapped}"
    return addr.compressed


def _hexdigest(pattern: re.Pattern[str]) -> Callable[[object], str | None]:
    def conv(value: object) -> str | None:
        if not isinstance(value, str) or len(value) > 128:
            return None
        digest = value.strip().lower()
        return digest if pattern.fullmatch(digest) else None

    return conv


def _parse_time(value: object) -> tuple[datetime, bool] | None:
    """(UTC datetime, zone_given). EVE times are strings; numbers are not taken as epochs."""
    if not isinstance(value, str):
        return None
    try:
        return parse_timestamp_with_zone_flag(value)
    except AdapterError:
        return None


def _time(value: object) -> str | None:
    """For certificate validity dates, which Suricata writes in UTC without a zone."""
    parsed = _parse_time(value)
    return parsed[0].isoformat() if parsed else None


def _take(d: Record, key: str, conv: Callable[[object], Any]) -> Any:
    """Return the converted value and remove the key; leave the key in place if invalid."""
    if key not in d:
        return None
    value = conv(d[key])
    if value is not None:
        del d[key]
    return value


def _sub(d: Record, key: str) -> Record | None:
    value = d.get(key)
    return value if isinstance(value, dict) else None


def _prune(d: Record, key: str) -> None:
    """Drop a sub-object once everything in it was mapped."""
    if isinstance(d.get(key), dict | list) and not d[key]:
        del d[key]


def _compact(d: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None and v != {} and v != []}


# --- options ------------------------------------------------------------------------------


def _ranges(options: Mapping[str, Any], name: str, default: Ranges) -> Ranges:
    value = options.get(name)
    if value is None:
        return default
    if not isinstance(value, list | tuple) or len(value) > _MAX_SID_RANGES:
        raise AdapterError(f"option {name} must be a list of at most {_MAX_SID_RANGES} pairs")
    ranges: list[tuple[int, int]] = []
    sid = _uint(_MAX_SID)
    for item in value:
        if not isinstance(item, list | tuple) or len(item) != 2:
            raise AdapterError(f"option {name} must be a list of [lo, hi] pairs")
        lo, hi = sid(item[0]), sid(item[1])
        if lo is None or hi is None or lo > hi:
            raise AdapterError(f"option {name} has an invalid range")
        ranges.append((lo, hi))
    return tuple(ranges)


@dataclass(frozen=True, slots=True)
class _Options:
    local_sid_ranges: Ranges
    builtin_sid_ranges: Ranges
    attack_version: str | None

    @classmethod
    def parse(cls, options: Mapping[str, Any]) -> _Options:
        version = options.get("attack_version")
        if version is not None and not (
            isinstance(version, str) and _ATTACK_VERSION.fullmatch(version)
        ):
            raise AdapterError("option attack_version must look like 'v15' or '15.1'")
        return cls(
            local_sid_ranges=_ranges(options, "local_sid_ranges", DEFAULT_LOCAL_SID_RANGES),
            builtin_sid_ranges=_ranges(options, "builtin_sid_ranges", DEFAULT_BUILTIN_SID_RANGES),
            attack_version=version,
        )


# --- common fields ------------------------------------------------------------------------


def _same_end(ip: str | None, port: int | None, f_ip: str | None, f_port: int | None) -> bool:
    if ip is None or ip != f_ip:
        return False
    return port is None or f_port is None or port == f_port


def _flow_orientation(
    rec: Record, src: tuple[str | None, int | None], dst: tuple[str | None, int | None]
) -> bool | None:
    """Compare an alert's ``flow`` src/dest (the flow's client/server) with the packet tuple.

    Returns True when the packet went server -> client, False when client -> server, None when
    the flow object does not settle it. Consumed fields are removed from the flow object.
    """
    flow = _sub(rec, "flow")
    if flow is None:
        return None
    port = _uint(65535)
    f_src, f_dst = _ip(flow.get("src_ip")), _ip(flow.get("dest_ip"))
    f_sport, f_dport = port(flow.get("src_port")), port(flow.get("dest_port"))
    forward = _same_end(*src, f_src, f_sport) and _same_end(*dst, f_dst, f_dport)
    backward = _same_end(*dst, f_src, f_sport) and _same_end(*src, f_dst, f_dport)
    if forward == backward:  # neither, or symmetric (same address and ports both ends)
        return None
    client, server = (dst, src) if backward else (src, dst)
    for key, value in (
        ("src_ip", client[0]),
        ("dest_ip", server[0]),
        ("src_port", client[1]),
        ("dest_port", server[1]),
    ):
        conv = _ip if key.endswith("_ip") else port
        if key in flow and value is not None and conv(flow[key]) == value:
            del flow[key]
    return backward


class _Common:
    """Fields every EVE record shares: time, 5-tuple, flow id, community id, orientation.

    ``hint`` is what the event type guarantees about orientation (False: written
    client->server, True: written server->client, None: no guarantee).
    """

    def __init__(self, rec: Record, hint: bool | None = None, flags: tuple[str, ...] = ()) -> None:
        self.flags: list[str] = list(flags)
        self.correlation: dict[str, str] = {}
        self.attributes: dict[str, Any] = {}

        self.event_time: datetime | None = None
        if "timestamp" not in rec:
            self.flags.append("missing_timestamp")
        else:
            parsed = _parse_time(rec["timestamp"])
            if parsed is None:
                self.flags.append("invalid_timestamp")
            else:
                self.event_time, zone_given = parsed
                if not zone_given:
                    self.flags.append("timezone_assumed_utc")
                del rec["timestamp"]

        flow_id = _take(rec, "flow_id", _uint(_MAX_U64))
        if flow_id is not None:
            self.correlation["suricata.flow_id"] = str(flow_id)

        proto = _take(rec, "proto", _str(32))
        proto_num = protocol_number(proto)
        src_ip = _take(rec, "src_ip", _ip)
        dst_ip = _take(rec, "dest_ip", _ip)
        src_port = _take(rec, "src_port", _uint(65535))
        dst_port = _take(rec, "dest_port", _uint(65535))
        for field in ("flow_id", "src_ip", "dest_ip", "src_port", "dest_port"):
            if field in rec:  # present but not valid: left in unmapped
                self.flags.append(f"invalid_{field}")

        # Community ID is computed on the tuple as the packet carried it. For ICMP, Suricata
        # reports icmp_type/icmp_code, which play the ports (they stay in unmapped).
        if proto_num in (1, 58):
            cid_sport, cid_dport = rec.get("icmp_type"), rec.get("icmp_code")
        else:
            cid_sport, cid_dport = src_port, dst_port
        computed = community_id(proto_num, src_ip, cid_sport, dst_ip, cid_dport)
        self.community_id, cid_flags = check_reported(computed, rec.get("community_id"))
        self.flags.extend(cid_flags)
        if "community_id" in rec and not cid_flags:
            del rec["community_id"]  # equal to the computed value stored alongside
        # Any flagged reported value (mismatch, unverified, invalid) stays verbatim in unmapped.

        # Orientation (see module docstring). `direction` stays in unmapped: Suricata's
        # to_server/to_client is not OCSF's inbound/outbound.
        direction = rec.get("direction")
        reversed_ = _flow_orientation(rec, (src_ip, src_port), (dst_ip, dst_port))
        if reversed_ is None and direction in ("to_server", "to_client"):
            reversed_ = direction == "to_client"
        if reversed_ is None:
            reversed_ = hint
        if reversed_ is None and (src_ip or dst_ip):
            self.flags.append("orientation_unknown")
        if reversed_:
            src_ip, src_port, dst_ip, dst_port = dst_ip, dst_port, src_ip, src_port

        conn: dict[str, Any] = {}
        if proto is not None:
            conn["protocol_name"] = proto.lower()
            conn["protocol_num"] = proto_num
        if src_ip and dst_ip:
            v_src = ipaddress.ip_address(src_ip).version
            if v_src == ipaddress.ip_address(dst_ip).version:
                conn["protocol_ver_id"] = v_src
        self.attributes["src_endpoint"] = _compact({"ip": src_ip, "port": src_port})
        self.attributes["dst_endpoint"] = _compact({"ip": dst_ip, "port": dst_port})
        self.attributes["connection_info"] = _compact(conn)
        self.attributes["app_name"] = _take(rec, "app_proto", _str(64))
        self.keys: Keys = [ip_key(src_ip), ip_key(dst_ip)]

    def observation(self, kind: str, ocsf_class_uid: int | None, rec: Record) -> ObservationDraft:
        return ObservationDraft(
            kind=kind,
            event_time=self.event_time,
            attributes=_compact(self.attributes),
            ocsf_class_uid=ocsf_class_uid,
            unmapped=rec,
            entity_keys=unique(*self.keys),
            community_id=self.community_id,
            correlation=self.correlation,
            flags=unique(*self.flags),
        )


# --- sub-object mappers -------------------------------------------------------------------


def _map_flow(rec: Record, c: _Common) -> None:
    flow = _sub(rec, "flow")
    if flow is None:
        return
    count = _uint(_MAX_U64)
    to_server = (_take(flow, "pkts_toserver", count), _take(flow, "bytes_toserver", count))
    to_client = (_take(flow, "pkts_toclient", count), _take(flow, "bytes_toclient", count))
    # OCSF *_out is src -> dst, and src is the flow's client (see orientation).
    c.attributes["traffic"] = _compact(
        {
            "packets_out": to_server[0],
            "bytes_out": to_server[1],
            "packets_in": to_client[0],
            "bytes_in": to_client[1],
        }
    )
    for src, dst in (("start", "start_time_dt"), ("end", "end_time_dt")):
        parsed = _take(flow, src, _parse_time)
        if parsed is not None:
            c.attributes[dst] = parsed[0].isoformat()
            if not parsed[1]:
                c.flags.append("timezone_assumed_utc")
    age = _take(flow, "age", _uint(_MAX_U64))
    if age is not None:
        c.attributes["duration"] = age * 1000  # Suricata: seconds; OCSF: milliseconds
    _prune(rec, "flow")


def _map_http(rec: Record, c: _Common) -> bool:
    http = _sub(rec, "http")
    if http is None:
        return False
    url: dict[str, Any] = {}
    hostname = _take(http, "hostname", _str(1024))
    url["hostname"] = hostname
    url["port"] = _take(http, "http_port", _uint(65535))
    target = _take(http, "url", _str(8192))
    if target is not None:
        if target.startswith("/"):
            path, _, query = target.partition("?")
            url["path"] = path
            url["query_string"] = query or None
        else:
            url["url_string"] = target
    c.attributes["http_request"] = _compact(
        {
            "http_method": _take(http, "http_method", _str(32)),
            "url": _compact(url),
            "user_agent": _take(http, "http_user_agent", _str(4096)),
            "referrer": _take(http, "http_refer", _str(8192)),
            "version": _take(http, "protocol", _str(32)),
        }
    )
    c.attributes["http_response"] = _compact(
        {
            "code": _take(http, "status", _uint(999)),
            "content_type": _take(http, "http_content_type", _str(256)),
            "length": _take(http, "length", _uint(_MAX_U64)),
        }
    )
    c.keys.append(domain_key(hostname))
    _prune(rec, "http")
    return True


def _map_query(item: object) -> tuple[dict[str, Any], bool]:
    """Map a copy of one query; also say whether nothing of it was left unmapped."""
    if not isinstance(item, dict):
        return {}, False
    rest = dict(item)
    query = _compact(
        {"hostname": _take(rest, "rrname", _str(1024)), "type": _take(rest, "rrtype", _str(32))}
    )
    return query, not rest


def _map_answers(d: Record, c: _Common) -> list[dict[str, Any]]:
    answers = d.get("answers")
    if not isinstance(answers, list):
        return []
    mapped: list[dict[str, Any]] = []
    fully_mapped = True
    for answer in answers:
        if not isinstance(answer, dict):
            fully_mapped = False
            continue
        rest = dict(answer)
        m = _compact(
            {
                "rrname": _take(rest, "rrname", _str(1024)),  # differs along CNAME chains
                "type": _take(rest, "rrtype", _str(32)),
                "rdata": _take(rest, "rdata", _str(4096)),
                "ttl": _take(rest, "ttl", _uint(2**32 - 1)),
            }
        )
        if rest:  # soa/srv/sshfp objects, invalid values: keep the original list verbatim
            fully_mapped = False
        if m.get("type") == "CNAME":
            c.keys.append(domain_key(m.get("rdata")))
        if m:
            mapped.append(m)
    if fully_mapped:
        del d["answers"]
    return mapped


def _dns_is_response(dns: Record) -> bool | None:
    dns_type = dns.get("type")
    if dns_type in ("answer", "response"):
        return True
    if dns_type in ("query", "request"):
        return False
    return None


def _dns_hint(rec: Record) -> bool | None:
    """Orientation of a dns event: requests are client->server; v3 responses come from the
    responder (src_ip is the server), v2 responses were written client->server."""
    dns = _sub(rec, "dns")
    if dns is None:
        return None
    response = _dns_is_response(dns)
    if response is None or not response:
        return response
    return dns.get("type") == "response" or dns.get("version") == 3


def _map_dns_body(dns: Record, c: _Common) -> str:
    """Map one DNS object in v2 (top-level rrname) or v3 (``queries`` list) shape."""
    queries = dns.get("queries")
    if isinstance(queries, list):  # v3 (Suricata 8 default)
        query, consumed = _map_query(queries[0]) if queries else ({}, False)
        if consumed and len(queries) == 1:
            del dns["queries"]
    else:  # v2: the (first) query's rrname/rrtype sit at the top level
        query = _compact(
            {"hostname": _take(dns, "rrname", _str(1024)), "type": _take(dns, "rrtype", _str(32))}
        )
    packet_uid = _take(dns, "id", _uint(65535))
    opcode = _take(dns, "opcode", _uint(15))
    query = _compact(query | {"packet_uid": packet_uid, "opcode_id": opcode})
    c.keys.append(domain_key(query.get("hostname")))
    answers = _map_answers(dns, c)

    response = _dns_is_response(dns)
    if response is None:
        response = bool(answers)
    else:
        del dns["type"]
    if response:  # a request's rcode field is not an answer from anyone: left in unmapped
        rcode = _take(dns, "rcode", _str(32))
        if rcode is not None:
            c.attributes["rcode"] = rcode
            c.attributes["rcode_id"] = _RCODE_IDS.get(rcode.upper(), 99)

    c.attributes["activity_id"] = 2 if response else 1
    c.attributes["query"] = query
    c.attributes["answers"] = answers
    return "dns.answer" if response else "dns.query"


def _map_dns(rec: Record, c: _Common) -> str | None:
    dns = _sub(rec, "dns")
    if dns is None:
        return None
    # v2 alerts wrap the DNS data: dns.query is a list (requests), dns.answer an object.
    wrapped_query = dns.get("query")
    wrapped_answer = dns.get("answer")
    if isinstance(wrapped_answer, dict):
        kind = _map_dns_body(wrapped_answer, c)
        _prune(dns, "answer")
    elif isinstance(wrapped_query, list) and wrapped_query and isinstance(wrapped_query[0], dict):
        first = dict(wrapped_query[0])
        kind = _map_dns_body(first, c)
        if len(wrapped_query) == 1:
            if first:
                dns["query"] = [first]
            else:
                del dns["query"]
        # with several wrapped queries the list stays verbatim
    else:
        kind = _map_dns_body(dns, c)
    _prune(rec, "dns")
    return kind


def _fingerprint(algorithm: str, value: str | None) -> dict[str, str] | None:
    return {"algorithm": algorithm, "value": value} if value else None


def _map_tls(rec: Record, c: _Common) -> bool:
    tls = _sub(rec, "tls")
    if tls is None:
        return False
    sni = _take(tls, "sni", _str(1024))
    # Normalized to bare lowercase hex; the original stays in unmapped.
    raw_fp = tls.get("fingerprint")
    fingerprint = None
    if isinstance(raw_fp, str) and len(raw_fp) <= 64:
        fp = raw_fp.strip().lower()
        if _SHA1_COLONS.fullmatch(fp) or _SHA1.fullmatch(fp):
            fingerprint = fp.replace(":", "")
    cert = _compact(
        {
            "subject": _take(tls, "subject", _str(4096)),
            "issuer": _take(tls, "issuerdn", _str(4096)),
            "serial_number": _take(tls, "serial", _str(256)),
            "fingerprints": [_fingerprint("SHA-1", fingerprint)] if fingerprint else None,
            "created_time_dt": _take(tls, "notbefore", _time),
            "expiration_time_dt": _take(tls, "notafter", _time),
        }
    )
    hashes: dict[str, Any] = {}
    for src, dst in (("ja3", "ja3_hash"), ("ja3s", "ja3s_hash")):
        sub = _sub(tls, src)
        if sub is not None:
            hashes[dst] = _fingerprint("MD5", _take(sub, "hash", _hexdigest(_MD5)))
            _prune(tls, src)
    c.attributes["tls"] = _compact(
        {"sni": sni, "version": _take(tls, "version", _str(64)), "certificate": cert} | hashes
    )
    c.keys.append(domain_key(sni))
    _prune(rec, "tls")
    return True


def _map_fileinfo(rec: Record, c: _Common) -> None:
    info = _sub(rec, "fileinfo")
    if info is None:
        return
    sha256 = _take(info, "sha256", _hexdigest(_SHA256))
    hashes = [
        _fingerprint("MD5", _take(info, "md5", _hexdigest(_MD5))),
        _fingerprint("SHA-1", _take(info, "sha1", _hexdigest(_SHA1))),
        _fingerprint("SHA-256", sha256),
    ]
    c.attributes["file"] = _compact(
        {
            "name": _take(info, "filename", _str(4096)),
            "size": _take(info, "size", _uint(_MAX_U64)),
            "hashes": [h for h in hashes if h],
        }
    )
    c.keys.append(sha256_key(sha256))
    _prune(rec, "fileinfo")


# --- detections ---------------------------------------------------------------------------


def _attack_ids(metadata: object) -> tuple[str, ...]:
    if not isinstance(metadata, dict):
        return ()
    found: list[str | None] = []
    for key, values in metadata.items():
        name = key.lower()
        if not (name.startswith("mitre") and name.endswith("technique_id")):
            continue
        for value in values if isinstance(values, list) else [values]:
            if isinstance(value, str) and len(value) <= 16 and _ATTACK_ID.fullmatch(value):
                found.append(value)
    return unique(*found)[:_MAX_ATTACK_IDS]


def _signature_severity(metadata: Record | None) -> list[str] | None:
    value = metadata.get("signature_severity") if metadata else None
    if not isinstance(value, list) or len(value) > 8:
        return None
    if not all(isinstance(v, str) and len(v) <= 64 for v in value):
        return None
    return value


def _in(sid: int, ranges: Ranges) -> bool:
    return any(lo <= sid <= hi for lo, hi in ranges)


def _alert_detection(alert: Record, c: _Common, opts: _Options) -> DetectionDraft:
    gid = _take(alert, "gid", _uint(_MAX_SID))
    sid = _take(alert, "signature_id", _uint(_MAX_SID))
    if gid is None or sid is None:
        raise AdapterError("alert without a valid gid and signature_id")
    rev = _take(alert, "rev", _uint(_MAX_SID))
    signature = _take(alert, "signature", _str(1024))
    category = _take(alert, "category", _str(256))
    action = _take(alert, "action", _str(32))
    metadata = _take(alert, "metadata", lambda v: v if isinstance(v, dict) else None)
    raw_severity = _take(alert, "severity", _uint(255))
    if raw_severity is None:  # missing or not an integer
        severity = Severity.UNKNOWN
    else:
        severity = _ALERT_SEVERITY.get(raw_severity, Severity.INFORMATIONAL)

    # Only gid 1 is the rules-file namespace the sid conventions apply to.
    if gid == 1 and _in(sid, opts.local_sid_ranges):
        authorship, why = Authorship.LOCAL, "gid 1 and a sid in the local range"
    elif gid == 1 and _in(sid, opts.builtin_sid_ranges):
        authorship, why = Authorship.BUILTIN, "gid 1 and a sid in Suricata's own event range"
    else:
        authorship, why = Authorship.COMMUNITY, "a sid outside the local and builtin ranges"
    rule = f"{gid}:{sid}:{rev}" if rev is not None else f"{gid}:{sid}"
    return DetectionDraft(
        kind="suricata.alert",
        authorship=authorship,
        identity=f"suricata:{gid}:{sid}",
        title=signature or f"Suricata rule {gid}:{sid}",
        severity=severity,
        event_time=c.event_time,
        rule_ref={
            "engine": "suricata",
            "gid": gid,
            "sid": sid,
            "rev": rev,
            "signature": signature,
            "category": category,
            "action": action,
            "metadata": metadata,
            "attack_version": opts.attack_version,
        },
        attributes={"unmapped": alert} if alert else {},
        attack=_attack_ids(metadata),
        entity_keys=unique(*c.keys),
        observation_refs=(0,),
        explanation=_compact(
            {
                "summary": f"Suricata signature {rule} matched; authorship from {why}",
                "signature": signature,
                "category": category,
                "action": action,
                "suricata_severity": raw_severity,
                "signature_severity": _signature_severity(metadata),
            }
        ),
    )


def _map_anomaly(rec: Record, c: _Common) -> dict[str, str]:
    """Anomaly facts go on the observation; returns the parts of the detection identity."""
    anomaly = _sub(rec, "anomaly")
    if anomaly is None:
        raise AdapterError("anomaly record without an anomaly object")
    facts = _compact(
        {
            "type": _take(anomaly, "type", _str(32)),
            "event": _take(anomaly, "event", _str(128)),
            "layer": _take(anomaly, "layer", _str(64)),
            "app_proto": _take(anomaly, "app_proto", _str(64)),
            "code": _take(anomaly, "code", _uint(_MAX_SID)),
        }
    )
    c.attributes["anomaly"] = facts
    _prune(rec, "anomaly")

    def part(value: object, pattern: re.Pattern[str]) -> str:
        return value if isinstance(value, str) and pattern.fullmatch(value) else "-"

    return {
        "type": part(facts.get("type"), _NAME_PART),
        "scope": part(facts.get("app_proto") or facts.get("layer"), _NAME_PART),
        "event": part(facts.get("event"), _EVENT_NAME),
    }


def _anomaly_detection(parts: dict[str, str], c: _Common) -> DetectionDraft:
    identity = f"suricata:anomaly:{parts['type']}:{parts['scope']}:{parts['event']}"
    return DetectionDraft(
        kind="suricata.anomaly",
        authorship=Authorship.BUILTIN,
        identity=identity,
        title=f"Suricata {parts['type']} anomaly {parts['event']}",
        severity=Severity.INFORMATIONAL,
        event_time=c.event_time,
        rule_ref={"engine": "suricata", "check": "anomaly"} | parts,
        entity_keys=unique(*c.keys),
        observation_refs=(0,),
        explanation={
            "summary": f"Suricata's built-in {parts['type']} checks reported {parts['event']}"
            f" ({parts['scope']}); the reported facts are on the referenced observation",
        },
    )


# --- the adapter --------------------------------------------------------------------------


class SuricataAdapter:
    name = "suricata"
    version = "1.0.0"

    def parse(self, raw: RawRecord, options: Mapping[str, Any]) -> ParseResult:
        if len(raw.body) > MAX_BODY:
            raise LimitExceeded("line_length", f"record larger than {MAX_BODY} bytes")
        opts = _Options.parse(options)
        # LimitExceeded from the decoder propagates so ingest can record the breach.
        rec, flags = loads_object_flagged(raw.text())
        event_type = rec.get("event_type")
        handler = _HANDLERS.get(event_type) if isinstance(event_type, str) else None
        if handler is None:
            c = _Common(rec, flags=flags)
            if "event_type" not in rec:
                c.flags.append("missing_event_type")
            return ParseResult(observations=(c.observation("suricata.unknown", None, rec),))
        del rec["event_type"]
        return handler(rec, opts, flags)


def _parse_flow(rec: Record, _: _Options, flags: tuple[str, ...]) -> ParseResult:
    c = _Common(rec, hint=False, flags=flags)  # flow records are written from the flow's initiator
    _map_flow(rec, c)
    return ParseResult(observations=(c.observation("network.flow", OCSF_NETWORK, rec),))


def _parse_dns(rec: Record, _: _Options, flags: tuple[str, ...]) -> ParseResult:
    c = _Common(rec, hint=_dns_hint(rec), flags=flags)
    kind = _map_dns(rec, c) or "dns.query"
    return ParseResult(observations=(c.observation(kind, OCSF_DNS, rec),))


def _parse_http(rec: Record, _: _Options, flags: tuple[str, ...]) -> ParseResult:
    c = _Common(rec, hint=False, flags=flags)  # LOG_DIR_FLOW: client -> server
    _map_http(rec, c)
    return ParseResult(observations=(c.observation("http.request", OCSF_HTTP, rec),))


def _parse_tls(rec: Record, _: _Options, flags: tuple[str, ...]) -> ParseResult:
    c = _Common(rec, hint=False, flags=flags)  # LOG_DIR_FLOW: client -> server
    _map_tls(rec, c)
    return ParseResult(observations=(c.observation("tls.handshake", OCSF_NETWORK, rec),))


def _parse_fileinfo(rec: Record, _: _Options, flags: tuple[str, ...]) -> ParseResult:
    c = _Common(rec, flags=flags)  # written in transfer direction, which the record does not state
    _map_fileinfo(rec, c)
    _map_http(rec, c)  # fileinfo records carry the app-layer object of the transfer
    return ParseResult(observations=(c.observation("file.transfer", OCSF_FILE, rec),))


def _parse_alert(rec: Record, opts: _Options, flags: tuple[str, ...]) -> ParseResult:
    alert = _sub(rec, "alert")
    if alert is None:
        raise AdapterError("alert record without an alert object")
    del rec["alert"]
    c = _Common(rec, flags=flags)
    _map_flow(rec, c)
    # The observation takes the app-layer kind when the alert carries one (http > dns > tls).
    kind, ocsf = "network.flow", OCSF_NETWORK
    tls = _map_tls(rec, c)
    dns_kind = _map_dns(rec, c)
    http = _map_http(rec, c)
    if http:
        kind, ocsf = "http.request", OCSF_HTTP
    elif dns_kind:
        kind, ocsf = dns_kind, OCSF_DNS
    elif tls:
        kind = "tls.handshake"
    detection = _alert_detection(alert, c, opts)
    return ParseResult(observations=(c.observation(kind, ocsf, rec),), detections=(detection,))


def _parse_anomaly(rec: Record, _: _Options, flags: tuple[str, ...]) -> ParseResult:
    if _sub(rec, "anomaly") is None:
        raise AdapterError("anomaly record without an anomaly object")
    c = _Common(rec, flags=flags)  # written in packet direction
    parts = _map_anomaly(rec, c)
    return ParseResult(
        observations=(c.observation("network.anomaly", OCSF_NETWORK, rec),),
        detections=(_anomaly_detection(parts, c),),
    )


_HANDLERS: dict[str, Callable[[Record, _Options, tuple[str, ...]], ParseResult]] = {
    "alert": _parse_alert,
    "flow": _parse_flow,
    "dns": _parse_dns,
    "http": _parse_http,
    "tls": _parse_tls,
    "fileinfo": _parse_fileinfo,
    "anomaly": _parse_anomaly,
}

ADAPTER = SuricataAdapter()
register(ADAPTER)
