"""Community ID v1 flow hashing (ADR 0003), via the reference ``communityid`` package."""

from __future__ import annotations

import ipaddress

import communityid

PROTOCOLS: dict[str, int] = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "icmp6": 58,
    "ipv6-icmp": 58,
    "sctp": 132,
}
_PORTED = {6, 17, 132}
_ICMP = {1, 58}

_CID = communityid.CommunityID(seed=0)


def protocol_number(proto: object) -> int | None:
    if isinstance(proto, bool):
        return None
    if isinstance(proto, int):
        return proto if 0 <= proto <= 255 else None
    if isinstance(proto, str):
        p = proto.strip().lower()
        if p.isdigit():
            return protocol_number(int(p))
        return PROTOCOLS.get(p)
    return None


def _port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 65535 else None


def community_id(
    proto: object, src_ip: object, src_port: object, dst_ip: object, dst_port: object
) -> str | None:
    """Return the v1 Community ID (seed 0), or ``None`` when the tuple is incomplete or invalid.

    For ICMP/ICMPv6 the "ports" are the ICMP type and code, as Suricata and Zeek report them.
    """
    proto_num = protocol_number(proto)
    if proto_num is None or not isinstance(src_ip, str) or not isinstance(dst_ip, str):
        return None
    try:
        saddr = ipaddress.ip_address(src_ip)
        daddr = ipaddress.ip_address(dst_ip)
    except ValueError:
        return None
    if saddr.version != daddr.version:
        return None
    if proto_num in _PORTED or proto_num in _ICMP:
        sport, dport = _port(src_port), _port(dst_port)
        if sport is None or dport is None:
            return None
        if proto_num in _ICMP and (sport > 255 or dport > 255):
            return None
        tpl = communityid.FlowTuple(proto_num, str(saddr), str(daddr), sport, dport)
    else:
        tpl = communityid.FlowTuple(proto_num, str(saddr), str(daddr))
    try:
        return _CID.calc(tpl)
    except Exception:  # the reference library raises assorted errors on odd input
        return None


def check_reported(computed: str | None, reported: object) -> tuple[str | None, tuple[str, ...]]:
    """Prefer Tuisku's computed id; flag a sensor-reported value that differs."""
    if reported is None or reported == "":
        return computed, ()
    if not isinstance(reported, str) or computed is None or reported != computed:
        return computed, ("community_id_mismatch",)
    return computed, ()
