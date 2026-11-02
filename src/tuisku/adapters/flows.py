"""Community ID v1 flow hashing (ADR 0003), via the reference ``communityid`` package."""

from __future__ import annotations

import ipaddress
import re

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
    """IANA protocol number from an int, a decimal string or a name; ``None`` if invalid."""
    if isinstance(proto, bool):
        return None
    if isinstance(proto, int):
        return proto if 0 <= proto <= 255 else None
    if isinstance(proto, str):
        p = proto.strip().lower()
        if p.isascii() and p.isdigit() and len(p) <= 3:
            return protocol_number(int(p))
        return PROTOCOLS.get(p)
    return None


def _port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 65535 else None


def _address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.scope_id is not None:
        return None  # a zone index is host-local and not part of the flow tuple
    return addr


def community_id(
    proto: object, src_ip: object, src_port: object, dst_ip: object, dst_port: object
) -> str | None:
    """Return the v1 Community ID (seed 0), or ``None`` when the tuple is incomplete or invalid.

    For ICMP/ICMPv6 the "ports" are the ICMP type and code, as Suricata and Zeek report them.
    Zeek reports ICMPv6 as proto ``icmp``; ICMP over IPv6 addresses is hashed as protocol 58.
    Scoped IPv6 addresses (``fe80::1%eth0``) are rejected.
    """
    proto_num = protocol_number(proto)
    saddr, daddr = _address(src_ip), _address(dst_ip)
    if proto_num is None or saddr is None or daddr is None or saddr.version != daddr.version:
        return None
    if proto_num == 1 and saddr.version == 6:
        proto_num = 58
    try:
        if proto_num in _PORTED or proto_num in _ICMP:
            sport, dport = _port(src_port), _port(dst_port)
            if sport is None or dport is None:
                return None
            if proto_num in _ICMP and (sport > 255 or dport > 255):
                return None
            tpl = communityid.FlowTuple(proto_num, str(saddr), str(daddr), sport, dport)
        else:
            tpl = communityid.FlowTuple(proto_num, str(saddr), str(daddr))
        return _CID.calc(tpl)
    except Exception:  # the reference library raises assorted errors on odd input
        return None


_CID_FORMAT = re.compile(r"1:[A-Za-z0-9+/]{27}=")


def check_reported(computed: str | None, reported: object) -> tuple[str | None, tuple[str, ...]]:
    """Reconcile Tuisku's computed Community ID with the one the sensor reported.

    - Nothing reported: the computed value, no flag.
    - Both present and equal: the computed value, no flag.
    - Both present and different (or the reported value is not a string): Tuisku's computed
      value, flagged ``community_id_mismatch``.
    - Tuisku cannot compute one (``computed is None``) but the sensor reported a well-formed v1
      id: the sensor's value, flagged ``community_id_unverified``.
    - Neither usable (nothing computed, reported value malformed): ``None``, flagged
      ``community_id_invalid``; a malformed value is never stored.
    """
    if reported is None or reported == "":
        return computed, ()
    if computed is None:
        if isinstance(reported, str) and _CID_FORMAT.fullmatch(reported):
            return reported, ("community_id_unverified",)
        return None, ("community_id_invalid",)
    if reported != computed:
        return computed, ("community_id_mismatch",)
    return computed, ()
