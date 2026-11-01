"""Typed entity keys (ADR 0008).

Every builder normalizes its input and returns ``None`` for values that are not valid, so a
hostile or malformed field never becomes a key. Keys are bounded in length. Input is not
trimmed: surrounding whitespace, newlines, CR and NUL make a value invalid.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from datetime import UTC, datetime

import idna

MAX_KEY_PART = 253
MAX_PID = 2**32

_HOSTNAME_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_SHA256 = re.compile(r"[0-9a-f]{64}")
# Kubernetes: namespaces are DNS-1123 labels; pod names are DNS-1123 subdomains.
_K8S_LABEL = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
_PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,252}")
_IMAGE_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,252}")
_IMAGE_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
_IMAGE_DIGEST = re.compile(r"[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-fA-F]{32,128}")
# UTS 46 would silently drop "ignored" code points; reject them instead. ZWJ/ZWNJ are left to
# the IDNA CONTEXTJ rules, which reject them outside the scripts that legitimately use them.
_VARIATION_SELECTORS = re.compile("[᠋-᠏︀-️\U000e0100-\U000e01ef]")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def ip_key(value: object) -> str | None:
    """``ip:<compressed>``. Scoped IPv6 is rejected; IPv4-mapped IPv6 becomes ``ip:<ipv4>``."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.scope_id is not None:
            return None
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
    return f"ip:{addr.compressed}"


def _has_ignored_codepoint(name: str) -> bool:
    for ch in name:
        if ch in "‌‍":
            continue
        if unicodedata.category(ch) == "Cf":  # soft hyphen, ZWSP, BOM, word joiner, ...
            return True
    return bool(_VARIATION_SELECTORS.search(name))


def _normalize_domain(value: str) -> str | None:
    """IDNA A-label form under UTS 46 non-transitional processing (``faß.de`` stays distinct
    from ``fass.de``), lowercase, no trailing dot, LDH labels. ``None`` for anything invalid,
    including bad punycode and code points UTS 46 would silently drop."""
    if not value or len(value) > MAX_KEY_PART:
        return None
    name = value[:-1] if value.endswith(".") else value
    if not name or _has_ignored_codepoint(name):
        return None
    try:
        # idna >= 3.x applies UTS 46 non-transitional processing (its ``transitional`` flag is
        # deprecated and ignored) and validates existing A-labels, rejecting bad punycode.
        name = idna.encode(name, uts46=True, std3_rules=True).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        return None
    labels = name.split(".")
    if len(name) > MAX_KEY_PART or not all(_HOSTNAME_LABEL.fullmatch(label) for label in labels):
        return None
    if labels[-1].isdigit():  # all-numeric final label: an IP-ish literal, never a name
        return None
    return name


def domain_key(value: object) -> str | None:
    """``domain:example.com``. IP literals are not domains; use :func:`ip_key`."""
    if not isinstance(value, str) or ip_key(value) is not None:
        return None
    name = _normalize_domain(value)
    if name is None or "." not in name:
        return None
    return f"domain:{name}"


def _normalize_host(value: object) -> str | None:
    if not isinstance(value, str) or ip_key(value) is not None:
        return None
    return _normalize_domain(value)


def host_key(value: object) -> str | None:
    """``host:<name>``, normalized like a domain. IP literals are rejected; use :func:`ip_key`."""
    name = _normalize_host(value)
    return f"host:{name}" if name else None


def process_key(host: object, pid: object, start: object) -> str | None:
    """``process:<host>/<pid>/<start-epoch-ns>``, e.g. ``process:node-1/4242/1761825600123456000``.

    ``host`` is normalized as in :func:`host_key`; ``pid`` must be a non-negative int; ``start``
    must be a timezone-aware datetime and is rendered as integer nanoseconds since the Unix epoch
    (microsecond precision, so the last three digits are zero). Returns ``None`` otherwise: a
    process without a known start time gets no key, since pids are reused.
    """
    name = _normalize_host(host)
    if name is None:
        return None
    if isinstance(pid, bool) or not isinstance(pid, int) or not 0 <= pid <= MAX_PID:
        return None
    if not isinstance(start, datetime) or start.utcoffset() is None:
        return None
    delta = start - _EPOCH
    nanos = (delta.days * 86_400 + delta.seconds) * 10**9 + delta.microseconds * 1000
    return f"process:{name}/{pid}/{nanos}"


def k8s_pod_key(namespace: object, pod: object) -> str | None:
    if not (isinstance(namespace, str) and isinstance(pod, str)):
        return None
    if not _K8S_LABEL.fullmatch(namespace) or len(pod) > MAX_KEY_PART:
        return None
    if not all(_K8S_LABEL.fullmatch(label) for label in pod.split(".")):
        return None
    return f"k8s:{namespace}/{pod}"


def k8s_namespace_key(namespace: object) -> str | None:
    if not isinstance(namespace, str) or not _K8S_LABEL.fullmatch(namespace):
        return None
    return f"k8s-ns:{namespace}"


def _split_image_reference(value: str) -> tuple[str, str | None] | None:
    """Split ``repo[:tag][@digest]`` into ``(repo, digest)``; ``None`` if malformed."""
    ref, at, digest = value.partition("@")
    if at and not _IMAGE_DIGEST.fullmatch(digest):
        return None
    colon = ref.rfind(":")
    if colon > ref.rfind("/"):  # a colon in the last path component is a tag, not a port
        ref, tag = ref[:colon], ref[colon + 1 :]
        if not _IMAGE_TAG.fullmatch(tag):
            return None
    if not _IMAGE_REPO.fullmatch(ref):
        return None
    return ref, (digest if at else None)


def image_key(reference: object) -> str | None:
    """``image:<repository>``, keyed on the repository only.

    Any tag and any ``@<algo>:<hex>`` digest are stripped, so ``ghcr.io/org/app:1.2@sha256:…``
    and ``ghcr.io/org/app`` share ``image:ghcr.io/org/app``. A registry port
    (``registry:5000/app``) is kept. Use :func:`image_digest_key` for the digest itself.
    """
    if not isinstance(reference, str) or len(reference) > 512:
        return None
    parts = _split_image_reference(reference)
    return f"image:{parts[0]}" if parts else None


def image_digest_key(value: object) -> str | None:
    """``sha256:<hex>`` for an image digest, from ``repo[:tag]@sha256:<hex>`` or a bare
    ``sha256:<hex>``. The same key form as :func:`sha256_key`, so it joins with file digests."""
    if not isinstance(value, str) or len(value) > 512:
        return None
    if "@" in value:
        parts = _split_image_reference(value)
        if parts is None or parts[1] is None:
            return None
        digest = parts[1]
    else:
        digest = value
    if not digest.lower().startswith("sha256:"):
        return None
    return sha256_key(digest)


def sha256_key(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 71:
        return None
    digest = value.lower().removeprefix("sha256:")
    return f"sha256:{digest}" if _SHA256.fullmatch(digest) else None


def caller_key(source: object, name: object) -> str | None:
    """``caller:<source>/<name>``, e.g. ``caller:harava/agents``."""
    if not (isinstance(source, str) and isinstance(name, str)):
        return None
    if not (_PLAIN.fullmatch(source) and _PLAIN.fullmatch(name)) or "/" in source:
        return None
    return f"caller:{source}/{name}"


def unique(*keys: str | None) -> tuple[str, ...]:
    """Drop ``None`` and duplicates, keeping first-seen order."""
    seen: dict[str, None] = {}
    for key in keys:
        if key is not None:
            seen.setdefault(key, None)
    return tuple(seen)
