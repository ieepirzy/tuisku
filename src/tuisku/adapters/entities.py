"""Typed entity keys (ADR 0008).

Every builder normalizes its input and returns ``None`` for values that are not valid, so a
hostile or malformed field never becomes a key. Keys are bounded in length.
"""

from __future__ import annotations

import ipaddress
import re

MAX_KEY_PART = 253

_HOSTNAME_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Kubernetes names: DNS-1123 subdomain (namespaces are labels, pods may contain dots).
_K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_PLAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,252}$")


def ip_key(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return f"ip:{addr.compressed}"


def _normalize_domain(value: str) -> str | None:
    name = value.strip().rstrip(".").lower()
    if not name or len(name) > MAX_KEY_PART:
        return None
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = name.split(".")
    if len(name) > MAX_KEY_PART or not all(_HOSTNAME_LABEL.match(label) for label in labels):
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


def host_key(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = _normalize_domain(value)
    return f"host:{name}" if name else None


def k8s_pod_key(namespace: object, pod: object) -> str | None:
    if not (isinstance(namespace, str) and isinstance(pod, str)):
        return None
    if not (_K8S_NAME.match(namespace) and _K8S_NAME.match(pod)):
        return None
    return f"k8s:{namespace}/{pod}"


def k8s_namespace_key(namespace: object) -> str | None:
    if not isinstance(namespace, str) or not _K8S_NAME.match(namespace):
        return None
    return f"k8s-ns:{namespace}"


def image_key(repository: object) -> str | None:
    if not isinstance(repository, str) or not _PLAIN.match(repository):
        return None
    return f"image:{repository}"


def sha256_key(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    digest = value.strip().lower().removeprefix("sha256:")
    return f"sha256:{digest}" if _SHA256.match(digest) else None


def caller_key(source: object, name: object) -> str | None:
    """``caller:<source>/<name>``, e.g. ``caller:harava/agents``."""
    if not (isinstance(source, str) and isinstance(name, str)):
        return None
    if not (_PLAIN.match(source) and _PLAIN.match(name)) or "/" in source:
        return None
    return f"caller:{source}/{name}"


def unique(*keys: str | None) -> tuple[str, ...]:
    """Drop ``None`` and duplicates, keeping first-seen order."""
    seen: dict[str, None] = {}
    for key in keys:
        if key is not None:
            seen.setdefault(key, None)
    return tuple(seen)
