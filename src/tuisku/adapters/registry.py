"""Name → adapter lookup. Adapters register themselves in :mod:`tuisku.adapters`."""

from __future__ import annotations

from tuisku.adapters.base import Adapter

_ADAPTERS: dict[str, Adapter] = {}


def register(adapter: Adapter) -> Adapter:
    if not isinstance(adapter, Adapter):
        raise TypeError(f"{adapter!r} does not implement the Adapter protocol")
    existing = _ADAPTERS.get(adapter.name)
    if existing is not None and existing is not adapter:
        raise ValueError(f"adapter {adapter.name!r} is already registered")
    _ADAPTERS[adapter.name] = adapter
    return adapter


def get(name: str) -> Adapter:
    try:
        return _ADAPTERS[name]
    except KeyError:
        raise KeyError(f"unknown adapter {name!r}") from None


def names() -> list[str]:
    return sorted(_ADAPTERS)
