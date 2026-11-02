"""The adapters shipped with Tuisku, registered when this module is imported.

Imports are explicit and unconditional: a missing or broken adapter module must fail loudly at
startup, never be skipped silently. Each module registers its ``ADAPTER`` on import.
"""

from __future__ import annotations

from tuisku.adapters import falco, harava, suricata, zeek
from tuisku.adapters.base import Adapter

BUILTIN: tuple[Adapter, ...] = (falco.ADAPTER, harava.ADAPTER, suricata.ADAPTER, zeek.ADAPTER)
