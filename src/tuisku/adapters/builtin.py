"""The adapters shipped with Tuisku, registered when this module is imported.

Each real adapter (suricata, zeek, falco, harava) lands in its own change, which adds one
import line below. Imports are explicit and unconditional: a missing or broken adapter module
must fail loudly at startup, never be skipped silently.
"""

from __future__ import annotations

from tuisku.adapters.base import Adapter

# One import per adapter module, e.g. `from tuisku.adapters import suricata`, and its
# `suricata.ADAPTER` in this tuple. Empty until the first adapter lands.
BUILTIN: tuple[Adapter, ...] = ()
