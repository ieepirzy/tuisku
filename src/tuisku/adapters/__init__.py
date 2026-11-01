"""Source adapters (ADR 0005).

Each adapter module registers its instance here. Import this package to get the full registry.
"""

from tuisku.adapters.base import (
    OCSF_VERSION,
    Adapter,
    AdapterError,
    Authorship,
    DetectionDraft,
    Evaluator,
    ObservationDraft,
    ParseResult,
    RawRecord,
    Severity,
)
from tuisku.adapters.registry import get, names, register

__all__ = [
    "OCSF_VERSION",
    "Adapter",
    "AdapterError",
    "Authorship",
    "DetectionDraft",
    "Evaluator",
    "ObservationDraft",
    "ParseResult",
    "RawRecord",
    "Severity",
    "get",
    "names",
    "register",
]
