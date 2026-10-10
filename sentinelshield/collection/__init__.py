"""Safe traffic sources for offline and synthetic development."""

from sentinelshield.collection.live import (
    MAX_CAPTURE_SECONDS,
    capture_live_metadata,
    list_capture_interfaces,
)
from sentinelshield.collection.synthetic import (
    make_synthetic_scenario,
    make_synthetic_stream,
)

__all__ = [
    "MAX_CAPTURE_SECONDS",
    "capture_live_metadata",
    "list_capture_interfaces",
    "make_synthetic_scenario",
    "make_synthetic_stream",
]
