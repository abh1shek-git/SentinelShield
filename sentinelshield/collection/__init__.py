"""Safe traffic sources for offline and synthetic development."""

from sentinelshield.collection.synthetic import (
    make_synthetic_scenario,
    make_synthetic_stream,
)

__all__ = ["make_synthetic_scenario", "make_synthetic_stream"]
