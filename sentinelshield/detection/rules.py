"""Explainable rate and TCP SYN-pattern detection with an adaptive baseline."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from statistics import median

from sentinelshield.processing.traffic import TrafficWindowFeatures


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Tunable detector parameters; defaults are starting points, not validated."""

    minimum_unusual_pps: float = 100.0
    minimum_baseline_samples: int = 5
    baseline_window_count: int = 60
    mad_multiplier: float = 3.0
    minimum_baseline_spread_pps: float = 1.0
    suspicious_syn_ratio: float = 0.70
    minimum_syn_pps: float = 20.0

    def __post_init__(self) -> None:
        if self.minimum_unusual_pps < 0:
            raise ValueError("minimum_unusual_pps cannot be negative")
        if self.minimum_baseline_samples < 1:
            raise ValueError("minimum_baseline_samples must be at least one")
        if self.baseline_window_count < self.minimum_baseline_samples:
            raise ValueError(
                "baseline_window_count must be at least minimum_baseline_samples"
            )
        if self.mad_multiplier <= 0:
            raise ValueError("mad_multiplier must be greater than zero")
        if self.minimum_baseline_spread_pps <= 0:
            raise ValueError("minimum_baseline_spread_pps must be greater than zero")
        if not 0 <= self.suspicious_syn_ratio <= 1:
            raise ValueError("suspicious_syn_ratio must be between zero and one")
        if self.minimum_syn_pps < 0:
            raise ValueError("minimum_syn_pps cannot be negative")


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """One explainable decision and the baseline context used to make it."""

    label: str
    reasons: tuple[str, ...]
    observed_pps: float
    syn_ratio: float
    syn_pps: float
    adaptive_threshold_pps: float
    baseline_samples: int
    baseline_ready: bool

    @property
    def is_alert(self) -> bool:
        return self.label != "Normal"


class RuleBasedDetector:
    """Compare each window to a rolling robust rate baseline and SYN rule.

    Baseline updates use only windows not marked unusual or SYN-suspicious.
    Consequently, high-rate/suspicious observations do not immediately teach
    the baseline to call themselves normal.
    """

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self._baseline_pps: deque[float] = deque(
            maxlen=self.config.baseline_window_count
        )

    @property
    def baseline_samples(self) -> tuple[float, ...]:
        """Return a read-only snapshot of benign rates incorporated so far."""
        return tuple(self._baseline_pps)

    def threshold_pps(self) -> float:
        """Return the current absolute floor or median/MAD adaptive threshold."""
        if len(self._baseline_pps) < self.config.minimum_baseline_samples:
            return self.config.minimum_unusual_pps

        center = median(self._baseline_pps)
        deviations = [abs(rate - center) for rate in self._baseline_pps]
        mad = median(deviations)
        robust_spread = max(1.4826 * mad, self.config.minimum_baseline_spread_pps)
        return max(
            self.config.minimum_unusual_pps,
            center + self.config.mad_multiplier * robust_spread,
        )

    def evaluate(self, features: TrafficWindowFeatures) -> DetectionResult:
        """Classify one aggregate window and update the benign baseline safely."""
        threshold = self.threshold_pps()
        unusual_rate = features.packets_per_second > threshold
        syn_pps = features.syn_count / features.window_seconds
        suspicious_syn = (
            features.tcp_packets > 0
            and features.syn_ratio >= self.config.suspicious_syn_ratio
            and syn_pps >= self.config.minimum_syn_pps
        )

        reasons: list[str] = []
        if unusual_rate:
            reasons.append(
                f"Packet rate {features.packets_per_second:.2f} pps exceeds "
                f"the {threshold:.2f} pps baseline threshold."
            )
        if suspicious_syn:
            reasons.append(
                f"Initial TCP SYN ratio is {features.syn_ratio:.1%} with "
                f"{syn_pps:.2f} initial SYN packets per second."
            )

        if unusual_rate and suspicious_syn:
            label = "Potential DDoS Activity"
        elif suspicious_syn:
            label = "Suspicious TCP SYN Pattern"
        elif unusual_rate:
            label = "Unusual Traffic"
        else:
            label = "Normal"

        baseline_ready = len(self._baseline_pps) >= self.config.minimum_baseline_samples
        result = DetectionResult(
            label=label,
            reasons=tuple(reasons),
            observed_pps=features.packets_per_second,
            syn_ratio=features.syn_ratio,
            syn_pps=syn_pps,
            adaptive_threshold_pps=threshold,
            baseline_samples=len(self._baseline_pps),
            baseline_ready=baseline_ready,
        )

        if not unusual_rate and not suspicious_syn:
            self._baseline_pps.append(features.packets_per_second)
        return result
