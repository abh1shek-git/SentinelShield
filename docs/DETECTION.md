# Rule-based detection and adaptive baseline

The initial detector is intentionally interpretable. It emits labels and human-readable reasons from aggregate window features. It does not claim that an event is a confirmed attack.

## Packet-rate baseline

`RuleBasedDetector` compares the observed packets per second (PPS) to a rolling baseline of previously normal windows. After the configured minimum number of baseline samples, it calculates:

```text
center = median(baseline PPS)
spread = max(1.4826 * median(abs(PPS - center)), minimum_baseline_spread_pps)
threshold = max(minimum_unusual_pps, center + mad_multiplier * spread)
```

Median absolute deviation (MAD) is less affected by isolated high values than mean and standard deviation. The threshold floor avoids flagging small routine changes when traffic is quiet. Before warm-up, only the absolute floor applies and `baseline_ready` is false.

Only windows that are neither above the rate threshold nor SYN-suspicious are added to the bounded rolling baseline. This reduces contamination from obvious anomalies; it does not guarantee a clean baseline. Slow changes that remain below the current threshold may still be incorporated.

## TCP SYN signal

The detector checks that the initial SYN-only ratio meets `suspicious_syn_ratio` and that the initial SYN rate meets `minimum_syn_pps`. A SYN-ACK packet is counted separately by feature extraction and is not counted as an initial SYN. This pattern can indicate connection-initiation pressure, but legitimate connection surges can look similar.

## Labels

| Conditions | Label |
| --- | --- |
| Neither rate nor SYN condition | `Normal` |
| Rate exceeds adaptive threshold only | `Unusual Traffic` |
| SYN ratio and SYN rate pass, but packet rate is not unusual | `Suspicious TCP SYN Pattern` |
| Both conditions pass | `Potential DDoS Activity` |

High volume alone never yields the DDoS label. `Confirmed Test Attack` is not emitted by this detector; that label requires known controlled test provenance and a later scenario/evaluation layer.

## Configuration and limitations

Defaults (`100 PPS` floor, five baseline samples, 60 retained samples, ratio `0.70`, initial SYN rate `20 PPS`) are starting parameters, not validated thresholds. There is no per-source detector, concept-drift study, calibration dataset, or precision/recall result yet. The detector processes one aggregate stream, not independent per-host or per-destination baselines. These values must be evaluated against labeled benign and controlled test traffic before drawing performance conclusions.
