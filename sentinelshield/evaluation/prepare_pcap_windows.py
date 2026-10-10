"""Extract the live detector's window features from labeled sample PCAPs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

from sentinelshield.evaluation.model import FEATURE_COLUMNS
from sentinelshield.processing.traffic import aggregate_windows, read_pcap


CAPTURES = (
    ("CIC-DDoS-2019-Benign.pcap", "Benign"),
    ("CIC-DDoS-2019-DNS.pcap", "DDoS"),
    ("CIC-DDoS-2019-SynFlood.pcap", "DDoS"),
    ("CIC-DDoS-2019-UDPLag.pcap", "DDoS"),
    ("CIC-DDoS-2019-WebDDoS.pcap", "DDoS"),
)
SOURCE_URL = "https://github.com/doriguzzi/lucid-ddos/tree/master/sample-dataset"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--window-seconds", type=float, default=5.0)
    args = parser.parse_args()
    if args.window_seconds <= 0:
        parser.error("--window-seconds must be positive")

    rows: list[dict] = []
    audits: list[dict] = []
    for filename, label in CAPTURES:
        path = args.capture_dir / filename
        if not path.is_file():
            parser.error(f"Missing capture: {path}")
        windows = aggregate_windows(read_pcap(path), args.window_seconds)
        if not windows:
            raise ValueError(f"Capture contains no supported IP packets: {path}")
        for window in windows:
            row = {name: getattr(window, name) for name in FEATURE_COLUMNS}
            row.update(
                {
                    "label": label,
                    "capture_id": path.stem,
                    "window_start": window.window_start,
                    "window_seconds": window.window_seconds,
                }
            )
            rows.append(row)
        gaps = [
            later.window_start - earlier.window_start
            for earlier, later in zip(windows, windows[1:])
        ]
        audits.append(
            {
                "capture": filename,
                "file_bytes": path.stat().st_size,
                "sha256": sha256(path),
                "file_label": label,
                "windows": len(windows),
                "packets_in_windows": sum(window.packet_count for window in windows),
                "first_window_start": windows[0].window_start,
                "last_window_start": windows[-1].window_start,
                "minimum_packets_per_window": min(
                    window.packet_count for window in windows
                ),
                "maximum_packets_per_window": max(
                    window.packet_count for window in windows
                ),
                "gaps_over_60_seconds": sum(gap > 60 for gap in gaps),
                "maximum_gap_seconds": max(gaps, default=0.0),
            }
        )

    dataset = pd.DataFrame(rows)
    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(args.output_csv, index=False)
    audit = {
        "kind": "labeled_pcap_window_preparation",
        "source": SOURCE_URL,
        "label_method": "Capture filename label applied to every nonempty window",
        "window_seconds": args.window_seconds,
        "feature_columns": list(FEATURE_COLUMNS),
        "total_windows": len(dataset),
        "ready_for_independent_model_evaluation": False,
        "captures": audits,
        "limitations": [
            "These are small samples of CIC-DDoS2019, not full capture days.",
            "A file-level attack label may not describe every packet in a window.",
            "Only one benign capture is present; a leakage-resistant benign holdout is unavailable.",
            "Do not use a random window split as an independent performance estimate.",
        ],
    }
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    args.audit.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
