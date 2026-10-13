"""Stream a bounded, explicitly labeled UTC interval from a large packet capture."""

from __future__ import annotations

import argparse
from contextlib import closing
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from sentinelshield.evaluation.model import FEATURE_COLUMNS
from sentinelshield.processing.traffic import iter_aggregate_windows, read_pcap


def utc_timestamp(value: str) -> float:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"Invalid ISO 8601 timestamp: {value}") from error
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise argparse.ArgumentTypeError("Specify an explicit UTC time ending in Z or +00:00")
    return parsed.timestamp()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--start-utc", type=utc_timestamp, required=True)
    parser.add_argument("--end-utc", type=utc_timestamp, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--label-note", required=True, help="Evidence and limits of the interval label")
    parser.add_argument("--source-url", required=True, help="Capture and label provenance")
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--window-seconds", type=float, default=5.0)
    args = parser.parse_args()

    if not args.capture.is_file():
        parser.error(f"Capture does not exist: {args.capture}")
    if args.end_utc <= args.start_utc:
        parser.error("--end-utc must be later than --start-utc")
    if args.window_seconds <= 0:
        parser.error("--window-seconds must be positive")
    if any(abs(t / args.window_seconds - round(t / args.window_seconds)) > 1e-6
           for t in (args.start_utc, args.end_utc)):
        parser.error("Interval boundaries must align with --window-seconds")
    if not args.label.strip() or not args.label_note.strip():
        parser.error("--label and --label-note must not be blank")
    paths = [args.capture.resolve(), args.output_csv.resolve(), args.audit.resolve()]
    if len(set(paths)) != len(paths):
        parser.error("Capture, output CSV, and audit must use different paths")

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    rows = 0
    packets = 0
    first_window = None
    last_window = None

    def selected_records():
        with closing(read_pcap(args.capture)) as records:
            for record in records:
                if record.timestamp < args.start_utc:
                    continue
                if record.timestamp >= args.end_utc:
                    break
                yield record

    # The output is local and ignored by Git. Write incrementally instead of
    # building a DataFrame or retaining the capture's packets in memory.
    with args.output_csv.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=[*FEATURE_COLUMNS, "label", "capture_id", "window_start", "window_seconds"],
        )
        writer.writeheader()
        for window in iter_aggregate_windows(selected_records(), args.window_seconds):
            writer.writerow({
                **{name: getattr(window, name) for name in FEATURE_COLUMNS},
                "label": args.label.strip(),
                "capture_id": args.capture.stem,
                "window_start": window.window_start,
                "window_seconds": window.window_seconds,
            })
            rows += 1
            packets += window.packet_count
            first_window = window.window_start if first_window is None else first_window
            last_window = window.window_start

    if rows == 0:
        args.output_csv.unlink()
        raise ValueError("No supported IP packets occurred in the selected interval")

    digest = hashlib.sha256()
    with args.output_csv.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    audit = {
        "kind": "bounded_pcap_interval_preparation",
        "capture": args.capture.name,
        "capture_bytes": args.capture.stat().st_size,
        "capture_id": args.capture.stem,
        "capture_sha256": None,
        "capture_sha256_note": "Full multi-gigabyte capture was not hashed or scanned to its end.",
        "source_url": args.source_url,
        "start_utc": datetime.fromtimestamp(args.start_utc, timezone.utc).isoformat(),
        "end_utc_exclusive": datetime.fromtimestamp(args.end_utc, timezone.utc).isoformat(),
        "label": args.label.strip(),
        "label_note": args.label_note.strip(),
        "window_seconds": args.window_seconds,
        "windows": rows,
        "packets_in_windows": packets,
        "first_window_start": first_window,
        "last_window_start": last_window,
        "output_csv": str(args.output_csv),
        "output_sha256": digest.hexdigest(),
        "ready_for_independent_model_evaluation": False,
        "limitations": [
            "The interval label comes from an attack schedule, not packet-level ground truth.",
            "Intervals from one capture remain one capture group, even if exported separately.",
            "Only the selected interval was decoded; the rest of the file was not audited.",
            "The interval ends at the first IP packet beyond its end time; this assumes capture timestamps are ordered.",
        ],
    }
    args.audit.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
