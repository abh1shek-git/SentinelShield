"""Audit the locally supplied Friday flow CSV and Xena packet examples."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_flow_csv(path: Path) -> dict:
    labels: Counter[str] = Counter()
    with path.open("r", newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        label_column = next(
            (name for name in reader.fieldnames or () if name.strip().lower() == "label"),
            None,
        )
        if label_column is None:
            raise ValueError(f"No label column in {path}")
        for row in reader:
            labels[row[label_column].strip()] += 1
    return {
        "file": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
        "rows": sum(labels.values()),
        "raw_label_counts": dict(sorted(labels.items())),
        "data_type": "labeled flow statistics; not raw packets",
    }


def audit_pcaps(directory: Path) -> dict:
    files = []
    for path in sorted(directory.glob("*.pcap")):
        packets = 0
        ip_packets = 0
        with PcapReader(str(path)) as reader:
            for packet in reader:
                packets += 1
                ip_packets += IP in packet or IPv6 in packet
        files.append({
            "file": path.name,
            "bytes": path.stat().st_size,
            "packets": packets,
            "ip_packets": ip_packets,
        })
    if not files:
        raise ValueError(f"No .pcap files in {directory}")
    return {
        "directory": directory.name,
        "file_count": len(files),
        "total_bytes": sum(item["bytes"] for item in files),
        "total_packets": sum(item["packets"] for item in files),
        "total_ip_packets": sum(item["ip_packets"] for item in files),
        "single_packet_files": sum(item["packets"] == 1 for item in files),
        "files": files,
        "provenance": "User-supplied folder; original source and label method unverified",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flow-csv", type=Path, required=True)
    parser.add_argument("--pcap-dir", type=Path, required=True)
    parser.add_argument("--existing-flow-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for path in (args.flow_csv, args.existing_flow_report):
        if not path.is_file():
            parser.error(f"Missing file: {path}")
    if not args.pcap_dir.is_dir():
        parser.error(f"Missing directory: {args.pcap_dir}")

    flow = audit_flow_csv(args.flow_csv)
    pcaps = audit_pcaps(args.pcap_dir)
    prior = json.loads(args.existing_flow_report.read_text(encoding="utf-8"))
    prior_audit = prior.get("evaluation_audit", {})
    report = {
        "kind": "review_dataset_suitability_audit",
        "friday_flow_csv": flow,
        "friday_matches_existing_evaluation": (
            flow["sha256"] == prior_audit.get("sha256")
            and flow["rows"] == prior_audit.get("original_rows")
            and flow["raw_label_counts"] == prior_audit.get("raw_label_counts")
        ),
        "xena_pcaps": pcaps,
        "decisions": {
            "friday_flow_csv": "Relevant to the separate flow-model evaluation; it is already represented by the existing report. Its flow schema cannot directly train the dashboard's packet-window model.",
            "xena_pcaps": "Useful for packet-parser examples only. These tiny traces are not sustained, independently labeled DDoS or benign captures and must not be used for model training or accuracy claims.",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "friday_matches_existing_evaluation": report["friday_matches_existing_evaluation"],
        "friday_rows": flow["rows"],
        "xena_files": pcaps["file_count"],
        "xena_packets": pcaps["total_packets"],
        "xena_ip_packets": pcaps["total_ip_packets"],
        "xena_single_packet_files": pcaps["single_packet_files"],
    }, indent=2))


if __name__ == "__main__":
    main()
