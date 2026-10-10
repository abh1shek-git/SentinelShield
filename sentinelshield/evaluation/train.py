"""Command line entry point for reproducible labeled-window training."""

from __future__ import annotations

import argparse

import pandas as pd

from sentinelshield.evaluation.dataset import generate_synthetic_dataset
from sentinelshield.evaluation.model import metrics_json, save_metrics, train_classifier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train and evaluate SentinelShield on labeled window features."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input-csv", help="CSV with feature columns and a label column")
    source.add_argument(
        "--synthetic-demo",
        action="store_true",
        help="Use deterministic synthetic examples; resulting metrics are not real-world evidence",
    )
    parser.add_argument("--model", required=True, help="Output path for the joblib model")
    parser.add_argument("--metrics", help="Optional output path for holdout metrics JSON")
    parser.add_argument("--samples-per-class", type=int, default=80)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.25)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.synthetic_demo:
        dataset = generate_synthetic_dataset(
            samples_per_class=args.samples_per_class,
            random_state=args.random_state,
        )
    else:
        dataset = pd.read_csv(args.input_csv)
        if "source_kind" not in dataset.columns:
            dataset["source_kind"] = "unspecified_csv_provenance"

    result = train_classifier(
        dataset,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    result.classifier.save(args.model)
    if args.metrics:
        save_metrics(result.metrics, args.metrics)
    print(metrics_json(result))


if __name__ == "__main__":
    main()
