"""Describe feature distribution differences between the supplied flow datasets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np

from sentinelshield.evaluation.flow_baseline import FEATURE_COLUMNS, LABELS, load_flows


def ks_distance(left: np.ndarray, right: np.ndarray) -> float:
    """Maximum distance between two empirical cumulative distributions."""
    left = np.sort(left)
    right = np.sort(right)
    points = np.unique(np.concatenate((left, right)))
    left_cdf = np.searchsorted(left, points, side="right") / len(left)
    right_cdf = np.searchsorted(right, points, side="right") / len(right)
    return float(np.max(np.abs(left_cdf - right_cdf)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-csv", type=Path, required=True)
    parser.add_argument("--eval-csv", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--sample-per-class", type=int, default=20_000)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    if args.sample_per_class < 2:
        parser.error("--sample-per-class must be at least two")

    train_x, train_y, train_audit = load_flows(args.train_csv, "cicddos2019")
    eval_x, eval_y, eval_audit = load_flows(args.eval_csv, "cicids2017")
    artifact = joblib.load(args.model)
    if artifact.get("artifact_kind") != "cic_binary_flow_baseline" or artifact.get(
        "feature_columns"
    ) != list(FEATURE_COLUMNS):
        raise ValueError("Expected a compatible locally trained CIC flow baseline")
    feature_importance = sorted(
        (
            {"feature": name, "importance": float(importance)}
            for name, importance in zip(
                FEATURE_COLUMNS, artifact["estimator"].feature_importances_
            )
        ),
        key=lambda item: item["importance"],
        reverse=True,
    )
    rng = np.random.default_rng(args.random_state)
    comparisons = {}
    for label in LABELS:
        train_rows = train_x.loc[train_y == label]
        eval_rows = eval_x.loc[eval_y == label]
        train_sample = rng.choice(
            len(train_rows), min(len(train_rows), args.sample_per_class), replace=False
        )
        eval_sample = rng.choice(
            len(eval_rows), min(len(eval_rows), args.sample_per_class), replace=False
        )
        train_rows = train_rows.iloc[train_sample]
        eval_rows = eval_rows.iloc[eval_sample]
        features = []
        for feature in FEATURE_COLUMNS:
            left = train_rows[feature].to_numpy()
            right = eval_rows[feature].to_numpy()
            features.append(
                {
                    "feature": feature,
                    "ks_distance": ks_distance(left, right),
                    "train_median": float(np.median(left)),
                    "eval_median": float(np.median(right)),
                }
            )
        comparisons[label] = {
            "train_sample_rows": len(train_rows),
            "eval_sample_rows": len(eval_rows),
            "features_by_shift": sorted(
                features, key=lambda item: item["ks_distance"], reverse=True
            ),
        }

    report = {
        "kind": "flow_dataset_shift_diagnostic",
        "random_state": args.random_state,
        "sample_per_class": args.sample_per_class,
        "train_file": train_audit["file"],
        "train_sha256": train_audit["sha256"],
        "eval_file": eval_audit["file"],
        "eval_sha256": eval_audit["sha256"],
        "model_feature_importance": feature_importance,
        "comparisons": comparisons,
        "interpretation_limit": (
            "The 2017 data has now been inspected for model diagnosis. "
            "It must not be presented as an untouched final benchmark for future tuning."
        ),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = {
        label: comparison["features_by_shift"][:5]
        for label, comparison in comparisons.items()
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
