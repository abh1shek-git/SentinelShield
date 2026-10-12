"""Audit packet-window capture groups and evaluate an explicitly held-out set."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

from sentinelshield.evaluation.model import (
    FEATURE_COLUMNS,
    MODEL_SCHEMA_VERSION,
    TrafficClassifier,
    save_metrics,
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_dataset(dataset: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    required = {*FEATURE_COLUMNS, "label", "capture_id"}
    missing = sorted(required - set(dataset.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {', '.join(missing)}")
    if dataset.empty:
        raise ValueError("Dataset contains no windows")

    if dataset[[*FEATURE_COLUMNS, "label", "capture_id"]].isna().any().any():
        raise ValueError("Dataset contains missing features, labels, or capture IDs")
    labels = dataset["label"].astype(str).str.strip()
    groups = dataset["capture_id"].astype(str).str.strip()
    if labels.eq("").any() or groups.eq("").any():
        raise ValueError("Labels and capture IDs must not be blank")
    try:
        features = dataset.loc[:, list(FEATURE_COLUMNS)].astype(float)
    except (TypeError, ValueError) as error:
        raise ValueError("All model features must be numeric") from error
    if not np.isfinite(features.to_numpy()).all():
        raise ValueError("Model features must contain only finite values")
    return features, labels, groups


def readiness_report(
    dataset: pd.DataFrame, labels: pd.Series, groups: pd.Series, input_path: Path
) -> dict[str, Any]:
    class_counts = labels.value_counts()
    class_capture_counts = {
        label: int(groups[labels == label].nunique()) for label in sorted(class_counts.index)
    }
    capture_rows = (
        pd.DataFrame({"capture_id": groups, "label": labels})
        .groupby(["capture_id", "label"], sort=True)
        .size()
    )
    captures: dict[str, dict[str, int]] = {}
    for (capture_id, label), count in capture_rows.items():
        captures.setdefault(str(capture_id), {})[str(label)] = int(count)

    blockers: list[str] = []
    if len(class_counts) < 2:
        blockers.append("At least two distinct labels are needed for classification.")
    for label, count in class_capture_counts.items():
        if count < 2:
            blockers.append(
                f"Label '{label}' occurs in only {count} capture(s); "
                "at least two separate captures are needed for a held-out evaluation."
            )

    return {
        "kind": "packet_window_capture_readiness",
        "feature_schema_version": MODEL_SCHEMA_VERSION,
        "input_csv": str(input_path),
        "input_sha256": file_sha256(input_path),
        "total_windows": int(len(dataset)),
        "capture_count": len(captures),
        "label_window_counts": {str(label): int(count) for label, count in class_counts.items()},
        "label_capture_counts": class_capture_counts,
        "capture_label_window_counts": captures,
        "structurally_eligible_for_capture_holdout": not blockers,
        "blockers": blockers,
        "cautions": [
            "Capture IDs must represent independent collections; this cannot be proven from CSV columns.",
            "File-level labels may not describe every packet or window in a capture.",
            "The current LUCID files are excerpts, so a future score needs provenance and label review.",
        ],
    }


def evaluate_holdout(
    features: pd.DataFrame,
    labels: pd.Series,
    groups: pd.Series,
    evaluation_capture_ids: list[str],
    *,
    input_sha256: str,
    random_state: int,
    n_estimators: int,
) -> tuple[dict[str, Any], TrafficClassifier]:
    if n_estimators < 1:
        raise ValueError("n_estimators must be at least one")
    selected = set(evaluation_capture_ids)
    if not selected:
        raise ValueError("Specify at least one evaluation capture ID")
    unknown = sorted(selected - set(groups.unique()))
    if unknown:
        raise ValueError(f"Unknown evaluation capture IDs: {', '.join(unknown)}")

    evaluation_mask = groups.isin(selected)
    training_mask = ~evaluation_mask
    if not training_mask.any():
        raise ValueError("At least one capture must remain for training")
    all_labels = set(labels.unique())
    training_labels = set(labels[training_mask].unique())
    evaluation_labels = set(labels[evaluation_mask].unique())
    if training_labels != all_labels or evaluation_labels != all_labels:
        missing_train = sorted(all_labels - training_labels)
        missing_eval = sorted(all_labels - evaluation_labels)
        raise ValueError(
            "Every label must occur in both training and held-out captures. "
            f"Missing from training: {missing_train}; missing from evaluation: {missing_eval}"
        )

    estimator = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=1,
    )
    estimator.fit(features.loc[training_mask], labels.loc[training_mask])
    predictions = estimator.predict(features.loc[evaluation_mask])
    actual = labels.loc[evaluation_mask]
    label_order = sorted(all_labels)
    precision, recall, f1, support = precision_recall_fscore_support(
        actual, predictions, labels=label_order, zero_division=0
    )
    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(actual, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(actual, predictions)),
        "labels": label_order,
        "confusion_matrix": confusion_matrix(
            actual, predictions, labels=label_order
        ).tolist(),
        "per_label": {
            label: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, label in enumerate(label_order)
        },
        "training_windows": int(training_mask.sum()),
        "evaluation_windows": int(evaluation_mask.sum()),
        "training_capture_ids": sorted(set(groups.loc[training_mask])),
        "evaluation_capture_ids": sorted(selected),
    }
    if label_order == ["Benign", "DDoS"]:
        matrix = metrics["confusion_matrix"]
        metrics["benign_false_alarm_rate"] = matrix[0][1] / sum(matrix[0])
        metrics["ddos_recall"] = matrix[1][1] / sum(matrix[1])

    metadata = {
        "model_type": "RandomForestClassifier",
        "feature_schema_version": MODEL_SCHEMA_VERSION,
        "feature_columns": list(FEATURE_COLUMNS),
        "split_method": "explicit_held_out_capture_ids",
        "input_sha256": input_sha256,
        "random_state": random_state,
        "n_estimators": n_estimators,
        "training_capture_ids": metrics["training_capture_ids"],
        "evaluation_capture_ids": metrics["evaluation_capture_ids"],
        "training_windows": metrics["training_windows"],
        "evaluation_windows": metrics["evaluation_windows"],
    }
    return metrics, TrafficClassifier(estimator, metadata)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-csv", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--eval-capture-id",
        action="append",
        default=[],
        help="Whole capture ID to hold out; repeat for multiple captures",
    )
    parser.add_argument("--model", type=Path, help="Optional model artifact after evaluation")
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()
    if args.model and not args.eval_capture_id:
        parser.error("--model requires at least one --eval-capture-id")

    dataset = pd.read_csv(args.input_csv, dtype={"label": str, "capture_id": str})
    try:
        features, labels, groups = validate_dataset(dataset)
    except ValueError as error:
        parser.error(str(error))
    report = readiness_report(dataset, labels, groups, args.input_csv)
    if args.eval_capture_id:
        if report["blockers"]:
            save_metrics(report, args.report)
            parser.error("Capture holdout is blocked: " + " ".join(report["blockers"]))
        try:
            metrics, classifier = evaluate_holdout(
                features,
                labels,
                groups,
                args.eval_capture_id,
                input_sha256=report["input_sha256"],
                random_state=args.random_state,
                n_estimators=args.n_estimators,
            )
        except ValueError as error:
            parser.error(str(error))
        report["evaluation"] = metrics
        if args.model:
            classifier.save(args.model)
    save_metrics(report, args.report)
    print(f"Capture readiness report written to {args.report}")
    if report["blockers"]:
        print("Evaluation blocked: " + " ".join(report["blockers"]))


if __name__ == "__main__":
    main()
