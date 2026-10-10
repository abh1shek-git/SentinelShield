"""Reproducible supervised model training and validated inference."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from sentinelshield.processing.traffic import TrafficWindowFeatures


MODEL_SCHEMA_VERSION = 1
FEATURE_COLUMNS = (
    "packet_count",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_bytes",
    "minimum_packet_bytes",
    "maximum_packet_bytes",
    "tcp_packets",
    "udp_packets",
    "icmp_packets",
    "other_packets",
    "syn_count",
    "syn_ack_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_ratio",
    "unique_sources",
    "unique_destinations",
    "unique_destination_ports",
    "unique_flows",
)
LABEL_COLUMN = "label"


@dataclass(frozen=True, slots=True)
class TrainingResult:
    """Trained estimator, holdout metrics, and provenance metadata."""

    classifier: "TrafficClassifier"
    metrics: dict[str, Any]
    metadata: dict[str, Any]


class TrafficClassifier:
    """A trained random forest with an explicit, versioned feature schema."""

    def __init__(self, estimator: RandomForestClassifier, metadata: dict[str, Any]):
        self.estimator = estimator
        self.metadata = metadata

    def predict(self, features: TrafficWindowFeatures) -> str:
        """Predict one window label using the features used during training."""
        row = {name: getattr(features, name) for name in FEATURE_COLUMNS}
        frame = pd.DataFrame([row], columns=FEATURE_COLUMNS)
        return str(self.estimator.predict(frame)[0])

    def save(self, path: str | Path) -> None:
        """Persist the estimator together with schema and provenance metadata."""
        artifact = {
            "schema_version": MODEL_SCHEMA_VERSION,
            "feature_columns": list(FEATURE_COLUMNS),
            "metadata": self.metadata,
            "estimator": self.estimator,
        }
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(artifact, target)

    @classmethod
    def load(cls, path: str | Path) -> "TrafficClassifier":
        """Load a model only when its artifact and feature schema are compatible."""
        artifact = joblib.load(Path(path))
        if not isinstance(artifact, dict):
            raise ValueError("Model artifact must be a dictionary")
        if artifact.get("schema_version") != MODEL_SCHEMA_VERSION:
            raise ValueError("Unsupported model artifact schema version")
        if artifact.get("feature_columns") != list(FEATURE_COLUMNS):
            raise ValueError("Model feature schema does not match this application")
        estimator = artifact.get("estimator")
        metadata = artifact.get("metadata")
        if not isinstance(estimator, RandomForestClassifier) or not isinstance(
            metadata, dict
        ):
            raise ValueError("Model artifact is missing a compatible estimator or metadata")
        return cls(estimator, metadata)


def train_classifier(
    dataset: pd.DataFrame,
    *,
    test_size: float = 0.25,
    random_state: int = 42,
    n_estimators: int = 200,
) -> TrainingResult:
    """Train on labeled rows and evaluate once on a stratified holdout split."""
    required = {*FEATURE_COLUMNS, LABEL_COLUMN}
    missing = sorted(required - set(dataset.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {', '.join(missing)}")
    if not 0 < test_size < 1:
        raise ValueError("test_size must be between zero and one")
    if n_estimators < 1:
        raise ValueError("n_estimators must be at least one")

    frame = dataset.loc[:, [*FEATURE_COLUMNS, LABEL_COLUMN]].copy()
    if frame.isna().any().any():
        raise ValueError("Dataset contains missing feature values or labels")
    try:
        feature_frame = frame.loc[:, list(FEATURE_COLUMNS)].astype(float)
    except (TypeError, ValueError) as error:
        raise ValueError("All model features must be numeric") from error
    if not np.isfinite(feature_frame.to_numpy()).all():
        raise ValueError("Dataset features must contain only finite values")

    labels = frame[LABEL_COLUMN].astype(str)
    class_counts = labels.value_counts()
    if len(class_counts) < 2:
        raise ValueError("Dataset must contain at least two distinct labels")
    if int(class_counts.min()) < 2:
        raise ValueError("Each label must have at least two samples for stratified evaluation")

    x_train, x_test, y_train, y_test = train_test_split(
        feature_frame,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels,
    )
    estimator = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=1,
    )
    estimator.fit(x_train, y_train)
    predictions = estimator.predict(x_test)
    label_order = sorted(labels.unique().tolist())
    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision_weighted": float(
            precision_score(y_test, predictions, average="weighted", zero_division=0)
        ),
        "recall_weighted": float(
            recall_score(y_test, predictions, average="weighted", zero_division=0)
        ),
        "f1_weighted": float(
            f1_score(y_test, predictions, average="weighted", zero_division=0)
        ),
        "labels": label_order,
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=label_order
        ).tolist(),
        "holdout_samples": int(len(y_test)),
    }
    sources = (
        sorted(dataset["source_kind"].astype(str).unique().tolist())
        if "source_kind" in dataset.columns
        else ["user_supplied_csv_or_dataframe"]
    )
    metadata: dict[str, Any] = {
        "model_type": "RandomForestClassifier",
        "feature_schema_version": MODEL_SCHEMA_VERSION,
        "feature_columns": list(FEATURE_COLUMNS),
        "random_state": random_state,
        "n_estimators": n_estimators,
        "test_size": test_size,
        "training_samples": int(len(y_train)),
        "test_samples": int(len(y_test)),
        "label_counts": {str(label): int(count) for label, count in class_counts.items()},
        "dataset_sources": sources,
        "metrics_are_synthetic_demo_only": sources == ["synthetic"],
    }
    classifier = TrafficClassifier(estimator, metadata)
    return TrainingResult(classifier, metrics, metadata)


def save_metrics(metrics: dict[str, Any], path: str | Path) -> None:
    """Write evaluation metrics as readable JSON without inventing any values."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")


def metrics_json(result: TrainingResult) -> str:
    """Serialize metrics and dataset provenance for CLI output."""
    return json.dumps(
        {"metrics": result.metrics, "metadata": result.metadata}, indent=2
    )
