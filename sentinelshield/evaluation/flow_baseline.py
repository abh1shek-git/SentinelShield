"""Train a binary flow baseline and evaluate on a separate CIC dataset."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


# Only flow measurements with the same meaning in both supplied CSV schemas.
# Protocol and destination port are deliberately excluded: each is absent from
# one source. The existing packet-window model uses a different feature schema.
FEATURE_ALIASES = {
    "flow_duration": ("Flow Duration", "Flow Duration"),
    "fwd_packets": ("Total Fwd Packets", "Total Fwd Packets"),
    "bwd_packets": ("Total Backward Packets", "Total Backward Packets"),
    "fwd_bytes": ("Fwd Packets Length Total", "Total Length of Fwd Packets"),
    "bwd_bytes": ("Bwd Packets Length Total", "Total Length of Bwd Packets"),
    "fwd_packet_length_max": ("Fwd Packet Length Max", "Fwd Packet Length Max"),
    "fwd_packet_length_mean": ("Fwd Packet Length Mean", "Fwd Packet Length Mean"),
    "fwd_packet_length_std": ("Fwd Packet Length Std", "Fwd Packet Length Std"),
    "bwd_packet_length_max": ("Bwd Packet Length Max", "Bwd Packet Length Max"),
    "bwd_packet_length_mean": ("Bwd Packet Length Mean", "Bwd Packet Length Mean"),
    "bwd_packet_length_std": ("Bwd Packet Length Std", "Bwd Packet Length Std"),
    "flow_packets_per_second": ("Flow Packets/s", "Flow Packets/s"),
    "flow_bytes_per_second": ("Flow Bytes/s", "Flow Bytes/s"),
    "flow_iat_mean": ("Flow IAT Mean", "Flow IAT Mean"),
    "flow_iat_std": ("Flow IAT Std", "Flow IAT Std"),
    "packet_length_mean": ("Packet Length Mean", "Packet Length Mean"),
    "packet_length_std": ("Packet Length Std", "Packet Length Std"),
    "syn_flag_count": ("SYN Flag Count", "SYN Flag Count"),
    "ack_flag_count": ("ACK Flag Count", "ACK Flag Count"),
    "fin_flag_count": ("FIN Flag Count", "FIN Flag Count"),
    "rst_flag_count": ("RST Flag Count", "RST Flag Count"),
}
FEATURE_COLUMNS = tuple(FEATURE_ALIASES)
LABELS = ("Benign", "DDoS")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_flows(path: Path, source: str) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Read common numeric flow features and audit excluded rows."""
    if source not in {"cicddos2019", "cicids2017"}:
        raise ValueError(f"Unsupported source: {source}")
    source_index = 0 if source == "cicddos2019" else 1
    header = pd.read_csv(path, nrows=0).columns
    stripped_to_raw = {name.strip(): name for name in header}
    needed = [aliases[source_index] for aliases in FEATURE_ALIASES.values()]
    needed += ["Label", "Class"] if source == "cicddos2019" else ["Label"]
    missing = sorted(set(needed) - set(stripped_to_raw))
    if missing:
        raise ValueError(f"{path.name} lacks expected columns: {', '.join(missing)}")

    raw_columns = [stripped_to_raw[name] for name in needed]
    frame = pd.read_csv(path, usecols=raw_columns, low_memory=False)
    frame.columns = frame.columns.str.strip()
    raw_labels = frame["Label"].astype("string").str.strip()
    if source == "cicddos2019":
        classes = frame["Class"].astype("string").str.strip()
        unknown = sorted(set(classes.dropna()) - {"Attack", "Benign"})
        if unknown or classes.isna().any():
            raise ValueError(f"Unexpected CIC-DDoS2019 Class values: {unknown}")
        inconsistent = (classes.eq("Benign") != raw_labels.eq("Benign")).fillna(True)
        if inconsistent.any():
            raise ValueError("CIC-DDoS2019 Label and Class columns disagree")
        labels = classes.map({"Attack": "DDoS", "Benign": "Benign"})
    else:
        unknown = sorted(set(raw_labels.dropna()) - {"BENIGN", "DDoS"})
        if unknown or raw_labels.isna().any():
            raise ValueError(f"Unexpected CIC-IDS2017 labels: {unknown}")
        labels = raw_labels.map({"BENIGN": "Benign", "DDoS": "DDoS"})

    renamed = {
        aliases[source_index]: canonical
        for canonical, aliases in FEATURE_ALIASES.items()
    }
    features = frame.rename(columns=renamed).loc[:, list(FEATURE_COLUMNS)]
    features = features.apply(pd.to_numeric, errors="coerce")
    valid = np.isfinite(features.to_numpy(dtype=np.float64)).all(axis=1)
    clean_features = features.loc[valid].reset_index(drop=True).astype(np.float32)
    clean_labels = labels.loc[valid].reset_index(drop=True)
    if set(clean_labels.unique()) != set(LABELS):
        raise ValueError(f"Both labels are required after cleaning {path.name}")
    audit = {
        "file": path.name,
        "sha256": _sha256(path),
        "original_rows": int(len(frame)),
        "valid_rows": int(valid.sum()),
        "removed_nonfinite_or_missing_feature_rows": int((~valid).sum()),
        "label_counts": {key: int(value) for key, value in Counter(clean_labels).items()},
        "raw_label_counts": {key: int(value) for key, value in Counter(raw_labels).items()},
        "duplicate_feature_rows": int(clean_features.duplicated().sum()),
    }
    return clean_features, clean_labels, audit


def evaluate(labels: pd.Series, predictions: np.ndarray) -> dict:
    matrix = confusion_matrix(labels, predictions, labels=LABELS)
    true_benign, false_alarms, missed_ddos, detected_ddos = matrix.ravel()
    return {
        "labels": list(LABELS),
        "confusion_matrix": matrix.tolist(),
        "accuracy": float(accuracy_score(labels, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "ddos_precision": float(
            precision_score(labels, predictions, pos_label="DDoS", zero_division=0)
        ),
        "ddos_recall": float(recall_score(labels, predictions, pos_label="DDoS")),
        "ddos_f1": float(f1_score(labels, predictions, pos_label="DDoS")),
        "false_alarm_rate": float(false_alarms / (true_benign + false_alarms)),
        "false_alarms": int(false_alarms),
        "missed_ddos": int(missed_ddos),
        "detected_ddos": int(detected_ddos),
        "evaluated_rows": int(len(labels)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-csv", type=Path, required=True)
    parser.add_argument("--eval-csv", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    if args.train_csv.resolve() == args.eval_csv.resolve():
        parser.error("Training and external evaluation must use different files")

    x_train, y_train, train_audit = load_flows(args.train_csv, "cicddos2019")
    x_eval, y_eval, eval_audit = load_flows(args.eval_csv, "cicids2017")
    estimator = RandomForestClassifier(
        n_estimators=80,
        max_depth=16,
        min_samples_leaf=5,
        class_weight="balanced_subsample",
        random_state=args.random_state,
        n_jobs=-1,
    )
    estimator.fit(x_train, y_train)
    predictions = estimator.predict(x_eval)
    report = {
        "evaluation_kind": "cross_dataset_flow_baseline",
        "train_source": "user_supplied_CIC_DDoS2019_CSV_provenance_unverified",
        "eval_source": "user_supplied_CIC_IDS2017_Friday_DDoS_CSV",
        "model": "RandomForestClassifier",
        "random_state": args.random_state,
        "feature_columns": list(FEATURE_COLUMNS),
        "training_audit": train_audit,
        "evaluation_audit": eval_audit,
        "external_evaluation": evaluate(y_eval, predictions),
        "always_ddos_reference": evaluate(
            y_eval, np.full(len(y_eval), "DDoS", dtype=object)
        ),
        "limitations": [
            "Flow-level classification is incompatible with the live packet-window model.",
            "The supplied CIC-DDoS2019 file's original provenance is unverified.",
            "One external capture cannot establish performance on current live traffic.",
            "The external dataset was used for evaluation, not model selection or tuning.",
        ],
    }
    args.model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "artifact_kind": "cic_binary_flow_baseline",
            "feature_schema_version": 1,
            "feature_columns": list(FEATURE_COLUMNS),
            "estimator": estimator,
            "training_audit": train_audit,
        },
        args.model,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
