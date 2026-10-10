"""Train on 2019 and 2017 flows; evaluate once on held-out 2018 flows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from sentinelshield.evaluation.flow_baseline import (
    FEATURE_COLUMNS,
    evaluate,
    load_flows,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cicddos2019-csv", type=Path, required=True)
    parser.add_argument("--cicids2017-csv", type=Path, required=True)
    parser.add_argument("--cicids2018-csv", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    paths = [
        args.cicddos2019_csv.resolve(),
        args.cicids2017_csv.resolve(),
        args.cicids2018_csv.resolve(),
    ]
    if len(set(paths)) != len(paths):
        parser.error("Training and evaluation files must be distinct")

    x_2019, y_2019, audit_2019 = load_flows(args.cicddos2019_csv, "cicddos2019")
    x_2017, y_2017, audit_2017 = load_flows(args.cicids2017_csv, "cicids2017")
    x_2018, y_2018, audit_2018 = load_flows(args.cicids2018_csv, "cicids2018")
    x_train = pd.concat((x_2019, x_2017), ignore_index=True)
    y_train = pd.concat((y_2019, y_2017), ignore_index=True)

    estimator = RandomForestClassifier(
        n_estimators=80,
        max_depth=16,
        min_samples_leaf=5,
        class_weight="balanced_subsample",
        random_state=args.random_state,
        n_jobs=-1,
    )
    estimator.fit(x_train, y_train)
    predictions = estimator.predict(x_2018)
    report = {
        "evaluation_kind": "three_dataset_flow_baseline",
        "held_out_dataset_source": {
            "original": "https://www.unb.ca/cic/datasets/ids-2018.html",
            "single_file_mirror": (
                "https://huggingface.co/datasets/pcy12345BSU/CSE-CIC-IDS-2018/"
                "resolve/main/data/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"
            ),
        },
        "model": "RandomForestClassifier",
        "random_state": args.random_state,
        "feature_columns": list(FEATURE_COLUMNS),
        "training_audits": [audit_2019, audit_2017],
        "evaluation_audit": audit_2018,
        "training_rows": int(len(x_train)),
        "external_evaluation": evaluate(y_2018, predictions),
        "always_ddos_reference": evaluate(
            y_2018, np.full(len(y_2018), "DDoS", dtype=object)
        ),
        "always_benign_reference": evaluate(
            y_2018, np.full(len(y_2018), "Benign", dtype=object)
        ),
        "limitations": [
            "The 2019 file's original provenance remains unverified.",
            "The 2017 file was used for diagnostic inspection before this training run.",
            "The 2018 file is one held-out capture day, not proof of current-network performance.",
            "The mirrored 2018 file has exactly 1,048,575 data rows; its completeness against the original release has not been verified.",
            "This flow model cannot be loaded by the live packet-window detector.",
        ],
    }
    args.model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "artifact_kind": "cic_multisource_binary_flow_baseline",
            "feature_schema_version": 1,
            "feature_columns": list(FEATURE_COLUMNS),
            "estimator": estimator,
            "training_audits": [audit_2019, audit_2017],
        },
        args.model,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
