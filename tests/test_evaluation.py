import unittest
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

import joblib
import pandas as pd

from sentinelshield.collection.synthetic import make_synthetic_scenario
from sentinelshield.evaluation.dataset import LABELS, generate_synthetic_dataset
from sentinelshield.evaluation.model import TrafficClassifier, train_classifier
from sentinelshield.evaluation.train import main as train_cli_main
from sentinelshield.processing.traffic import aggregate_windows


class SyntheticDatasetTests(unittest.TestCase):
    def test_generator_is_reproducible_and_marked(self):
        first = generate_synthetic_dataset(samples_per_class=5, random_state=7)
        second = generate_synthetic_dataset(samples_per_class=5, random_state=7)
        pd.testing.assert_frame_equal(first, second)
        self.assertEqual(set(first["label"]), set(LABELS))
        self.assertEqual(set(first["source_kind"]), {"synthetic"})

    def test_requires_enough_examples_for_holdout(self):
        with self.assertRaises(ValueError):
            generate_synthetic_dataset(samples_per_class=4)


class ModelTrainingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dataset = generate_synthetic_dataset(samples_per_class=12, random_state=3)
        cls.result = train_classifier(dataset, random_state=3, n_estimators=30)

    def test_training_returns_real_holdout_metrics_and_provenance(self):
        result = self.result
        self.assertEqual(result.metadata["model_type"], "RandomForestClassifier")
        self.assertEqual(result.metadata["dataset_sources"], ["synthetic"])
        self.assertTrue(result.metadata["metrics_are_synthetic_demo_only"])
        self.assertEqual(result.metrics["holdout_samples"], 12)
        self.assertEqual(len(result.metrics["confusion_matrix"]), 4)
        self.assertEqual(len(result.metrics["confusion_matrix"][0]), 4)

    def test_inference_accepts_window_features(self):
        features = aggregate_windows(make_synthetic_scenario("syn_heavy"))[0]
        prediction = self.result.classifier.predict(features)
        self.assertIn(prediction, LABELS)

    def test_saved_model_round_trips_with_same_prediction(self):
        features = aggregate_windows(make_synthetic_scenario("normal"))[0]
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            model_path = Path(directory) / "model.joblib"
            self.result.classifier.save(model_path)
            loaded = TrafficClassifier.load(model_path)

        self.assertEqual(
            loaded.predict(features), self.result.classifier.predict(features)
        )
        self.assertEqual(loaded.metadata["dataset_sources"], ["synthetic"])

    def test_training_rejects_missing_features(self):
        dataset = generate_synthetic_dataset(samples_per_class=5)
        with self.assertRaisesRegex(ValueError, "missing required columns"):
            train_classifier(dataset.drop(columns=["syn_ratio"]))

    def test_training_rejects_missing_labels_and_nonfinite_values(self):
        dataset = generate_synthetic_dataset(samples_per_class=5)
        missing_label = dataset.drop(columns=["label"])
        with self.assertRaisesRegex(ValueError, "missing required columns"):
            train_classifier(missing_label)

        dataset.loc[0, "syn_ratio"] = float("nan")
        with self.assertRaisesRegex(ValueError, "missing feature values"):
            train_classifier(dataset)

    def test_model_loader_rejects_incompatible_artifact_and_missing_path(self):
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            with self.assertRaises(FileNotFoundError):
                TrafficClassifier.load(root / "missing.joblib")
            incompatible_path = root / "incompatible.joblib"
            joblib.dump({"schema_version": 999}, incompatible_path)
            with self.assertRaisesRegex(ValueError, "schema version"):
                TrafficClassifier.load(incompatible_path)

    def test_synthetic_demo_cli_writes_model_and_metrics(self):
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            arguments = [
                "train",
                "--synthetic-demo",
                "--samples-per-class",
                "5",
                "--model",
                str(root / "demo.joblib"),
                "--metrics",
                str(root / "metrics.json"),
            ]
            output = io.StringIO()
            with patch.object(sys, "argv", arguments), redirect_stdout(output):
                train_cli_main()
            self.assertTrue((root / "demo.joblib").exists())
            self.assertTrue((root / "metrics.json").exists())
            self.assertIn('"metrics_are_synthetic_demo_only": true', output.getvalue())

    def test_labeled_csv_cli_preserves_synthetic_provenance_column(self):
        dataset = generate_synthetic_dataset(samples_per_class=5, random_state=11)
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            csv_path = root / "labeled.csv"
            dataset.to_csv(csv_path, index=False)
            arguments = [
                "train",
                "--input-csv",
                str(csv_path),
                "--model",
                str(root / "csv-model.joblib"),
            ]
            output = io.StringIO()
            with patch.object(sys, "argv", arguments), redirect_stdout(output):
                train_cli_main()
            self.assertTrue((root / "csv-model.joblib").exists())
            output_document = json.loads(output.getvalue())
            self.assertEqual(output_document["metadata"]["dataset_sources"], ["synthetic"])
            self.assertTrue(output_document["metadata"]["metrics_are_synthetic_demo_only"])


if __name__ == "__main__":
    unittest.main()
