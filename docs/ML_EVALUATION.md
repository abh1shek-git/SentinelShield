# Supervised ML training and evaluation

SentinelShield currently uses a supervised `RandomForestClassifier` over the aggregate window features. The model is trained by this project from labeled examples; it does not load a pretrained network-security model.

## Input dataset

Provide a CSV with the 21 numeric features listed by `FEATURE_COLUMNS` in `sentinelshield.evaluation.model`, plus a `label` column. Extra columns are ignored for fitting. If present, `source_kind` is recorded as dataset provenance but is not a model feature. Rows with missing, non-numeric, or non-finite feature values are rejected. Each label needs at least two rows for a stratified train/test split.

Labels in the synthetic demo are `Normal`, `Unusual Traffic`, `Suspicious TCP SYN Pattern`, and `Potential DDoS Activity`. Real datasets may use different labels; map them deliberately and document how labels were assigned before training.

## Training and metrics

The default split reserves 25% of examples for a stratified holdout using random state 42. The model uses 200 trees, class-balanced subsampling, and a fixed random seed. Evaluation reports accuracy, weighted precision, weighted recall, weighted F1, label order, confusion matrix, and holdout size. Metrics are calculated from the held-out rows by the code; no results are hard-coded.

For reliable research evaluation, ensure related flows/captures do not appear in both train and test partitions. A random row split can leak capture-specific patterns when rows from the same time series are correlated. This initial pipeline does not yet support grouped or time-based splitting, so its metrics are only a first-stage check and can be optimistic for real captures.

## Synthetic demo

`generate_synthetic_dataset` creates a deterministic, explicitly synthetic set of feature rows with separable scenario ranges. It is useful for verifying that CSV validation, model fitting, artifact saving/loading, metrics, and inference work together. Its generated class patterns are hand-designed, so performance on this data is not a benchmark, not a DDoS efficacy result, and not evidence of generalization.

## Model artifacts

Saved artifacts include a schema version, exact ordered feature list, model, and metadata about random seed, sample counts, class counts, and data source. Loading rejects missing or incompatible artifacts. Only load locally created or otherwise trusted Joblib files because deserializing an untrusted artifact can execute code.

## Current limitations

- No public labeled dataset has been downloaded or evaluated yet.
- There are no measured real-world precision, recall, F1, false-positive, or false-negative results.
- The random row split can overstate performance if correlated rows are present.
- The demo data is deliberately separable and does not model diverse benign traffic or realistic attack variability.
- No probability calibration, threshold selection, drift monitoring, grouped split, or time-based evaluation exists yet.
- The ML label is a learned pattern classification and must not be presented as confirmation that an attack occurred.
