# Supervised ML training and evaluation

SentinelShield currently uses a supervised `RandomForestClassifier` over the aggregate window features. The model is trained by this project from labeled examples; it does not load a pretrained network-security model.

## Input dataset

Provide a CSV with the 21 numeric features listed by `FEATURE_COLUMNS` in `sentinelshield.evaluation.model`, plus a `label` column. Extra columns are ignored for fitting. If present, `source_kind` is recorded as dataset provenance but is not a model feature. Rows with missing, non-numeric, or non-finite feature values are rejected. Each label needs at least two rows for a stratified train/test split.

Labels in the synthetic demo are `Normal`, `Unusual Traffic`, `Suspicious TCP SYN Pattern`, and `Potential DDoS Activity`. Real datasets may use different labels; map them deliberately and document how labels were assigned before training.

## Training and metrics

The default split reserves 25% of examples for a stratified holdout using random state 42. The model uses 200 trees, class-balanced subsampling, and a fixed random seed. Evaluation reports accuracy, weighted precision, weighted recall, weighted F1, label order, confusion matrix, and holdout size. Metrics are calculated from the held-out rows by the code; no results are hard-coded.

Run the synthetic pipeline check or train from a CSV with these commands:

```powershell
.\.venv\Scripts\python.exe -m sentinelshield.evaluation.train --synthetic-demo --model models/synthetic-demo.joblib --metrics results/synthetic-demo.json
.\.venv\Scripts\python.exe -m sentinelshield.evaluation.train --input-csv data/processed/labeled_windows.csv --model models/traffic-model.joblib --metrics results/traffic-model.json
```

The CSV must contain all 21 numeric feature columns and `label`. An optional `source_kind` column is copied into provenance metadata and is not used as a feature. If omitted, the CLI marks provenance as `unspecified_csv_provenance`; do not treat that as verified real data. Synthetic outputs and local model artifacts are ignored by Git.

For reliable research evaluation, ensure related flows/captures do not appear in both train and test partitions. A random row split can leak capture-specific patterns when rows from the same time series are correlated. This initial pipeline does not yet support grouped or time-based splitting, so its metrics are only a first-stage check and can be optimistic for real captures.

## Synthetic demo

`generate_synthetic_dataset` creates a deterministic, explicitly synthetic set of feature rows with separable scenario ranges. It is useful for verifying that CSV validation, model fitting, artifact saving/loading, metrics, and inference work together. Its generated class patterns are hand-designed, so performance on this data is not a benchmark, not a DDoS efficacy result, and not evidence of generalization.

## Model artifacts

Saved artifacts include a schema version, exact ordered feature list, model, and metadata about random seed, sample counts, class counts, and data source. Loading rejects missing or incompatible artifacts. Only load locally created or otherwise trusted Joblib files because deserializing an untrusted artifact can execute code.

## Current limitations

- A separate labeled-flow baseline has now been evaluated; its weak result does not validate the live packet-window model.
- There are no measured live packet-window precision, recall, F1, false-positive, or false-negative results.
- The random row split can overstate performance if correlated rows are present.
- The demo data is deliberately separable and does not model diverse benign traffic or realistic attack variability.
- No probability calibration, threshold selection, drift monitoring, grouped split, or time-based evaluation exists yet.
- The ML label is a learned pattern classification and must not be presented as confirmation that an attack occurred.
- The dashboard's optional ML comparison trains the bundled synthetic dataset in memory. It does not load a user-trained CSV model; user-trained artifacts are currently produced for separate evaluation/inference workflows.

## Cross-dataset flow baseline

The supplied `cicddos2019_dataset.csv` has 431,371 rows. Its `Class` column is mapped to binary `Benign` and `DDoS`; the specific attack name remains in the data audit. The separate supplied `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` has 225,745 rows labeled `BENIGN` or `DDoS`. The command selects 21 numeric flow measurements with the same meaning in both files. It excludes source-specific fields such as protocol and destination port. Missing and non-finite feature rows are removed and counted. The original CIC-DDoS2019 file provenance has not been verified independently.

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m sentinelshield.evaluation.flow_baseline --train-csv cicddos2019_dataset.csv --eval-csv Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --model models/cic-flow-baseline.joblib --report results/cic-flow-baseline.json
```

The model trains on all valid CIC-DDoS2019 rows and is evaluated only on the separate CIC-IDS2017 file. The fixed Random Forest settings and random seed are in the command's source. Both raw CSVs and the model artifact are ignored by Git; the small JSON report is committed for review. The output artifact has its own schema and must not be loaded by the dashboard's packet-window `TrafficClassifier`.

On this supplied copy, 34 non-finite CIC-IDS2017 rows were excluded, leaving 225,711 evaluation flows. The measured confusion matrix (rows: actual benign, DDoS; columns: predicted benign, DDoS) was `[[73445, 24241], [81433, 46592]]`. DDoS recall was **36.4%**, DDoS precision **65.8%**, and the benign false-alarm rate **24.8%**. Accuracy was **53.2%**, below the **56.7%** of an always-DDoS reference on this attack-heavy evaluation file; balanced accuracy was **55.8%** versus that reference's **50%**. This model misses too many attacks and raises too many false alarms for live use. It is an initial measure of cross-dataset transfer, not a claim of current-network performance. The external file was not used to tune the model.

## Why the flow baseline transfers poorly

The distribution diagnostic samples 20,000 flows per class from each dataset with seed 42. It reports per-feature Kolmogorov-Smirnov distances (0 means matching empirical distributions; 1 means no overlap), medians, and the trained model's impurity-based feature importances:

```powershell
.\.venv\Scripts\python.exe -m sentinelshield.evaluation.flow_shift --train-csv cicddos2019_dataset.csv --eval-csv Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --model models/cic-flow-baseline.joblib --report results/flow-shift.json
```

For attack flows, median forward bytes are **2,064** in the 2019 file versus **26** in the 2017 file (KS distance **0.87**). Median forward packet length is **440** versus **7** (KS distance **0.83**). Forward packet length is also the model's highest-importance feature. These differences are consistent with the failed transfer, although impurity importance and distribution differences do not prove a single cause. Benign traffic differs too: median flow inter-arrival time is **7,009.5** versus **56,179** in the source units (KS distance **0.30**). See [the full diagnostic](../results/flow-shift.json).

This inspection uses the 2017 file to guide future work, so it is no longer an untouched final benchmark for model changes. A future improved model needs another independent capture for final evaluation. Until then, do not deploy this flow model or present its score as live DDoS detection performance.

## Third-dataset held-out evaluation

A second baseline trains on the valid 2019 and 2017 rows together, then evaluates once on a separate 2018 capture day. The 2018 CSV came from a [single-file mirror](https://huggingface.co/datasets/pcy12345BSU/CSE-CIC-IDS-2018/tree/main/data) of the [CSE-CIC-IDS2018 dataset](https://www.unb.ca/cic/datasets/ids-2018.html). The original dataset authors should be cited when using these results. The raw file stays in Git-ignored `data/raw/`.

```powershell
.\.venv\Scripts\python.exe -m sentinelshield.evaluation.flow_multisource --cicddos2019-csv cicddos2019_dataset.csv --cicids2017-csv Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --cicids2018-csv data/raw/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv --model models/cic-multisource-flow.joblib --report results/cic-multisource-flow.json
```

The 2018 file has **1,048,575** rows: 360,833 benign, 686,012 labeled `DDOS attack-HOIC`, and 1,730 labeled `DDOS attack-LOIC-UDP`. This exact row count is one below Excel's worksheet row limit; completeness of the mirror against the original release has not been verified. The file also has 487,378 duplicate rows under the selected 21-feature schema, which limits how much independent information the row count represents.

The model trained on **657,082** valid 2019 and 2017 flows. On the held-out 2018 file, its confusion matrix was `[[360521, 312], [687716, 26]]` (rows and columns ordered benign, DDoS). It detected just **26 of 687,742 DDoS flows**, or **0.0038% recall**, with **312 false alarms**. Accuracy was **34.38%**, roughly the **34.41%** of an always-benign classifier on this file. See [the full report](../results/cic-multisource-flow.json) for source hashes, exclusions, and reference baselines.

After recording that held-out result, inspection found median forward and backward byte totals of **zero** for 2018 DDoS flows. The earlier 2019 and 2017 DDoS flows had different packet-size patterns, so the training examples do not cover this attack behavior well. This is an observed distribution difference, not proof of a single cause. The 2018 file has now also been inspected for diagnosis; any future model tuned in response needs another independent final evaluation capture. The current flow models must remain separate from live detection.

## Before reporting a real-data result

Keep a record of the capture source, collection period, environment, label definitions, and exclusions. Have labels assigned independently of this model's predictions. Partition by capture, scenario, or time before training so adjacent windows from the same trace cannot land in both sets. The packet-window training CLI supports only a stratified random row split; use its metrics as a first-stage check and do not describe them as leakage-resistant research results. The separate flow baseline uses one training dataset and one external evaluation dataset. Report per-class errors and false alarms alongside aggregate scores when extending the evaluation.
