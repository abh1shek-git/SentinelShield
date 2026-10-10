# SentinelShield

SentinelShield is a student project exploring cautious, flow-based detection of unusual network traffic. It is being built incrementally; this repository currently contains an initial packet-printing script and an experimental live traffic counter.

## Current status

- `sniffer.py` captures up to 20 packets and prints basic IPv4 metadata, then exits.
- `traffice_counter.py` captures indefinitely and reports per-source packet counts and TCP SYN ratios in five-second windows.
- The counter's fixed thresholds (500 packets and 70% SYN) are unvalidated experiments. High packet volume or a high SYN ratio alone does not prove a DDoS attack.
- Packet capture is live and starts immediately when either script is run. It may require Npcap and elevated permissions on Windows. Do not run it on networks you are not authorized to monitor.
- Offline PCAP metadata reading, labelled synthetic scenarios, and fixed-window aggregate features are implemented and covered by unit tests.
- The interpretable rule detector and adaptive packet-rate baseline are implemented and tested.
- The supervised Random Forest training, holdout evaluation, versioned model artifact, and inference path are implemented. Synthetic data is available only as a clearly marked pipeline demo.
- SQLite persists aggregate windows, deduplicated alerts, and simulation-only expiring block entries.
- The Streamlit dashboard displays synthetic and uploaded offline traffic, rules, optional synthetic-only ML comparison, stored alerts, and simulation-only block entries.
- The dashboard now offers bounded, opt-in live capture after an explicit authorization checkbox and button click. Capture is limited to 60 seconds and stores only derived packet metadata.

The misspelled legacy filename `traffice_counter.py` is retained for now so existing work is preserved. It will be renamed only alongside an intentional migration step.

## Proposed structure

```text
sentinelshield/
  config.py
  collection/       # offline PCAP, synthetic source, optional live capture
  processing/       # packet metadata, time windows, flows, features
  detection/        # interpretable rules and ML inference
  mitigation/       # simulation first; enforcement disabled by default
  storage/          # SQLite events and statistics
  evaluation/       # dataset preparation and measured comparisons
  dashboard/        # Streamlit application
tests/
docs/
```

## Development sequence

1. Repository foundation and audit (current step).
2. Offline and synthetic collection with deterministic feature extraction.
3. Interpretable rule-based detection and adaptive baseline (implemented).
4. Reproducible ML training, inference, and evaluation (initial pipeline implemented).
5. SQLite event storage and simulated, expiring blocklist (implemented).
6. Streamlit and Plotly dashboard (initial integration implemented).
7. Optional, opt-in live capture (implemented with a bounded dashboard control).
8. Real-data evaluation and complete technical documentation (evaluation still requires a labeled dataset; no real-world scores are claimed).

The core pipeline was developed and verified before adding live capture. Firewall enforcement remains out of scope. Synthetic scenarios are labelled synthetic; no performance results are claimed.

## First processing slice

`sentinelshield.processing.traffic` converts IPv4/IPv6 packets into metadata records and aggregates them into epoch-aligned windows. It stores no payload. The current feature set includes packet/byte rates, packet size statistics, protocol counts, initial SYN-only and SYN-ACK counts, TCP ACK/FIN/RST flag counts, unique IPs/ports, and five-tuple flow count. The SYN ratio is initial SYN-only packets divided by TCP packets; it is only one indicator and is not an attack verdict. Offline PCAP support and small deterministic `normal`/`syn_heavy` synthetic scenarios are available.

`sentinelshield.detection.RuleBasedDetector` compares packet rate with a rolling median/MAD baseline after a configurable warm-up. Before warm-up, it uses an absolute configurable rate floor. Only windows considered normal enter the baseline. High rate alone is labeled `Unusual Traffic`; a high initial-SYN ratio/rate alone is `Suspicious TCP SYN Pattern`; only both together produce the cautious label `Potential DDoS Activity`. Defaults are starting values and have not been calibrated on a real labeled dataset.

The initial supervised ML path trains a Random Forest from a labeled feature CSV and reports stratified holdout accuracy, weighted precision/recall/F1, and a confusion matrix. A deterministic synthetic demo dataset is available for checking the training and inference code; its results are explicitly marked synthetic and do not describe real-world detection quality. Models store a feature schema version and dataset provenance.

`sentinelshield.storage.SQLiteStore` saves aggregate windows, alert reasons, and mitigation decisions in SQLite. Repeated windows and identical alerts are ignored. Simulated IP blocks are validated, expire according to their UTC timestamp, and remain in the history after expiry. This component has no firewall or operating-system enforcement path.

Run the unit tests with:

```powershell
python -m unittest discover -s tests -v
```

Train a clearly labeled synthetic demonstration model and write a local metrics file:

```powershell
python -m sentinelshield.evaluation.train --synthetic-demo --model models/synthetic-demo.joblib --metrics results/synthetic-demo.json
```

Launch the dashboard after installing project dependencies. Use the virtual environment's Python so it can find Streamlit and Plotly:

```powershell
.\.venv\Scripts\python.exe -m streamlit run sentinelshield/dashboard/app.py
```

The dashboard defaults to a local synthetic demonstration. You can switch to an authorized offline PCAP/PCAPNG upload or start a single live capture on a selected interface after confirming authorization. Live capture is explicitly user-triggered, lasts at most 60 seconds, and keeps derived headers/flow metadata only; raw packet payloads are not retained. On Windows, live capture may require Npcap and appropriate interface permissions. Uploaded capture bytes are parsed via a temporary file and are not copied into SQLite. The optional ML comparison trains a clearly labeled synthetic-only model in memory. The simulated block control only records a database entry; it never changes firewall or network settings.

Technical guides: [dashboard demo](docs/DEMO_GUIDE.md), [live capture](docs/LIVE_CAPTURE.md), [dataset preparation](docs/DATASET_PREPARATION.md), [feature definitions](docs/FEATURES.md), [detection behavior](docs/DETECTION.md), [ML evaluation](docs/ML_EVALUATION.md), and [SQLite storage](docs/STORAGE.md).

To train from measured labeled windows, provide a CSV containing all feature columns in `sentinelshield.evaluation.model.FEATURE_COLUMNS` plus a `label` column:

```powershell
python -m sentinelshield.evaluation.train --input-csv data/processed/labeled_windows.csv --model models/traffic-model.joblib --metrics results/traffic-model.json
```

Only load model artifacts you created or trust; Joblib uses Python object serialization. A model trained on synthetic or unrepresentative data is not evidence that it will detect real attacks.

## Environment

The current machine has Python 3.14.3, Scapy, Pandas, NumPy, and scikit-learn available. The global Python 3.11 environment contains Streamlit 1.53.1 but no Plotly; the project requires Streamlit 1.57 or newer and installs the dashboard dependencies in a virtual environment.

```powershell
py -3.14 -m venv .venv --system-site-packages
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Python 3.12–3.14 are the supported targets. The project virtual environment keeps its dashboard dependencies separate from global Python packages.

## Run current scripts

Both scripts start live capture immediately; use only in an authorized environment.

```powershell
python .\sniffer.py
python .\traffice_counter.py
```

`sniffer.py` stops after 20 packets. `traffice_counter.py` runs until interrupted with Ctrl+C. On Windows, install Npcap and select an authorized interface before capture. Host capture only observes traffic visible to that host/interface; it does not automatically monitor all devices on a network.

## Safety and limits

SentinelShield is a monitoring and research project, not proof of malicious intent. A busy server, shared NAT, or CDN can produce high traffic. The early SYN heuristic only concerns one TCP pattern and can have false positives and false negatives. Mitigation will default to simulation; no real firewall changes are part of the current implementation.
