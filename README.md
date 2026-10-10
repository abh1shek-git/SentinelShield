# SentinelShield

SentinelShield is a student project exploring cautious, flow-based detection of unusual network traffic. It is being built incrementally; this repository currently contains an initial packet-printing script and an experimental live traffic counter.

## Current status

- `sniffer.py` captures up to 20 packets and prints basic IPv4 metadata, then exits.
- `traffice_counter.py` captures indefinitely and reports per-source packet counts and TCP SYN ratios in five-second windows.
- The counter's fixed thresholds (500 packets and 70% SYN) are unvalidated experiments. High packet volume or a high SYN ratio alone does not prove a DDoS attack.
- Packet capture is live and starts immediately when either script is run. It may require Npcap and elevated permissions on Windows. Do not run it on networks you are not authorized to monitor.
- Offline PCAP metadata reading, labelled synthetic scenarios, and fixed-window aggregate features are implemented and covered by unit tests.
- Rule-based detection, adaptive baselines, ML, persistence, dashboard, and live capture integration have not yet been implemented.

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
3. Interpretable rule-based detection and adaptive baseline.
4. Reproducible ML training, inference, and evaluation.
5. SQLite event storage and simulated, expiring blocklist.
6. Streamlit and Plotly dashboard.
7. Optional, opt-in live capture.
8. Evaluation, demonstration instructions, and complete technical documentation.

The core pipeline will be developed and verified before live capture or firewall enforcement. Synthetic scenarios are labelled synthetic; no performance results are claimed.

## First processing slice

`sentinelshield.processing.traffic` converts IPv4/IPv6 packets into metadata records and aggregates them into epoch-aligned windows. It stores no payload. The current feature set includes packet/byte rates, packet size statistics, protocol counts, initial SYN-only and SYN-ACK counts, TCP ACK/FIN/RST flag counts, unique IPs/ports, and five-tuple flow count. The SYN ratio is initial SYN-only packets divided by TCP packets; it is only one indicator and is not an attack verdict. Offline PCAP support and small deterministic `normal`/`syn_heavy` synthetic scenarios are available.

Run the unit tests with:

```powershell
python -m unittest discover -s tests -v
```

## Environment

The current machine has Python 3.14.3, Scapy, Pandas, NumPy, and scikit-learn available. pytest, FastAPI, Streamlit, and Plotly were not found in the current environment during the initial audit. Install project dependencies in a virtual environment using the commands below. The initial code does not yet use these dependencies.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Python 3.12 is the initial supported target for broad compatibility with the selected networking and dashboard libraries. Dependency resolution on the current Python 3.14 installation has not yet been verified.

## Run current scripts

Both scripts start live capture immediately; use only in an authorized environment.

```powershell
python .\sniffer.py
python .\traffice_counter.py
```

`sniffer.py` stops after 20 packets. `traffice_counter.py` runs until interrupted with Ctrl+C. On Windows, install Npcap and select an authorized interface before capture. Host capture only observes traffic visible to that host/interface; it does not automatically monitor all devices on a network.

## Safety and limits

SentinelShield is a monitoring and research project, not proof of malicious intent. A busy server, shared NAT, or CDN can produce high traffic. The early SYN heuristic only concerns one TCP pattern and can have false positives and false negatives. Mitigation will default to simulation; no real firewall changes are part of the current implementation.
