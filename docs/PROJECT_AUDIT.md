# Initial repository audit

Date: 2026-10-10

This file records the project state at the original repository audit. It is retained as historical context; its inventory, environment, and next-step sections do not describe the current implementation.

## Files and behavior

| File | Observed behavior | Initial concerns |
| --- | --- | --- |
| `sniffer.py` | Scapy captures 20 packets, printing IPv4 source, destination, protocol, and packet length. | Starts live capture at import/run; no interface selection, structured output, error handling, or safe offline path. |
| `traffice_counter.py` | Scapy counts packets and TCP SYN packets by source, printing every five seconds. | Typo in filename; global mutable state; fixed thresholds; no explicit window alignment or reset for inactive sources; starts unbounded live capture. |

## Workspace inventory

No tests, dependency manifest, configuration, datasets, dashboard, database, architecture documents, or Git repository were present at the initial audit. The existing scripts are retained unchanged in this first step.

## Environment observed

Python 3.14.3 is available. Scapy 2.7.0, Pandas 3.0.5, NumPy 2.5.2, and scikit-learn 1.9.0 were installed. pytest, FastAPI, Streamlit, and Plotly were not installed. There is no `gh` executable. The Python launcher reported an unresolved interpreter location, so a clean Python 3.12 virtual environment should be established before relying on package installation.

## Design decisions

- Build offline and synthetic sources before live capture so development does not need packet-capture privileges.
- Use a five-tuple for flow identity and configurable time windows, with metadata only and no payload retention.
- Treat rules as explainable signals, not proof of an attack; compare them with ML and report false positives/negatives.
- Keep mitigation simulated by default and isolate optional real enforcement behind explicit configuration and confirmation.
- Preserve the existing script names for this foundation step; migrate the misspelled counter filename deliberately later.

## Next implementation step at audit time

Create the package skeleton and an offline/synthetic input contract, then implement deterministic packet metadata and window feature extraction with focused tests. The scripts remain as legacy demonstrations until replacement behavior is working.
