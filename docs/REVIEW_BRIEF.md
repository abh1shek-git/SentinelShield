# SentinelShield review brief

## One-minute explanation

SentinelShield is a local, research-oriented DDoS monitoring prototype. It reads authorized offline captures or an explicitly started, bounded live capture; extracts packet metadata into five-second windows; applies explainable packet-rate and TCP SYN rules; and shows the decisions in a Streamlit dashboard. It stores aggregate results and supports a temporary **simulation-only** blocklist. A Random Forest training path exists, but no real-data model has yet met the evidence needed for live use.

The safe claim is **working monitoring and evaluation prototype**, not proven DDoS protection. A high packet rate or SYN ratio is an investigation signal, not proof of an attack.

## What to demonstrate in five minutes

1. From the repository root, run `.\.venv\Scripts\python.exe -m streamlit run sentinelshield/dashboard/app.py` in PowerShell.
2. In **Try a demo**, select **Normal only**, **Mixed demonstration**, and **SYN-heavy windows**. Explain that these are generated locally and labeled synthetic.
3. Open **See detailed analysis** and **See window decisions and reasons**. Point to packet rate, SYN signal, and the rule reason for each window.
4. Show **Temporary block simulation**. Explain that an entry expires in SQLite and no firewall rule is changed.
5. If time permits, show the [dataset audit](../results/review-dataset-audit.json) and the measured [flow-model evaluation](../results/cic-flow-baseline.json). State clearly that the real-data model is not used by the dashboard.

Do not upload the 8.3 GB Thursday capture into the dashboard: the upload path holds uploaded bytes in memory. Live capture is optional and requires an authorized interface and working Npcap. The synthetic demonstration works without either.

## Architecture to explain

```text
Authorized PCAP / opt-in live capture / synthetic demo
                    |
                    v
          Packet metadata extraction
                    |
                    v
        Five-second feature windows
                    |
                    v
       Explainable detection rules
                    |
                    v
        Dashboard + SQLite alerts
                    |
                    v
       Simulated temporary blocks
```

The offline flow-model experiments use CICFlowMeter CSV features in a **separate** pipeline. Those feature columns are not interchangeable with the dashboard's packet-window features.

## Dataset decisions

| Local data | Role | Review conclusion |
| --- | --- | --- |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Labeled [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) flow statistics | Relevant and already evaluated. Its SHA-256, row count, and labels match the existing evaluation report. It is a CSV, not a raw PCAP. |
| `all-xena-pcap/` | 25 very small packet examples | 98 packets total, including 72 IP packets; 18 files contain one packet. Useful for showing parsing, not for measuring DDoS detection or training ML. Original provenance is unverified. |
| Five LUCID CIC-DDoS2019 PCAP excerpts | Packet-window extraction examples | Useful for pipeline checks; only one benign capture, so no independent benign holdout. |
| `Thursday-WorkingHours.pcap` | Large mixed CIC-IDS2017 capture | A bounded early interval was extracted. Its benign label is provisional; the whole day is not benign or DDoS. |

The reproducible local audit is [here](../results/review-dataset-audit.json). Run it again with:

```powershell
.\.venv\Scripts\python.exe -m sentinelshield.evaluation.audit_review_datasets --flow-csv Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --pcap-dir all-xena-pcap --existing-flow-report results/cic-flow-baseline.json --output results/review-dataset-audit.json
```

## Measured ML results and honest interpretation

The synthetic four-class training example exercises the code path only; its perfect score is **not** real-world accuracy.

The separate flow model trained on the supplied CIC-DDoS2019 CSV and was evaluated on the Friday CIC-IDS2017 CSV. Its DDoS recall was **36.4%**, with a **24.8%** benign false-alarm rate. A second model trained using the earlier flow sources detected only **26 of 687,742** labeled DDoS flows in a held-out 2018 file (**0.0038% recall**). These poor transfer results are informative: the source datasets have different traffic/feature distributions. They are why no real-data model is connected to live decisions. See [ML evaluation](ML_EVALUATION.md) for preprocessing, confusion matrices, and limitations.

## Likely review questions

**Where is the machine learning?** A scikit-learn Random Forest is trained from labeled features in the evaluation pipeline. The dashboard's optional comparison uses synthetic examples only. The real-data flow model remains separate because its external results are weak.

**Why use rules too?** They are interpretable and provide a cautious baseline while the ML model is being evaluated. The rate baseline adapts from windows treated as normal; an alert explains which condition fired.

**Does it stop an attack?** No. It records a temporary simulated block decision. Real firewall enforcement would need isolated-lab validation and is outside this prototype's demonstrated scope.

**What is the main limitation?** There is not yet a trustworthy, independently held-out packet-window benchmark across enough labeled benign and DDoS captures. The project therefore cannot claim reliable real-world DDoS detection accuracy.

**Why not use the Xena files for training?** Most contain only one packet. A flood is a sustained traffic pattern measured over time, and filename labels alone do not create independent ground truth.

## Project status

The code, dashboard, data preparation, audit trail, and safe demonstration are ready to present as a **prototype**. The remaining research work is to verify label/clock alignment, collect more independent captures, evaluate capture-held-out packet windows, and calibrate or redesign the model before any deployment claim.
