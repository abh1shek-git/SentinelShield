# SentinelShield: start here

This is the shortest way to see the working prototype. You do not need to download another dataset for this demonstration.

## 1. Open the dashboard

In PowerShell, from `D:\Project\DDOS project`, run:

```powershell
.\.venv\Scripts\python.exe -m streamlit run sentinelshield/dashboard/app.py
```

Open the local address Streamlit prints, usually `http://localhost:8501`.

## 2. Try three traffic patterns

In the left sidebar, keep **Synthetic demonstration** selected. Under **Synthetic traffic pattern**, select each of these in turn:

1. **Normal only** — the baseline example.
2. **Mixed demonstration** — normal and unusual windows together.
3. **SYN-heavy windows** — windows with many TCP connection attempts.

Watch **Alerts / potential events**, the two charts, **Window decisions**, and **Detection reasons**. The dashboard updates when you change the pattern; there is no separate Run button.

## 3. Read the result

SentinelShield groups packets into short time windows. It measures packet rate and the share of initial TCP SYN packets, then applies explainable rules:

| Dashboard label | Meaning |
| --- | --- |
| Normal | No configured rule condition was met. |
| Unusual Traffic | Packet rate crossed the current rule threshold. |
| Suspicious TCP SYN Pattern | SYN ratio and SYN rate crossed their thresholds. |
| Potential DDoS Activity | Both the rate and SYN rules were met. This is a signal to investigate, not proof of an attack. |

**What to say in a demo:** “This prototype turns packet metadata into time-window measurements and explains why it flags unusual traffic. These three examples are generated locally. We have not established reliable real-world detection accuracy yet.”

## After the basic demo

- **Offline PCAP / PCAPNG** lets you inspect a capture you are authorized to use. Start with a small file; the dashboard loads the upload into memory.
- **Compare with synthetic-trained ML demo** shows that the ML code runs. Its scores come from generated examples and do not measure real-world accuracy.
- **Live capture (opt-in)** is a separate, bounded feature. See [live capture instructions](docs/LIVE_CAPTURE.md) before using it.

The next research step is collecting enough independently labeled packet captures to evaluate the live-compatible features. The current real-data model has weak results on a different dataset and is not used for dashboard predictions. Details are in [ML evaluation](docs/ML_EVALUATION.md).
