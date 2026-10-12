# SentinelShield: start here

This is the shortest way to see the working prototype. You do not need to download another dataset for this demonstration.

## 1. Open the dashboard

In PowerShell, from `D:\Project\DDOS project`, run:

```powershell
.\.venv\Scripts\python.exe -m streamlit run sentinelshield/dashboard/app.py
```

Open the local address Streamlit prints, usually `http://localhost:8501`.

## 2. Try three traffic patterns

Keep **Try a demo** selected at the top of the page. Under **Choose a demo traffic pattern**, select each of these in turn:

1. **Normal only** — the baseline example.
2. **Mixed demonstration** — normal and unusual windows together.
3. **SYN-heavy windows** — windows with many TCP connection attempts.

Watch the result message, **Windows flagged**, and the packet-rate chart. Open **See detailed analysis** and **See window decisions and reasons** when you want to inspect the SYN signal and each rule decision. The dashboard updates when you change the pattern; there is no separate Run button.

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

- **Upload a capture** lets you inspect an authorized PCAP or PCAPNG file. Start with a small file; the dashboard loads the upload into memory.
- **Advanced settings** in the sidebar include the optional synthetic-trained ML comparison. Its scores come from generated examples and do not measure real-world accuracy.
- **Capture live traffic** is a separate, bounded feature that still requires an authorization checkbox and a button click. See [live capture instructions](docs/LIVE_CAPTURE.md) before using it.

The next research step is collecting enough independently labeled packet captures to evaluate the live-compatible features. The current real-data model has weak results on a different dataset and is not used for dashboard predictions. Details are in [ML evaluation](docs/ML_EVALUATION.md).
