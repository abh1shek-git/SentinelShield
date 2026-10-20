# Demonstration guide

## Start the dashboard

From the repository root, install the project dependencies if needed, then run:

```powershell
.\.venv\Scripts\python.exe -m streamlit run sentinelshield/dashboard/app.py
```

The dashboard starts in synthetic demonstration mode. It does not start live capture automatically.

## Suggested walkthrough

1. Leave **Try a demo** selected and review the result message and packet-rate chart. Open **See detailed analysis** and **See window decisions and reasons** for the initial-SYN chart, rule labels, and detector reasons.
2. Try **Mixed demonstration**, **Normal only**, and **SYN-heavy windows** under **Choose a demo traffic pattern**. The generated stream is deterministic and explicitly marked synthetic.
3. Open the sidebar **Advanced settings** and turn on **Compare with synthetic-trained ML demo** only to demonstrate that the training/inference path works. Its scores are based on hand-designed synthetic data and are not evidence of real network performance.
4. If you have an authorized capture file, choose **Upload a capture** and upload a PCAP or PCAPNG file. The file is parsed from a temporary directory; capture payloads are not saved in the project database.
5. For an authorized local interface, follow [live capture instructions](LIVE_CAPTURE.md). A capture requires the explicit authorization checkbox and button click.
6. Optionally open **Temporary block simulation** and select an IP. This adds a simulated database record with an expiry; it does not change the firewall.

## Interpreting results

- `Unusual Traffic` means the packet rate exceeded the configured rule threshold.
- `Suspicious TCP SYN Pattern` means the SYN ratio and SYN rate rules passed.
- `Potential DDoS Activity` means both rules passed. It is a cautious indicator, not confirmation of an attack.
- Adjusting sensitivity changes rule decisions. Defaults have not been calibrated on a measured labeled dataset.
- A host capture sees only traffic visible to the selected host/interface; it is not automatically a network-wide sensor.

## What this demonstration does not establish

The synthetic stream is not a replay of an attack, and the synthetic ML holdout is not a benchmark. Do not report its perfect scores as expected real-world performance. A research evaluation needs independently labeled benign and controlled test captures, a documented labeling method, and a split that prevents related windows from leaking across train and test sets. The separate capture-aware evaluator enforces whole-capture holdout, but the current PCAP excerpts do not provide enough independently labeled benign captures for a valid score. The general-purpose trainer still uses a stratified random row split and is unsuitable for a capture-level performance claim.

For a faculty or technical review, use the shorter [review brief](REVIEW_BRIEF.md), which includes the actual dataset decisions and measured ML limitations.
