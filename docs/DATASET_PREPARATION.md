# Dataset suitability and next preparation steps

## Dataset currently in the project folder

The local file `Unicauca-dataset-April-June-2019-Network-flows.csv` is about 1.28 GB. It has 2,704,839 rows and 50 columns in the copy inspected here. A streaming scan of its `category` column found application/traffic categories such as `Web`, `Network`, `SocialNetwork`, `Chat`, `Media`, `Email`, and `VoIP`.

Those values describe application or traffic types. They do not identify DDoS events, and the file does not provide a confirmed `BENIGN` versus attack target. It is therefore not suitable by itself for supervised DDoS evaluation or for claiming a false-positive rate. It could support application-traffic exploration or, after the dataset's provenance is verified, an explicitly described background-traffic exercise. Do not silently relabel every category as `Normal`.

The file also contains source and destination IP fields. It is excluded from Git by its exact filename pattern in `.gitignore`; keep large or identifying source data out of commits.

## Labeled flow files

The Canadian Institute for Cybersecurity's [CIC-DDoS2019 dataset page](https://www.unb.ca/cic/datasets/ddos-2019.html) describes benign traffic and multiple labeled DDoS attack types, with both flow CSVs and packet captures. The page also requires citing the dataset and its paper when using or redistributing it. This is a closer fit for SentinelShield's evaluation goal than application-type labels.

The supplied CIC-DDoS2019, CIC-IDS2017, and mirrored CSE-CIC-IDS2018 flow CSVs have been evaluated as a separate flow-model experiment. See [ML evaluation](ML_EVALUATION.md) for the measured cross-dataset failures. Flow rows cannot directly train SentinelShield's 21-feature live packet-window model.

## Packet-window preparation from small PCAP samples

The [LUCID DDoS research repository](https://github.com/doriguzzi/lucid-ddos/tree/master/sample-dataset) provides five small CIC-DDoS2019 PCAP excerpts: one labeled benign and four named for attack types. [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html) is the original dataset; cite the dataset authors when using these samples. The five local PCAPs are kept under `data/raw/`, which Git ignores.

Run the converter from the repository root:

```powershell
.\.venv\Scripts\python.exe -m sentinelshield.evaluation.prepare_pcap_windows --capture-dir data/raw --output-csv data/processed/lucid-windows.csv --audit results/lucid-windows-audit.json
```

It uses the same `read_pcap` and `aggregate_windows` functions as SentinelShield's offline/live processing path, so the output CSV has the exact 21 model feature columns, plus a file-level label, capture ID, and window timing. The derived CSV remains local; [the small audit](../results/lucid-windows-audit.json) records hashes, counts, and time coverage without retaining IPs or payloads.

At five-second windows, these samples yielded **567 nonempty windows**: 247 benign, 1 DNS, 1 SYN flood, 159 UDP lag, and 159 WebDDoS. The UDP lag sample has a roughly 28-day gap between portions of its packet timestamps. File-level attack names are coarse labels and may not describe every packet or window. These excerpts cannot support an independent model score: there is only one benign capture, and two attack captures provide just one window each. Do not use a random window split to claim DDoS accuracy on this derived CSV.

## Preparation rules

1. Preserve the original labels and source filenames in a local manifest. Make any mapping into SentinelShield labels explicit and reviewable.
2. Use flow-level data only in its separate flow-model schema. Do not infer packet flags or timing details that a flow file does not contain.
3. For window-level training, use packet captures with explicit capture or time-range labels. Document how mixed windows are labeled or excluded.
4. Split by independent capture/day before fitting. The current packet-window trainer only supports a stratified random row split, so it cannot yet produce leakage-resistant evaluation for correlated windows.
5. Keep the Unicauca application categories separate from DDoS attack labels. They may later help describe benign traffic diversity, but they cannot substitute for labeled attack examples.

The next data requirement is more independently collected benign and attack captures with precise label intervals. The five excerpts establish that the packet-window extraction path works on real PCAPs; they do not establish detection performance.
