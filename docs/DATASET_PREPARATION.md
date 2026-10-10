# Dataset suitability and next preparation steps

## Dataset currently in the project folder

The local file `Unicauca-dataset-April-June-2019-Network-flows.csv` is about 1.28 GB. It has 2,704,839 rows and 50 columns in the copy inspected here. A streaming scan of its `category` column found application/traffic categories such as `Web`, `Network`, `SocialNetwork`, `Chat`, `Media`, `Email`, and `VoIP`.

Those values describe application or traffic types. They do not identify DDoS events, and the file does not provide a confirmed `BENIGN` versus attack target. It is therefore not suitable by itself for supervised DDoS evaluation or for claiming a false-positive rate. It could support application-traffic exploration or, after the dataset's provenance is verified, an explicitly described background-traffic exercise. Do not silently relabel every category as `Normal`.

The file also contains source and destination IP fields. It is excluded from Git by its exact filename pattern in `.gitignore`; keep large or identifying source data out of commits.

## Recommended labeled source for DDoS evaluation

The Canadian Institute for Cybersecurity's [CIC-DDoS2019 dataset page](https://www.unb.ca/cic/datasets/ddos-2019.html) describes benign traffic and multiple labeled DDoS attack types, with both flow CSVs and packet captures. The page also requires citing the dataset and its paper when using or redistributing it. This is a closer fit for SentinelShield's evaluation goal than application-type labels.

Before using it, select a manageable subset and record the source files, capture day, labels, and any filtering. Keep source archives local and ignored by Git. Prefer processing in chunks or streaming; do not load all CSVs into a single in-memory dataframe.

## Preparation rules

1. Preserve the original labels and source filenames in a local manifest. Make any mapping into SentinelShield labels explicit and reviewable.
2. Use flow-level data only when its fields can be mapped consistently to the current feature schema. Do not infer packet flags or timing details that a flow file does not contain.
3. For window-level training, group flows by timestamp into fixed windows and define the target rule in advance. For example, a window containing any attack-labeled flow could be assigned an attack label, but this changes the evaluation question and must be reported.
4. Split by capture/day or another independent group before fitting. The current trainer only supports a stratified random row split, so it cannot yet produce leakage-resistant evaluation for correlated windows.
5. Keep the Unicauca application categories separate from DDoS attack labels. They may later help describe benign traffic diversity, but they cannot substitute for labeled attack examples.

No real-world metrics have been produced from the local file. The next code step is a streaming adapter for the selected attack-labeled source, after confirming which source files are available and which labels/feature fields they contain.
