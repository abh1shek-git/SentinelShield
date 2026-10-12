"""SentinelShield dashboard for synthetic scenarios and offline PCAP files."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import tempfile

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from scapy.error import Scapy_Exception

from sentinelshield.collection.live import (
    MAX_CAPTURE_SECONDS,
    capture_live_metadata,
    list_capture_interfaces,
)
from sentinelshield.collection.synthetic import make_synthetic_stream
from sentinelshield.detection import DetectionConfig, DetectionResult, RuleBasedDetector
from sentinelshield.evaluation.dataset import generate_synthetic_dataset
from sentinelshield.evaluation.model import TrainingResult, train_classifier
from sentinelshield.processing.traffic import (
    TrafficWindowFeatures,
    aggregate_windows,
    read_pcap,
)
from sentinelshield.storage import SQLiteStore


DATABASE_PATH = Path(
    os.environ.get("SENTINELSHIELD_DATABASE", "data/sentinelshield.sqlite3")
)


@st.cache_resource(show_spinner="Preparing the synthetic-only model demo...")
def get_synthetic_model() -> TrainingResult:
    """Train once per dashboard process; never load an untrusted model file."""
    dataset = generate_synthetic_dataset(samples_per_class=80, random_state=42)
    return train_classifier(dataset, random_state=42)


@st.cache_data(show_spinner="Generating the deterministic demo stream...")
def get_synthetic_features(
    scenario: str, window_count: int, window_seconds: float
) -> tuple[list[TrafficWindowFeatures], list[str]]:
    records = make_synthetic_stream(
        scenario=scenario,
        window_count=window_count,
        window_seconds=window_seconds,
    )
    return aggregate_windows(records, window_seconds), sorted(
        {packet.source_ip for packet in records}
    )


def load_uploaded_capture(payload: bytes, window_seconds: float) -> tuple[
    list[TrafficWindowFeatures], list[str]
]:
    """Parse an uploaded capture from a temporary file, then remove its raw bytes."""
    digest = sha256(payload).hexdigest()[:12]
    source_kind = f"pcap:{digest}"
    extension = ".pcapng" if payload.startswith(b"\x0a\x0d\x0d\x0a") else ".pcap"
    with tempfile.TemporaryDirectory(prefix="sentinelshield-") as temp_directory:
        capture_path = Path(temp_directory) / f"upload{extension}"
        capture_path.write_bytes(payload)
        records = [
            replace(record, source_kind=source_kind)
            for record in read_pcap(capture_path)
        ]
    if not records:
        return [], []
    return aggregate_windows(records, window_seconds), sorted(
        {packet.source_ip for packet in records}
    )


def analyze_windows(
    windows: list[TrafficWindowFeatures], config: DetectionConfig
) -> tuple[list[dict[str, object]], list[DetectionResult]]:
    """Run one fresh, ordered detector pass over the displayed input windows."""
    detector = RuleBasedDetector(config)
    results = [detector.evaluate(window) for window in windows]
    rows: list[dict[str, object]] = []
    for number, (window, result) in enumerate(zip(windows, results), start=1):
        rows.append(
            {
                "window_number": number,
                "window_start": window.window_start,
                "packets_per_second": window.packets_per_second,
                "bytes_per_second": window.bytes_per_second,
                "syn_ratio": window.syn_ratio,
                "initial_syn_pps": result.syn_pps,
                "adaptive_rate_threshold_pps": result.adaptive_threshold_pps,
                "baseline_ready": result.baseline_ready,
                "rule_label": result.label,
                "reasons": " ".join(result.reasons),
                "source_kind": window.source_kind,
            }
        )
    return rows, results


def main() -> None:
    st.set_page_config(
        page_title="SentinelShield | Traffic Monitor",
        page_icon=":material/security:",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    st.title("SentinelShield")
    st.caption("Inspect traffic patterns and see why SentinelShield flags them.")
    source_mode = st.segmented_control(
        "Choose a traffic source",
        ["Try a demo", "Upload a capture", "Capture live traffic"],
        default="Try a demo",
        required=True,
        key="traffic_source_choice",
    )

    with st.sidebar:
        st.header("Advanced settings")
        st.caption("The defaults are starting values, not validated attack thresholds.")
        window_seconds = st.select_slider(
            "Aggregation window",
            options=[1.0, 2.0, 5.0, 10.0],
            value=5.0,
            format_func=lambda value: f"{value:g} seconds",
        )
        minimum_unusual_pps = st.number_input(
            "Unusual traffic floor (PPS)", min_value=1.0, max_value=100_000.0,
            value=100.0, step=10.0,
            help="A high rate alone is labeled Unusual Traffic, never a DDoS verdict.",
        )
        suspicious_syn_ratio = st.slider(
            "Initial SYN ratio", min_value=0.50, max_value=1.00,
            value=0.70, step=0.05,
        )
        minimum_syn_pps = st.number_input(
            "Initial SYN rate floor (PPS)", min_value=0.0, max_value=100_000.0,
            value=20.0, step=5.0,
        )
        show_ml_comparison = st.checkbox(
            "Compare with synthetic-trained ML demo", value=False,
            help="This model was trained only on hand-designed synthetic examples. Its predictions and metrics are not validated on real captures.",
        )

    config = DetectionConfig(
        minimum_unusual_pps=float(minimum_unusual_pps),
        suspicious_syn_ratio=float(suspicious_syn_ratio),
        minimum_syn_pps=float(minimum_syn_pps),
    )

    features: list[TrafficWindowFeatures] = []
    source_ips: list[str] = []
    input_ready = False
    if source_mode == "Try a demo":
        demo_scenario = st.selectbox(
            "Choose a demo traffic pattern",
            ["Mixed demonstration", "Normal only", "SYN-heavy windows"],
            key="demo_scenario",
        )
        scenario = {
            "Mixed demonstration": "mixed",
            "Normal only": "normal",
            "SYN-heavy windows": "syn_surge",
        }[demo_scenario]
        features, source_ips = get_synthetic_features(
            scenario, window_count=30, window_seconds=float(window_seconds)
        )
        input_ready = True
        st.info(
            "Synthetic data is generated locally for demonstration. It is not a replay, "
            "real network observation, or attack benchmark."
        )
    else:
        if source_mode == "Upload a capture":
            uploaded_file = st.file_uploader(
                "Select an authorized PCAP or PCAPNG file",
                type=["pcap", "pcapng"],
                help="The uploaded file is parsed from a temporary file and not copied into the project database.",
                key="pcap_upload",
            )
            if uploaded_file is not None:
                try:
                    features, source_ips = load_uploaded_capture(
                        uploaded_file.getvalue(), float(window_seconds)
                    )
                    input_ready = True
                except (OSError, Scapy_Exception, ValueError) as error:
                    st.error(f"Could not read this capture: {error}")
        else:
            st.warning(
                "Capture only traffic you are authorized to monitor. The capture runs "
                "once for at most 60 seconds and stores packet metadata only."
            )
            authorized = st.checkbox(
                "I am authorized to monitor traffic on the selected interface.",
                key="live_capture_authorized",
            )
            try:
                interfaces = list_capture_interfaces()
            except (OSError, Scapy_Exception, ValueError) as error:
                interfaces = []
                st.error(f"Could not list capture interfaces: {error}")

            if interfaces:
                selected_interface = st.selectbox(
                    "Capture interface", interfaces, key="live_capture_interface"
                )
                duration_seconds = st.select_slider(
                    "Capture duration",
                    options=[5, 10, 20, 30, MAX_CAPTURE_SECONDS],
                    value=10,
                    format_func=lambda value: f"{value} seconds",
                    key="live_capture_duration",
                )
                if st.button(
                    "Start bounded capture",
                    type="primary",
                    disabled=not authorized,
                    key="start_live_capture",
                ):
                    try:
                        with st.spinner(
                            f"Capturing metadata for up to {duration_seconds} seconds..."
                        ):
                            live_records, capture_source = capture_live_metadata(
                                selected_interface, int(duration_seconds)
                            )
                        st.session_state["live_capture_result"] = {
                            "records": live_records,
                            "interface": selected_interface,
                            "duration_seconds": int(duration_seconds),
                            "source_kind": capture_source,
                        }
                    except (OSError, Scapy_Exception, ValueError) as error:
                        st.error(f"Live capture failed: {error}")

                saved_capture = st.session_state.get("live_capture_result")
                if saved_capture:
                    st.caption(
                        f"Showing the last bounded capture from {saved_capture['interface']} "
                        f"({saved_capture['duration_seconds']} seconds max)."
                    )
                    live_records = saved_capture["records"]
                    features = aggregate_windows(live_records, float(window_seconds))
                    source_ips = sorted({record.source_ip for record in live_records})
                    input_ready = True
                else:
                    st.caption("No live capture has been started in this session.")
            else:
                st.info("No capture interfaces were found. Check Npcap and Scapy setup.")

    if not input_ready:
        st.info("Choose a capture file or start a bounded live capture to see results.")
        return
    if not features:
        st.info("No IPv4 or IPv6 packets were found in this input.")
        return

    rows, detections = analyze_windows(features, config)
    frame = pd.DataFrame(rows)
    store = SQLiteStore(DATABASE_PATH)
    for window, result in zip(features, detections):
        store.record_window(window)
        store.record_detection(window, result)

    alert_count = sum(result.is_alert for result in detections)
    potential_count = sum(
        result.label == "Potential DDoS Activity" for result in detections
    )
    if potential_count:
        st.warning(
            f"Potential DDoS pattern in {potential_count} of {len(features)} windows. "
            "Both packet rate and initial TCP SYN activity crossed their rules. "
            "Investigate further; this is not confirmation of an attack."
        )
    elif alert_count:
        st.info(
            f"Unusual activity in {alert_count} of {len(features)} windows. "
            "A packet-rate or initial-SYN rule was triggered. See details for the reasons."
        )
    else:
        st.success(
            f"No rule alerts in these {len(features)} windows. "
            "This does not establish that the traffic is safe."
        )

    with st.container(horizontal=True):
        st.metric("Windows analyzed", f"{len(features):,}", border=True)
        st.metric("Windows flagged", f"{alert_count:,}", border=True)
        st.metric("Packets processed", f"{sum(window.packet_count for window in features):,}", border=True)

    rate_chart = go.Figure()
    rate_chart.add_trace(
        go.Scatter(
            x=frame["window_number"], y=frame["packets_per_second"],
            mode="lines+markers", name="Observed packet rate",
            line={"color": "#43d9c2", "width": 2},
        )
    )
    rate_chart.add_trace(
        go.Scatter(
            x=frame["window_number"], y=frame["adaptive_rate_threshold_pps"],
            mode="lines", name="Current rule threshold",
            line={"color": "#f5a742", "dash": "dash", "width": 2},
        )
    )
    rate_chart.update_layout(
        title="Packet rate over time",
        xaxis_title="Window number (capture order)",
        yaxis_title="Packets per second",
        hovermode="x unified",
        legend={"orientation": "h", "y": 1.12},
        margin={"l": 10, "r": 10, "t": 65, "b": 10},
    )
    st.plotly_chart(
        rate_chart,
        width="stretch",
        alt="Observed packet rate and the current adaptive threshold across traffic windows.",
    )

    with st.expander("See detailed analysis", expanded=False):
        st.caption("This shows the share of initial TCP SYN packets in each window.")
        syn_chart = go.Figure()
        syn_chart.add_trace(
            go.Scatter(
                x=frame["window_number"], y=frame["syn_ratio"],
                mode="lines+markers", name="Initial SYN ratio",
                line={"color": "#b794f6", "width": 2},
            )
        )
        syn_chart.add_hline(
            y=float(suspicious_syn_ratio), line_dash="dash", line_color="#f5a742",
            annotation_text="Configured SYN ratio floor",
        )
        syn_chart.update_layout(
            title="TCP connection-initiation signal",
            xaxis_title="Window number (capture order)",
            yaxis_title="Initial SYN / TCP packets",
            yaxis={"range": [0, 1]},
            hovermode="x unified",
            margin={"l": 10, "r": 10, "t": 65, "b": 10},
        )
        st.plotly_chart(
            syn_chart,
            width="stretch",
            alt="Initial TCP SYN ratio across windows compared with the configured ratio threshold.",
        )

    if show_ml_comparison:
        model_result = get_synthetic_model()
        frame["ml_demo_label"] = [
            model_result.classifier.predict(window) for window in features
        ]
        with st.expander("Synthetic-trained ML comparison", expanded=True):
            st.warning(
                "The classifier and these metrics use hand-designed synthetic data only. "
                "Predictions on uploaded captures are exploratory and are not validated."
            )
            with st.container(horizontal=True):
                st.metric(
                    "Synthetic holdout accuracy",
                    f"{model_result.metrics['accuracy']:.1%}", border=True,
                )
                st.metric(
                    "Weighted precision",
                    f"{model_result.metrics['precision_weighted']:.1%}", border=True,
                )
                st.metric(
                    "Weighted recall",
                    f"{model_result.metrics['recall_weighted']:.1%}", border=True,
                )
                st.metric(
                    "Weighted F1",
                    f"{model_result.metrics['f1_weighted']:.1%}", border=True,
                )
            st.caption(
                f"{model_result.metrics['holdout_samples']} synthetic holdout rows; "
                "these scores are a pipeline check, not measured real-world performance."
            )

    with st.expander("See window decisions and reasons", expanded=False):
        st.subheader("Window decisions")
        display_columns = [
            "window_number", "packets_per_second", "bytes_per_second", "syn_ratio",
            "initial_syn_pps", "adaptive_rate_threshold_pps", "baseline_ready", "rule_label",
        ]
        if show_ml_comparison:
            display_columns.append("ml_demo_label")
        st.dataframe(
            frame[display_columns],
            hide_index=True,
            width="stretch",
            alt="Traffic window rates, TCP SYN signals, baseline status, and rule labels.",
            column_config={
                "window_number": st.column_config.NumberColumn("Window", format="%d"),
                "packets_per_second": st.column_config.NumberColumn("Packets / sec", format="%.1f"),
                "bytes_per_second": st.column_config.NumberColumn("Bytes / sec", format="%.0f"),
                "syn_ratio": st.column_config.NumberColumn("Initial SYN ratio", format="%.1%"),
                "initial_syn_pps": st.column_config.NumberColumn("Initial SYN / sec", format="%.1f"),
                "adaptive_rate_threshold_pps": st.column_config.NumberColumn("Rate threshold", format="%.1f"),
            },
        )

        st.subheader("Detection reasons")
        alert_rows = frame.loc[frame["rule_label"] != "Normal", [
            "window_number", "rule_label", "reasons", "source_kind"
        ]]
        if alert_rows.empty:
            st.caption("No alert events in the current input.")
        else:
            st.dataframe(
                alert_rows,
                hide_index=True,
                width="stretch",
                alt="Current traffic windows that triggered a detection rule and why.",
            )

    with st.expander("Temporary block simulation", expanded=False):
        st.caption("Records an expiring simulated decision. No network or firewall changes occur.")
        if source_ips:
            selected_ip = st.selectbox(
                "Source IP for simulation", source_ips, key="simulation_source_ip"
            )
            ttl_minutes = st.selectbox(
                "Simulation duration", [1, 5, 15, 60], index=1, key="simulation_ttl"
            )
            if st.button(
                "Record simulated block", type="secondary", key="record_simulated_block"
            ):
                store.record_simulated_block(
                    selected_ip,
                    reason="Manually recorded from the SentinelShield dashboard",
                    ttl_seconds=ttl_minutes * 60,
                )
                st.success(f"Recorded {selected_ip} in simulation mode for {ttl_minutes} minutes.")
        else:
            st.caption("No source IPs are available to simulate.")

        active_blocks = store.active_simulated_blocks()
        if active_blocks:
            st.dataframe(
                pd.DataFrame(active_blocks)[["target_ip", "reason", "created_at", "expires_at"]],
                hide_index=True,
                width="stretch",
                alt="IP addresses recorded in simulation mode with their reason and expiry time.",
            )
        else:
            st.caption("No active simulated entries.")

    with st.expander("Recent stored alerts", expanded=False):
        stored_alerts = store.list_detection_events(limit=10)
        if stored_alerts:
            st.dataframe(
                pd.DataFrame(stored_alerts)[["label", "window_start", "reasons", "created_at"]],
                hide_index=True,
                width="stretch",
                alt="Recent alert labels, window times, and detection reasons saved in SQLite.",
            )
        else:
            st.caption("Alerts will appear here after a rule is triggered.")

    st.caption(
        f"Input kind: {features[0].source_kind}. Stored locally in `{DATABASE_PATH}`. "
        "A laptop capture only sees traffic visible to that host/interface."
    )


if __name__ == "__main__":
    main()
