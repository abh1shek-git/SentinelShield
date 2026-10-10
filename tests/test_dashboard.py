"""Headless smoke tests for the Streamlit dashboard."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from sentinelshield.storage import SQLiteStore


APP_PATH = Path(__file__).parents[1] / "sentinelshield" / "dashboard" / "app.py"


class DashboardTests(unittest.TestCase):
    def test_default_dashboard_renders_synthetic_demo(self):
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            database = str(Path(directory) / "dashboard.sqlite3")
            with patch.dict(os.environ, {"SENTINELSHIELD_DATABASE": database}):
                app = AppTest.from_file(str(APP_PATH)).run(timeout=60)

            self.assertEqual(app.exception, [])
            self.assertEqual(len(app.get("plotly_chart")), 2)
            self.assertTrue(any("Synthetic data is generated locally" in x.value for x in app.info))
            self.assertEqual(len(SQLiteStore(database).list_traffic_windows()), 30)

    def test_offline_mode_without_upload_prompts_for_input(self):
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            database = str(Path(directory) / "dashboard.sqlite3")
            with patch.dict(os.environ, {"SENTINELSHIELD_DATABASE": database}):
                app = AppTest.from_file(str(APP_PATH)).run(timeout=60)
                app.radio(key="source_mode").set_value("Offline PCAP / PCAPNG").run(timeout=60)

            self.assertEqual(app.exception, [])
            self.assertTrue(any("Choose a traffic source" in x.value for x in app.warning))
            self.assertEqual(SQLiteStore(database).list_traffic_windows(), [])

    def test_simulation_button_records_only_simulated_block(self):
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            database = str(Path(directory) / "dashboard.sqlite3")
            with patch.dict(os.environ, {"SENTINELSHIELD_DATABASE": database}):
                app = AppTest.from_file(str(APP_PATH)).run(timeout=60)
                app.button(key="record_simulated_block").click().run(timeout=60)

            self.assertEqual(app.exception, [])
            blocks = SQLiteStore(database).active_simulated_blocks()
            self.assertEqual(len(blocks), 1)
            self.assertEqual(blocks[0]["mode"], "simulation")


if __name__ == "__main__":
    unittest.main()
