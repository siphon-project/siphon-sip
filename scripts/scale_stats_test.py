#!/usr/bin/env python3
"""Exercise the scale harness's actual result collector without placing calls."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class ScaleStatsTest(unittest.TestCase):
    def test_fractional_periodic_rates_do_not_abort_successful_results(self):
        script = Path(__file__).with_name("scale_test.sh").read_text()
        collector = script.split("TOTAL_SUCCESS=0\n", 1)[1]
        collector = "TOTAL_SUCCESS=0\n" + collector.split("# Aggregate peak", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            for index, rate in enumerate(("250.499", "250.501"), start=1):
                columns = ["0"] * 70
                columns[6] = rate
                columns[15] = "1250"
                csv = Path(directory) / f"sipp_uac_{index}.csv"
                csv.write_text("header\n" + ";".join(columns) + "\n")
            result = subprocess.run(
                ["bash", "-eu", "-o", "pipefail", "-c",
                 collector.replace("/tmp/", directory + "/")],
                env={**os.environ, "NUM_UACS": "2", "RT_LABEL": "invite_rt"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertIn("UAC 1: success=1250 failed=0 peak=250 cps", result.stdout)
            self.assertIn("UAC 2: success=1250 failed=0 peak=251 cps", result.stdout)
            self.assertEqual(len(list(Path(directory).glob("*.last.csv"))), 2)


if __name__ == "__main__":
    unittest.main()
