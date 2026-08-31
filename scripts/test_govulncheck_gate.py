from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from govulncheck_gate import run_gate

REVISION = "5" * 40
OBSERVED = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)


def result(database_time: str, finding: str = "") -> subprocess.CompletedProcess[str]:
    messages: list[dict[str, object]] = [{
        "config": {
            "scanner_name": "govulncheck",
            "scanner_version": "v1.1.4",
            "db": "https://vuln.go.dev",
            "db_last_modified": database_time,
            "go_version": "go1.25.13",
            "scan_level": "symbol",
            "scan_mode": "source",
        },
    }, {"SBOM": {"modules": []}}]
    if finding:
        trace = [{"module": "example/module", "version": "v1.0.0"}]
        if finding == "reachable":
            trace.append({"module": "example/module", "package": "example/module/pkg", "function": "Open"})
        messages.append({"finding": {"osv": "GO-2026-0001", "trace": trace}})
    return subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout="\n".join(json.dumps(message) for message in messages), stderr="",
    )


class GovulncheckGateTest(unittest.TestCase):
    @patch("govulncheck_gate.subprocess.check_output", return_value="go1.25.13\n")
    @patch("govulncheck_gate.subprocess.run")
    def test_fresh_zero_finding_evidence_passes_and_stale_database_fails(
        self, run: Mock, _go_version: Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence.json"
            run.return_value = result("2026-08-28T14:47:45Z", "informational")
            evidence = run_gate(output, REVISION, OBSERVED)
            self.assertEqual(evidence["reachable_finding_count"], 0)
            self.assertEqual(evidence["informational_finding_ids"], ["GO-2026-0001"])
            self.assertEqual(evidence["database_last_modified"], "2026-08-28T14:47:45Z")

            run.return_value = result("2026-08-28T14:47:45Z", "reachable")
            with self.assertRaisesRegex(RuntimeError, "reachable findings"):
                run_gate(Path(temporary) / "reachable.json", REVISION, OBSERVED)

            run.return_value = result("2026-08-01T00:00:00Z")
            with self.assertRaisesRegex(RuntimeError, "stale or future-dated"):
                run_gate(Path(temporary) / "stale.json", REVISION, OBSERVED)


if __name__ == "__main__":
    unittest.main()
