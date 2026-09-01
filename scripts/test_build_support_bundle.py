from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from build_support_bundle import build_support_bundle


class BuildSupportBundleTest(unittest.TestCase):
    def test_bundle_aggregates_without_copying_runtime_or_request_content(self) -> None:
        secret = "deployment-business-canary"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdout = root / "server.stdout.log"
            stderr = root / "server.stderr.log"
            access = root / "access.log"
            output = root / "support"
            stdout.write_text(
                json.dumps({"time": "2026-01-01T00:00:00Z", "level": "INFO",
                            "msg": secret, "error": secret}) + "\n" +
                json.dumps({"level": "WARN", "msg": "fixed event"}) + "\n",
                encoding="utf-8",
            )
            stderr.write_bytes(b"")
            access.write_text(f"POST /v1/{secret} 403\n", encoding="utf-8")

            build_support_bundle(stdout, stderr, access, output)

            summary = (output / "summary.json").read_text(encoding="utf-8")
            self.assertNotIn(secret, summary)
            self.assertEqual(
                json.loads(summary),
                {
                    "admin_output_included": False,
                    "http_paths_included": False,
                    "operator_terminal_retention": "external-control-required",
                    "raw_logs_included": False,
                    "request_counts": [{"count": 1, "method": "POST", "status": 403}],
                    "runtime_level_counts": {"INFO": 1, "WARN": 1},
                    "schema": "sevenmirror-support-summary-v1",
                },
            )


if __name__ == "__main__":
    unittest.main()
