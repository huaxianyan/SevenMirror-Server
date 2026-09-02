from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from validate_registry_release_ledger import SCHEMA, validate_ledger


def candidate() -> dict[str, object]:
    return {
        "archive_reference": None,
        "decision_actors": [],
        "decision_reference": None,
        "decided_at": None,
        "index_digest": "sha256:" + "1" * 64,
        "platforms": [
            {"architecture": "amd64", "manifest_digest": "sha256:" + "2" * 64},
            {"architecture": "arm64", "manifest_digest": "sha256:" + "3" * 64},
        ],
        "publication_run":
            "https://github.com/huaxianyan/SevenMirror-Server/actions/runs/123456",
        "published_at": "2026-09-02T00:00:00Z",
        "registry_availability": "expected",
        "replacement_index_digest": None,
        "source_revision": "4" * 40,
        "state": "candidate",
    }


class RegistryReleaseLedgerTest(unittest.TestCase):
    def write(self, path: Path, entries: list[dict[str, object]]) -> None:
        path.write_text(
            json.dumps({
                "entries": entries,
                "registry_repository": "ghcr.io/huaxianyan/sevenmirror-server",
                "schema": SCHEMA,
            }),
            encoding="utf-8",
        )

    def test_candidate_passes_and_invalid_decisions_or_removal_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.json"
            self.write(path, [candidate()])
            self.assertEqual(validate_ledger(path), 1)

            approved = copy.deepcopy(candidate())
            approved.update({
                "decided_at": "2026-09-03T00:00:00Z",
                "decision_actors": ["@only-reviewer"],
                "decision_reference": "review/123",
                "state": "approved",
            })
            self.write(path, [approved])
            with self.assertRaisesRegex(RuntimeError, "independent retained decision"):
                validate_ledger(path)

            revoked = copy.deepcopy(candidate())
            revoked.update({
                "decided_at": "2026-09-03T00:00:00Z",
                "decision_actors": ["@incident-owner"],
                "decision_reference": "incident/123",
                "registry_availability": "removed",
                "state": "revoked",
            })
            self.write(path, [revoked])
            with self.assertRaisesRegex(RuntimeError, "preserved evidence"):
                validate_ledger(path)

            revoked["registry_availability"] = "expected"
            self.write(path, [revoked])
            with self.assertRaisesRegex(RuntimeError, "cannot be republished"):
                validate_ledger(path, publication_revision="4" * 40)


if __name__ == "__main__":
    unittest.main()
