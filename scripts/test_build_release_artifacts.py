from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from build_release_artifacts import artifact_name, artifact_plan, verify


class ReleaseArtifactManifestTest(unittest.TestCase):
    def test_release_inventory_contains_every_command_of_the_component(self) -> None:
        self.assertEqual(artifact_plan("server"), (
            ("server", "linux", "amd64"),
            ("admin", "linux", "amd64"),
            ("server", "linux", "arm64"),
            ("admin", "linux", "arm64"),
        ))
        self.assertEqual(artifact_plan("admin"), (
            ("admin-web", "linux", "amd64"),
            ("admin-web", "linux", "arm64"),
        ))

    def test_exact_manifest_rejects_target_metadata_and_binary_tampering(self) -> None:
        revision = "1" * 40
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release"
            output.mkdir()
            records = []
            for command, goos, goarch in artifact_plan("server"):
                name = artifact_name(command, goos, goarch)
                content = f"fixture:{name}".encode("ascii")
                (output / name).write_bytes(content)
                records.append({
                    "name": name,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                    "command": command,
                    "goos": goos,
                    "goarch": goarch,
                })
            records.sort(key=lambda record: record["name"])
            manifest = {
                "schema": "sevenmirror-component-release-v1",
                "component": "server",
                "source_repository": "https://github.com/huaxianyan/SevenMirror-Server",
                "source_revision": revision,
                "protocol_version": "fixture",
                "go_version": "fixture",
                "artifacts": records,
            }
            manifest_path = output / "release-manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (output / "SHA256SUMS").write_text(
                "".join(f"{record['sha256']}  {record['name']}\n" for record in records),
                encoding="ascii",
            )

            verify(output, revision, "server")
            records[0]["command"] = "admin-web"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "artifact binding is invalid"):
                verify(output, revision, "server")
            records[0]["command"] = "admin"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (output / records[0]["name"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "does not match its manifest"):
                verify(output, revision, "server")


if __name__ == "__main__":
    unittest.main()
