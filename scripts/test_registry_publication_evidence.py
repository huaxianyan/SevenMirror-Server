#!/usr/bin/env python3
"""Focused tests for registry_publication_evidence.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("registry_publication_evidence.py")
SPEC = importlib.util.spec_from_file_location("registry_publication_evidence", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load registry_publication_evidence.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

REVISION = "7" * 40


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def descriptor(content: bytes, media_type: str) -> dict[str, object]:
    return {
        "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
        "mediaType": media_type,
        "size": len(content),
    }


def write_blob(layout: Path, content: bytes) -> str:
    digest = hashlib.sha256(content).hexdigest()
    target = layout / "blobs" / "sha256" / digest
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return f"sha256:{digest}"


def write_pulled_layout(root: Path) -> tuple[list[dict[str, object]], str]:
    root.mkdir()
    (root / "oci-layout").write_bytes(encoded({"imageLayoutVersion": "1.0.0"}))
    records: list[dict[str, object]] = []
    platform_descriptors = []
    for architecture in ("amd64", "arm64"):
        layer = f"independent {architecture} registry layer".encode("ascii")
        layer_descriptor = descriptor(layer, "application/vnd.oci.image.layer.v1.tar")
        write_blob(root, layer)
        config = encoded({
            "architecture": architecture,
            "os": "linux",
            "config": {
                "User": "nonroot:nonroot",
                "Entrypoint": ["/app/server"],
                "Labels": {"org.opencontainers.image.revision": REVISION},
            },
        })
        config_descriptor = descriptor(config, "application/vnd.oci.image.config.v1+json")
        write_blob(root, config)
        image_manifest = encoded({
            "schemaVersion": 2,
            "config": config_descriptor,
            "layers": [layer_descriptor],
        })
        image_descriptor = descriptor(
            image_manifest, "application/vnd.oci.image.manifest.v1+json",
        )
        write_blob(root, image_manifest)
        image_descriptor["platform"] = {"architecture": architecture, "os": "linux"}
        platform_descriptors.append(image_descriptor)
        records.append({
            "architecture": architecture,
            "config_digest": config_descriptor["digest"],
            "layer_count": 1,
            "manifest_digest": image_descriptor["digest"],
        })
    registry_index = encoded({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": platform_descriptors,
    })
    index_descriptor = descriptor(registry_index, "application/vnd.oci.image.index.v1+json")
    index_digest = write_blob(root, registry_index)
    (root / "index.json").write_bytes(encoded({
        "schemaVersion": 2,
        "manifests": [index_descriptor],
    }))
    return records, index_digest


class RegistryPublicationEvidenceTest(unittest.TestCase):
    def test_pulled_registry_graph_preserves_both_platforms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = Path(directory) / "pulled"
            records, expected_digest = write_pulled_layout(layout)
            actual_digest, index_content = MODULE.inspect_pulled_layout(
                layout, records, REVISION,
            )
            self.assertEqual(actual_digest, expected_digest)
            self.assertEqual(
                hashlib.sha256(index_content).hexdigest(),
                expected_digest.removeprefix("sha256:"),
            )

    def test_pulled_registry_graph_rejects_platform_digest_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = Path(directory) / "pulled"
            records, _ = write_pulled_layout(layout)
            records[1]["manifest_digest"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(RuntimeError, "platform binding"):
                MODULE.inspect_pulled_layout(layout, records, REVISION)

    def test_pulled_registry_graph_rejects_unreferenced_blob(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = Path(directory) / "pulled"
            records, _ = write_pulled_layout(layout)
            write_blob(layout, b"unreferenced registry content")
            with self.assertRaisesRegex(RuntimeError, "unreferenced graph"):
                MODULE.inspect_pulled_layout(layout, records, REVISION)


if __name__ == "__main__":
    unittest.main()
