from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from build_container_artifacts import REPOSITORY, build, verify

REVISION = "4" * 40


def canonical_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def descriptor(content: bytes, media_type: str) -> dict[str, object]:
    return {
        "mediaType": media_type,
        "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
        "size": len(content),
    }


def write_oci_archive(path: Path, architecture: str) -> None:
    layer = f"independent {architecture} layer fixture".encode("ascii")
    config = canonical_json({
        "architecture": architecture,
        "os": "linux",
        "config": {
            "User": "nonroot:nonroot",
            "Entrypoint": ["/app/server"],
            "Labels": {
                "org.opencontainers.image.source": REPOSITORY,
                "org.opencontainers.image.revision": REVISION,
            },
        },
    })
    config_descriptor = descriptor(config, "application/vnd.oci.image.config.v1+json")
    layer_descriptor = descriptor(layer, "application/vnd.oci.image.layer.v1.tar")
    manifest = canonical_json({
        "schemaVersion": 2,
        "config": config_descriptor,
        "layers": [layer_descriptor],
    })
    manifest_descriptor = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
    index = canonical_json({"schemaVersion": 2, "manifests": [manifest_descriptor]})
    files = {
        "oci-layout": canonical_json({"imageLayoutVersion": "1.0.0"}),
        "index.json": index,
        f"blobs/sha256/{config_descriptor['digest'].split(':')[1]}": config,
        f"blobs/sha256/{layer_descriptor['digest'].split(':')[1]}": layer,
        f"blobs/sha256/{manifest_descriptor['digest'].split(':')[1]}": manifest,
    }
    with tarfile.open(path, "w") as archive:
        for name, content in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))


class ContainerArtifactTest(unittest.TestCase):
    def test_oci_identity_verifies_and_rejects_archive_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = {}
            for architecture in ("amd64", "arm64"):
                archive = root / f"{architecture}.tar"
                write_oci_archive(archive, architecture)
                archives[architecture] = archive
            output = root / "release"
            build(archives, output, REVISION)
            verify(output, REVISION)

            target = output / "sevenmirror-server-linux-amd64.oci.tar"
            target.write_bytes(target.read_bytes() + b"tampered")
            with self.assertRaisesRegex(RuntimeError, "field archive_sha256 is invalid"):
                verify(output, REVISION)


if __name__ == "__main__":
    unittest.main()
