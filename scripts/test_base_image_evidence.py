#!/usr/bin/env python3
"""Focused tests for base_image_evidence.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("base_image_evidence.py")
SPEC = importlib.util.spec_from_file_location("base_image_evidence", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load base_image_evidence.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BaseImageEvidenceTest(unittest.TestCase):
    def test_dockerfile_images_requires_exact_digest_pins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dockerfile = Path(directory) / "Dockerfile"
            dockerfile.write_text(
                "FROM --platform=$BUILDPLATFORM example.test/build:1@sha256:"
                + "1" * 64
                + " AS build\n"
                + "FROM example.test/runtime:2@sha256:"
                + "2" * 64
                + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                MODULE.dockerfile_images(dockerfile),
                [
                    {
                        "role": "build",
                        "reference": "example.test/build:1@sha256:" + "1" * 64,
                    },
                    {
                        "role": "runtime",
                        "reference": "example.test/runtime:2@sha256:" + "2" * 64,
                    },
                ],
            )
            dockerfile.write_text("FROM example.test/runtime:latest\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "sha256 digest"):
                MODULE.dockerfile_images(dockerfile)

    def test_builder_output_controls_fail_closed_on_boundary_changes(self) -> None:
        valid = (
            "FROM --platform=$BUILDPLATFORM example.test/build:1@sha256:"
            + "1" * 64
            + " AS build\n"
            + "RUN test -n \"$SOURCE_REVISION\" \\\n"
            + "    && CGO_ENABLED=0 GOOS=\"$TARGETOS\" GOARCH=\"$TARGETARCH\" go build -trimpath -o /out/server ./cmd/server \\\n"
            + "    && CGO_ENABLED=0 GOOS=\"$TARGETOS\" GOARCH=\"$TARGETARCH\" go build -trimpath -o /out/admin ./cmd/admin \\\n"
            + "    && mkdir /out/data\n"
            + "FROM gcr.io/distroless/static-debian12:nonroot@sha256:"
            + "2" * 64
            + "\n"
            + "COPY --chown=nonroot:nonroot --from=build /out /app\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            dockerfile = Path(directory) / "Dockerfile"
            dockerfile.write_text(valid, encoding="utf-8")
            self.assertEqual(
                MODULE.builder_output_controls(dockerfile),
                {
                    "advisory": "CVE-2026-14456",
                    "build_commands": ["./cmd/server", "./cmd/admin"],
                    "cgo_enabled": False,
                    "copied_builder_path": "/out",
                    "runtime_path": "/app",
                    "runtime_type": "distroless-static",
                },
            )

            for changed, message in (
                (valid.replace("CGO_ENABLED=0", "CGO_ENABLED=1", 1), "CGO boundary"),
                (valid.replace("mkdir /out/data", "cp /usr/bin/openssl /out/openssl && mkdir /out/data"),
                 "undeclared producer"),
                (valid.replace("distroless/static-debian12", "distroless/base-debian12"),
                 "distroless static"),
            ):
                dockerfile.write_text(changed, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, message):
                    MODULE.builder_output_controls(dockerfile)

    def test_vulnerability_summary_preserves_inventory_and_blocks_high(self) -> None:
        report = {
            "Results": [
                {
                    "Packages": [{"Name": "base-files"}, {"Name": "libc6"}],
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2099-1000",
                            "Severity": "MEDIUM",
                            "PkgIdentifier": {"PURL": "pkg:deb/debian/base-files@1"},
                        },
                        {
                            "VulnerabilityID": "CVE-2099-2000",
                            "Severity": "HIGH",
                            "PkgIdentifier": {"PURL": "pkg:deb/debian/libc6@2"},
                        },
                    ],
                },
            ],
        }
        summary = MODULE.vulnerability_summary(report, {})
        self.assertEqual(summary["applied_exceptions"], [])
        self.assertFalse(MODULE.release_blocking("build", summary))
        self.assertTrue(MODULE.release_blocking("runtime", summary))
        self.assertEqual(summary["package_count"], 2)
        self.assertEqual(summary["finding_count"], 2)
        self.assertEqual(
            summary["severity_counts"],
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0},
        )
        self.assertEqual(
            summary["blocking_findings"],
            [
                {
                    "purl": "pkg:deb/debian/libc6@2",
                    "severity": "HIGH",
                    "vulnerability_id": "CVE-2099-2000",
                },
            ],
        )
        accepted = MODULE.vulnerability_summary(
            report,
            {("pkg:deb/debian/libc6@2", "CVE-2099-2000"): "VE-2099-001"},
        )
        self.assertEqual(accepted["blocking_findings"], [])
        self.assertEqual(
            accepted["applied_exceptions"],
            [
                {
                    "exception_id": "VE-2099-001",
                    "purl": "pkg:deb/debian/libc6@2",
                    "vulnerability_id": "CVE-2099-2000",
                },
            ],
        )
        self.assertEqual(accepted["severity_counts"]["HIGH"], 1)

    def test_database_timestamp_must_be_current_at_observation(self) -> None:
        MODULE.require_fresh_database("2099-01-07T00:00:00Z", "2099-01-08T00:00:00Z")
        with self.assertRaisesRegex(RuntimeError, "freshness window"):
            MODULE.require_fresh_database("2098-12-31T23:59:59Z", "2099-01-08T00:00:00Z")
        with self.assertRaisesRegex(RuntimeError, "freshness window"):
            MODULE.require_fresh_database("2099-01-08T00:05:01Z", "2099-01-08T00:00:00Z")

    def test_vulnerability_identity_requires_exact_purl(self) -> None:
        report = {
            "Results": [
                {
                    "Packages": [],
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2099-3000", "Severity": "HIGH"},
                    ],
                },
            ],
        }
        with self.assertRaisesRegex(RuntimeError, "identity is incomplete"):
            MODULE.vulnerability_summary(report, {})


if __name__ == "__main__":
    unittest.main()
