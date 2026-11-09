#!/usr/bin/env python3
"""Black-box checks for the build-time OTA public-key verifier."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


class OtaSignerVerifyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.signer = pathlib.Path(sys.argv[1]).resolve(strict=True)

    def run_signer(self, *arguments: object, success: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [str(self.signer), *(str(argument) for argument in arguments)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if success and result.returncode != 0:
            self.fail(f"ota_signer unexpectedly failed: {result.stderr}")
        if not success and result.returncode == 0:
            self.fail("ota_signer unexpectedly accepted corrupted evidence")
        return result

    def signed_inputs(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        seed = root / "test-seed.bin"
        seed.write_bytes(bytes(range(32)))
        image = root / "image.zbi"
        image.write_bytes(b"bounded deterministic test image")
        public_key = root / "public-key.bin"
        manifest = root / "manifest.json"
        self.run_signer("pubkey", "--seed", seed, "--out", public_key)
        self.run_signer(
            "sign",
            "--seed",
            seed,
            "--image",
            image,
            "--version",
            9,
            "--out",
            manifest,
        )
        return image, manifest, public_key

    def verify(
        self,
        image: pathlib.Path,
        manifest: pathlib.Path,
        public_key: pathlib.Path,
        *,
        success: bool,
    ) -> subprocess.CompletedProcess:
        return self.run_signer(
            "verify",
            "--pubkey",
            public_key,
            "--manifest",
            manifest,
            "--image",
            image,
            success=success,
        )

    def test_genuine_manifest_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            image, manifest, public_key = self.signed_inputs(pathlib.Path(directory))
            result = self.verify(image, manifest, public_key, success=True)
            self.assertIn("status=verified", result.stdout)
            self.assertNotIn("bounded deterministic test image", result.stdout + result.stderr)

    def test_corrupted_signature_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            image, manifest, public_key = self.signed_inputs(pathlib.Path(directory))
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["signature"] = ("0" if value["signature"][0] != "0" else "1") + value[
                "signature"
            ][1:]
            manifest.write_text(json.dumps(value), encoding="utf-8")
            self.verify(image, manifest, public_key, success=False)

    def test_wrong_public_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image, manifest, public_key = self.signed_inputs(root)
            other_seed = root / "other-seed.bin"
            other_seed.write_bytes(bytes(reversed(range(32))))
            self.run_signer("pubkey", "--seed", other_seed, "--out", public_key)
            self.verify(image, manifest, public_key, success=False)

    def test_each_signed_message_field_is_rejected_when_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image, manifest, public_key = self.signed_inputs(root)
            original = json.loads(manifest.read_text(encoding="utf-8"))
            mutations = {
                "version": original["version"] + 1,
                "sha256": "0" * 64,
                "size": original["size"] + 1,
            }
            for field, replacement in mutations.items():
                with self.subTest(field=field):
                    changed = dict(original)
                    changed[field] = replacement
                    manifest.write_text(json.dumps(changed), encoding="utf-8")
                    self.verify(image, manifest, public_key, success=False)

    def test_image_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            image, manifest, public_key = self.signed_inputs(pathlib.Path(directory))
            image.write_bytes(b"same manifest, substituted image")
            self.verify(image, manifest, public_key, success=False)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
