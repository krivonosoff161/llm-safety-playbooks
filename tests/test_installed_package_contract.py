from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from llm_safety_playbooks import (  # noqa: E402
    POLICY_PACK_ARTIFACT_SHA256,
    policy_pack_artifact_sha256,
    policy_pack_bytes,
)


class InstalledPackageContractTests(unittest.TestCase):
    def test_packaged_policy_pack_is_the_exact_source_artifact(self) -> None:
        expected = (ROOT / "contracts" / "policy-pack.v1.json").read_bytes()
        self.assertEqual(policy_pack_bytes(), expected)
        self.assertEqual(hashlib.sha256(expected).hexdigest(), POLICY_PACK_ARTIFACT_SHA256)
        self.assertEqual(policy_pack_artifact_sha256(), POLICY_PACK_ARTIFACT_SHA256)

    def test_package_surface_has_no_automatic_loading_or_effect_authority(self) -> None:
        source = (ROOT / "src" / "llm_safety_playbooks" / "__init__.py").read_text(
            encoding="utf-8"
        )
        forbidden = ("entry_points(", "import_module(", "subprocess", "socket", "urlopen(")
        self.assertTrue(all(token not in source for token in forbidden))
