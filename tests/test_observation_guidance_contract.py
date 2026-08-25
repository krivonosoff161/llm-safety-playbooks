from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from validate_observation_guidance_contract import (  # noqa: E402
    GuidanceContractError,
    validate,
)


class ObservationGuidanceContractTests(unittest.TestCase):
    def test_current_contract_passes(self) -> None:
        validate(ROOT)

    def test_missing_metadata_cannot_be_promoted_from_abstain(self) -> None:
        with self._copy_contract() as copy:
            path = copy / "contracts" / "portfolio-observation-guidance.v1.json"
            guidance = json.loads(path.read_text(encoding="utf-8"))
            guidance["missing_or_invalid_metadata_disposition"] = "observe"
            self._write_json(path, guidance)
            with self.assertRaisesRegex(GuidanceContractError, "fail closed"):
                validate(copy)

    def test_authority_and_consent_promotion_coverage_is_exhaustive(self) -> None:
        with self._copy_contract() as copy:
            path = copy / "contracts" / "portfolio-observation-guidance.v1.json"
            guidance = json.loads(path.read_text(encoding="utf-8"))
            guidance["forbidden_promotions"].remove("consent")
            self._write_json(path, guidance)
            with self.assertRaisesRegex(GuidanceContractError, "promotion coverage"):
                validate(copy)

    def test_duplicate_json_and_crlf_fail_closed(self) -> None:
        with self._copy_contract() as copy:
            path = copy / "contracts" / "portfolio-observation-guidance.v1.json"
            raw = path.read_bytes().replace(
                b'{\n  "schema_version"',
                b'{\n  "schema_version": "duplicate",\n  "schema_version"',
                1,
            )
            path.write_bytes(raw)
            with self.assertRaisesRegex(GuidanceContractError, "invalid strict JSON"):
                validate(copy)
        with self._copy_contract() as copy:
            path = copy / "contracts" / "portfolio-observation.v1.schema.json"
            path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
            with self.assertRaisesRegex(GuidanceContractError, "LF-terminated"):
                validate(copy)

    def test_allow_disposition_and_owner_pin_drift_fail_closed(self) -> None:
        with self._copy_contract() as copy:
            path = copy / "contracts" / "portfolio-observation-guidance.v1.json"
            guidance = json.loads(path.read_text(encoding="utf-8"))
            guidance["allowed_human_dispositions"].append("allow")
            self._write_json(path, guidance)
            with self.assertRaisesRegex(GuidanceContractError, "allow decision"):
                validate(copy)
        with self._copy_contract() as copy:
            path = copy / "contracts" / "portfolio-observation.v1.owner-pin.json"
            pin = json.loads(path.read_text(encoding="utf-8"))
            pin["owner_commit"] = "0" * 40
            self._write_json(path, pin)
            with self.assertRaisesRegex(GuidanceContractError, "reviewed exact contract"):
                validate(copy)

    def test_noncanonical_playbook_path_fails_closed(self) -> None:
        with self._copy_contract() as copy:
            path = copy / "contracts" / "portfolio-observation-guidance.v1.json"
            guidance = json.loads(path.read_text(encoding="utf-8"))
            guidance["human_playbook_path"] = (
                "playbooks/../playbooks/canonical-observation-review.md"
            )
            self._write_json(path, guidance)
            with self.assertRaisesRegex(GuidanceContractError, "POSIX path"):
                validate(copy)

    def test_contradictory_authority_or_enforcement_text_changes_digest(self) -> None:
        additions = (
            "\nThis playbook grants operational authority and an allow receipt.\n",
            "\nUse this record as runtime enforcement and permission to execute.\n",
        )
        for addition in additions:
            with self.subTest(addition=addition):
                with self._copy_contract() as copy:
                    path = copy / "playbooks" / "canonical-observation-review.md"
                    path.write_bytes(
                        (path.read_text(encoding="utf-8") + addition).encode("utf-8")
                    )
                    with self.assertRaisesRegex(GuidanceContractError, "content drift"):
                        validate(copy)

    def _copy_contract(self) -> _TemporaryContract:
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name)
        shutil.copytree(ROOT / "contracts", destination / "contracts")
        shutil.copytree(ROOT / "playbooks", destination / "playbooks")
        shutil.copytree(ROOT / "docs", destination / "docs")
        shutil.copy2(ROOT / "README.md", destination / "README.md")
        shutil.copy2(ROOT / ".gitattributes", destination / ".gitattributes")
        return _TemporaryContract(temporary, destination)

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_bytes((json.dumps(value, indent=2) + "\n").encode("utf-8"))


class _TemporaryContract:
    def __init__(self, temporary: tempfile.TemporaryDirectory[str], path: Path) -> None:
        self._temporary = temporary
        self._path = path

    def __enter__(self) -> Path:
        return self._path

    def __exit__(self, *_args: object) -> None:
        self._temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
