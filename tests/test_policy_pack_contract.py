from __future__ import annotations

import ast
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import policy_pack  # noqa: E402
from policy_pack import (  # noqa: E402
    PolicyPackContractError,
    build_policy_input_v1,
    decode_policy_input_v1,
    decode_policy_output_v1,
    encode_policy_input_v1,
    evaluate_policy_input_v1,
    validate_repository,
    verify_policy_evaluation_pair_v1,
)


class PolicyPackContractTests(unittest.TestCase):
    def test_current_generated_contract_passes(self) -> None:
        validate_repository(ROOT)

    def test_canonical_input_and_output_are_deterministic_and_content_free(self) -> None:
        raw_canary = "SYNTHETIC_RAW_SECRET_CONTENT_CANARY"
        signals = self._signals()
        signals["untrusted_instructions_detected"] = "present"
        input_receipt = build_policy_input_v1(
            subject_sha256=hashlib.sha256(raw_canary.encode("utf-8")).hexdigest(),
            source_class="synthetic_fixture",
            signals=signals,
        )
        input_bytes = encode_policy_input_v1(input_receipt)
        output_bytes = evaluate_policy_input_v1(input_bytes)

        self.assertEqual(decode_policy_input_v1(input_bytes), input_receipt)
        self.assertEqual(evaluate_policy_input_v1(input_bytes), output_bytes)
        output = decode_policy_output_v1(output_bytes)
        self.assertEqual(verify_policy_evaluation_pair_v1(input_bytes, output_bytes), output)
        self.assertEqual(output["input_receipt_id"], input_receipt["input_receipt_id"])
        self.assertEqual(output["overall_advisory_disposition"], "challenge")
        self.assertEqual(output["summary"]["signal_count"], len(policy_pack.SIGNALS))
        self.assertEqual(output["summary"]["present"], 1)
        self.assertEqual(output["summary"]["observe"], len(policy_pack.SIGNALS) - 1)
        self.assertNotIn(raw_canary.encode("utf-8"), input_bytes)
        self.assertNotIn(raw_canary.encode("utf-8"), output_bytes)

    def test_unknown_and_present_signals_fail_closed_to_advisory_abstain(self) -> None:
        signals = self._signals()
        signals["secret_exposure_risk"] = "present"
        signals["git_change_control_unclear"] = "unknown"
        input_bytes = self._input_bytes(signals)
        output = decode_policy_output_v1(evaluate_policy_input_v1(input_bytes))

        self.assertEqual(output["overall_advisory_disposition"], "abstain")
        self.assertEqual(output["summary"]["present"], 1)
        self.assertEqual(output["summary"]["unknown"], 1)
        self.assertEqual(output["summary"]["abstain"], 1)
        self.assertEqual(output["summary"]["escalate"], 1)
        self.assertNotIn("allow", policy_pack.DISPOSITIONS)
        self.assertNotIn(
            "allow",
            {result["advisory_disposition"] for result in output["results"]},
        )
        for result in output["results"]:
            self.assertIs(result["may_authorize_effects"], False)
            self.assertEqual(result["operational_authority"], "none")

    def test_input_rejects_duplicate_unknown_noncanonical_and_raw_content_fields(self) -> None:
        canonical = self._input_bytes(self._signals())
        duplicate = canonical.replace(
            b'{"digest_is_authentication"',
            b'{"digest_is_authentication":false,"digest_is_authentication"',
            1,
        )
        with self.assertRaisesRegex(PolicyPackContractError, "strict UTF-8 JSON"):
            decode_policy_input_v1(duplicate)

        with self.assertRaisesRegex(PolicyPackContractError, "canonical"):
            decode_policy_input_v1(canonical.replace(b":", b": ", 1))
        with self.assertRaisesRegex(PolicyPackContractError, "canonical"):
            decode_policy_input_v1(canonical.replace(b"\n", b"\r\n"))

        for forbidden in ("raw_content", "prompt", "secret", "model_output"):
            payload = json.loads(canonical)
            payload[forbidden] = "SYNTHETIC_CANARY"
            with self.subTest(forbidden=forbidden):
                with self.assertRaisesRegex(PolicyPackContractError, "fields"):
                    decode_policy_input_v1(self._canonical(payload))

    def test_input_rejects_missing_signals_authority_and_pack_rebinding(self) -> None:
        payload = json.loads(self._input_bytes(self._signals()))
        payload["signals"].pop("secret_exposure_risk")
        payload["input_receipt_id"] = policy_pack._identity(policy_pack.INPUT_DOMAIN, payload)
        with self.assertRaisesRegex(PolicyPackContractError, "exhaustive"):
            decode_policy_input_v1(self._canonical(payload))

        for field, value, message in (
            ("raw_content_included", True, "raw content"),
            ("digest_is_authentication", True, "authenticate"),
            ("may_authorize_effects", True, "authorize effects"),
            ("operational_authority", "execute", "no operational authority"),
        ):
            payload = json.loads(self._input_bytes(self._signals()))
            payload[field] = value
            payload["input_receipt_id"] = policy_pack._identity(policy_pack.INPUT_DOMAIN, payload)
            with self.subTest(field=field):
                with self.assertRaisesRegex(PolicyPackContractError, message):
                    decode_policy_input_v1(self._canonical(payload))

        payload = json.loads(self._input_bytes(self._signals()))
        payload["pack_sha256"] = "0" * 64
        payload["input_receipt_id"] = policy_pack._identity(policy_pack.INPUT_DOMAIN, payload)
        rebound = self._canonical(payload)
        self.assertEqual(decode_policy_input_v1(rebound)["pack_sha256"], "0" * 64)
        with self.assertRaisesRegex(PolicyPackContractError, "current pack"):
            evaluate_policy_input_v1(rebound)

    def test_input_rejects_oversized_and_pathologically_nested_json(self) -> None:
        with self.assertRaisesRegex(PolicyPackContractError, "byte size"):
            decode_policy_input_v1(b"{" + b"x" * policy_pack.MAX_INPUT_BYTES + b"}\n")
        nested = b'{"value":' + (b"[" * 2000) + b"0" + (b"]" * 2000) + b"}\n"
        with self.assertRaisesRegex(PolicyPackContractError, "nesting depth"):
            decode_policy_input_v1(nested)

    def test_output_rejects_identity_summary_and_authority_tampering(self) -> None:
        output_bytes = evaluate_policy_input_v1(self._input_bytes(self._signals()))
        for mutation, message in (
            (lambda value: value.__setitem__("receipt_id", "0" * 64), "identity"),
            (lambda value: value["summary"].__setitem__("observe", 0), "summary"),
            (lambda value: value.__setitem__("may_authorize_effects", True), "authorize"),
            (lambda value: value["results"][0].__setitem__("operational_authority", "execute"), "authority"),
        ):
            payload = json.loads(output_bytes)
            mutation(payload)
            with self.subTest(message=message):
                with self.assertRaises(PolicyPackContractError):
                    decode_policy_output_v1(self._canonical(payload))

    def test_pair_verifier_rejects_a_valid_receipt_from_another_input(self) -> None:
        first = self._input_bytes(self._signals())
        second_signals = self._signals()
        second_signals["handoff_verification_incomplete"] = "present"
        second = self._input_bytes(second_signals)
        output = evaluate_policy_input_v1(first)

        with self.assertRaisesRegex(PolicyPackContractError, "pair does not match"):
            verify_policy_evaluation_pair_v1(second, output)

    def test_pack_and_schema_are_closed_and_have_no_allow_or_enforcement_authority(self) -> None:
        pack = json.loads((ROOT / policy_pack.PACK_PATH).read_bytes())
        input_schema = json.loads((ROOT / policy_pack.INPUT_SCHEMA_PATH).read_bytes())
        output_schema = json.loads((ROOT / policy_pack.OUTPUT_SCHEMA_PATH).read_bytes())

        self.assertEqual(pack["policy_mode"], "deterministic_offline_advisory_only")
        self.assertEqual(
            pack["playbook_digest_semantics"],
            "sha256_lf_normalized_text_v1",
        )
        self.assertEqual(pack["allowed_dispositions"], list(policy_pack.DISPOSITIONS))
        self.assertNotIn("allow", pack["allowed_dispositions"])
        self.assertIs(pack["may_authorize_effects"], False)
        self.assertEqual(pack["operational_authority"], "none")
        self.assertEqual([rule["signal"] for rule in pack["rules"]], list(policy_pack.SIGNALS))
        for schema in (input_schema, output_schema):
            self.assertIs(schema["additionalProperties"], False)
            self.assertEqual(schema["properties"]["operational_authority"], {"const": "none"})
            self.assertEqual(schema["properties"]["may_authorize_effects"], {"const": False})
        self.assertEqual(
            json.loads((ROOT / policy_pack.PACK_SCHEMA_PATH).read_bytes())["properties"]["rules"],
            {"const": pack["rules"]},
        )
        result_schemas = output_schema["properties"]["results"]["prefixItems"]
        self.assertEqual(
            [item["properties"]["signal"]["const"] for item in result_schemas],
            list(policy_pack.SIGNALS),
        )

    def test_source_playbook_and_generated_pack_drift_fail_closed(self) -> None:
        with self._copy_contract() as copy:
            path = copy / "playbooks" / "secret-handling.md"
            path.write_bytes(
                (
                    path.read_text(encoding="utf-8")
                    + "\nSynthetic drift.\n"
                ).encode("utf-8")
            )
            with self.assertRaisesRegex(PolicyPackContractError, "artifact drift"):
                validate_repository(copy)

        with self._copy_contract() as copy:
            path = copy / policy_pack.PACK_PATH
            pack = json.loads(path.read_bytes())
            pack["policy_mode"] = "runtime_enforcement"
            path.write_bytes(self._canonical(pack))
            with self.assertRaisesRegex(PolicyPackContractError, "artifact drift"):
                validate_repository(copy)

    def test_generated_synthetic_fixture_and_cli_evaluation(self) -> None:
        fixture = ROOT / policy_pack.FIXTURE_PATH
        expected = evaluate_policy_input_v1(fixture.read_bytes())
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "policy_pack.py"), "evaluate", str(fixture)],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
        self.assertEqual(completed.stdout, expected)
        self.assertEqual(completed.stderr, b"")

    def test_cli_failure_is_sanitized_and_runtime_has_no_effect_imports(self) -> None:
        payload = json.loads(self._input_bytes(self._signals()))
        payload["raw_content"] = "SYNTHETIC_PRIVATE_CANARY"
        with tempfile.TemporaryDirectory() as temporary:
            invalid = Path(temporary) / "invalid.json"
            invalid.write_bytes(self._canonical(payload))
            completed = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "policy_pack.py"), "evaluate", str(invalid)],
                cwd=ROOT,
                check=False,
                capture_output=True,
            )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, b"")
        self.assertNotIn(b"SYNTHETIC_PRIVATE_CANARY", completed.stderr)

        tree = ast.parse((ROOT / "tools" / "policy_pack.py").read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imported.isdisjoint(
                {"socket", "ssl", "http", "urllib", "requests", "subprocess", "asyncio"}
            )
        )

    def _input_bytes(self, signals: dict[str, str]) -> bytes:
        return encode_policy_input_v1(
            build_policy_input_v1(
                subject_sha256="b" * 64,
                source_class="synthetic_fixture",
                signals=signals,
            )
        )

    @staticmethod
    def _signals() -> dict[str, str]:
        return {signal: "absent" for signal in policy_pack.SIGNALS}

    @staticmethod
    def _canonical(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"

    def _copy_contract(self) -> _TemporaryContract:
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name)
        for relative in policy_pack.BOUND_FILES:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        for relative in policy_pack.expected_artifacts(ROOT):
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        return _TemporaryContract(temporary, destination)


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
