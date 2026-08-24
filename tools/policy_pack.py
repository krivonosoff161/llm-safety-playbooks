"""Closed deterministic policy-pack V1 for offline advisory evaluation.

The evaluator consumes only a canonical, content-free signal receipt. It does not
inspect subject content, call providers, execute playbook text, or enforce effects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Optional


ROOT = Path(__file__).resolve().parents[1]

PACK_VERSION = "llm-safety-policy-pack-v1.0"
INPUT_VERSION = "llm-safety-policy-input-receipt-v1.0"
OUTPUT_VERSION = "llm-safety-policy-evaluation-receipt-v1.0"
MANIFEST_VERSION = "llm-safety-policy-pack-manifest-v1.0"
PACK_ID = "llm-safety-playbooks-core"
POLICY_MODE = "deterministic_offline_advisory_only"
VERDICT_SEMANTICS = "advisory_only_no_allow_or_enforcement"
PLAYBOOK_DIGEST_SEMANTICS = "sha256_lf_normalized_text_v1"
PACK_DOMAIN = b"llm-safety-playbooks/policy-pack/v1\0"
INPUT_DOMAIN = b"llm-safety-playbooks/policy-input/v1\0"
OUTPUT_DOMAIN = b"llm-safety-playbooks/policy-output/v1\0"
INPUT_BYTES_DOMAIN = b"llm-safety-playbooks/policy-input-bytes/v1\0"
MAX_INPUT_BYTES = 16_384
MAX_OUTPUT_BYTES = 65_536
MAX_JSON_DEPTH = 64
SHA256_HEX_LENGTH = 64

DISPOSITIONS = ("observe", "challenge", "escalate", "abstain")
SIGNAL_STATES = ("absent", "present", "unknown")
SOURCE_CLASSES = ("synthetic_fixture", "sanitized_metadata", "external_adapter_receipt")
DISPOSITION_RANK = {value: index for index, value in enumerate(DISPOSITIONS)}

RULE_SPECS = (
    {
        "rule_id": "untrusted-instructions-v1",
        "signal": "untrusted_instructions_detected",
        "playbook_path": "playbooks/data-vs-instructions.md",
        "present_disposition": "challenge",
        "unknown_disposition": "challenge",
    },
    {
        "rule_id": "secret-exposure-v1",
        "signal": "secret_exposure_risk",
        "playbook_path": "playbooks/secret-handling.md",
        "present_disposition": "abstain",
        "unknown_disposition": "abstain",
    },
    {
        "rule_id": "generated-resource-v1",
        "signal": "generated_resource_unverified",
        "playbook_path": "playbooks/generated-resource-check.md",
        "present_disposition": "challenge",
        "unknown_disposition": "challenge",
    },
    {
        "rule_id": "git-change-control-v1",
        "signal": "git_change_control_unclear",
        "playbook_path": "playbooks/git-agent-safety.md",
        "present_disposition": "escalate",
        "unknown_disposition": "escalate",
    },
    {
        "rule_id": "handoff-verification-v1",
        "signal": "handoff_verification_incomplete",
        "playbook_path": "playbooks/handoff-verification.md",
        "present_disposition": "challenge",
        "unknown_disposition": "challenge",
    },
    {
        "rule_id": "research-authorization-v1",
        "signal": "research_authorization_unclear",
        "playbook_path": "playbooks/safe-research-scope.md",
        "present_disposition": "abstain",
        "unknown_disposition": "abstain",
    },
    {
        "rule_id": "observation-metadata-v1",
        "signal": "observation_metadata_invalid",
        "playbook_path": "playbooks/canonical-observation-review.md",
        "present_disposition": "abstain",
        "unknown_disposition": "abstain",
    },
)
SIGNALS = tuple(rule["signal"] for rule in RULE_SPECS)

PACK_PATH = Path("contracts/policy-pack.v1.json")
PACK_SCHEMA_PATH = Path("contracts/policy-pack.v1.schema.json")
INPUT_SCHEMA_PATH = Path("contracts/policy-input-receipt.v1.schema.json")
OUTPUT_SCHEMA_PATH = Path("contracts/policy-evaluation-receipt.v1.schema.json")
MANIFEST_PATH = Path("contracts/policy-pack.v1.manifest.json")
FIXTURE_PATH = Path("tests/fixtures/policy-pack-v1/valid/mixed-signals.json")
BOUND_FILES = (
    Path("AGENTS.md"),
    Path("README.md"),
    Path("component.yaml"),
    Path("docs/component-roadmap.md"),
    Path("docs/coverage-map.md"),
    Path("docs/policy-pack-v1.md"),
    Path("playbooks/data-vs-instructions.md"),
    Path("playbooks/secret-handling.md"),
    Path("playbooks/generated-resource-check.md"),
    Path("playbooks/git-agent-safety.md"),
    Path("playbooks/handoff-verification.md"),
    Path("playbooks/safe-research-scope.md"),
    Path("playbooks/canonical-observation-review.md"),
    Path("tests/test_ecosystem_component_contract.py"),
    Path("tests/test_observation_guidance_contract.py"),
    Path("tests/test_policy_pack_contract.py"),
    Path("tools/policy_pack.py"),
    Path(".github/workflows/roadmap.yml"),
    Path(".gitattributes"),
)


class PolicyPackContractError(ValueError):
    """Raised when canonical policy-pack bytes violate the closed V1 contract."""


def build_policy_input_v1(
    *,
    subject_sha256: str,
    source_class: str,
    signals: Mapping[str, str],
    root: Path = ROOT,
) -> dict[str, Any]:
    """Build a content-free canonical input receipt for advisory evaluation."""

    pack = _policy_pack(root.resolve())
    payload: dict[str, Any] = {
        "schema_version": INPUT_VERSION,
        "pack_sha256": pack["pack_sha256"],
        "subject_sha256": subject_sha256,
        "subject_digest_semantics": "caller_supplied_sanitized_subject_commitment",
        "source_class": source_class,
        "signals": dict(signals),
        "raw_content_included": False,
        "digest_is_authentication": False,
        "may_authorize_effects": False,
        "operational_authority": "none",
    }
    payload["input_receipt_id"] = _identity(INPUT_DOMAIN, payload)
    _validate_input(payload)
    return payload


def encode_policy_input_v1(value: Mapping[str, Any]) -> bytes:
    payload = dict(value)
    _validate_input(payload)
    encoded = _canonical_json(payload) + b"\n"
    if len(encoded) > MAX_INPUT_BYTES:
        raise PolicyPackContractError("policy input exceeds the V1 byte limit")
    return encoded


def decode_policy_input_v1(raw: bytes) -> dict[str, Any]:
    payload = _decode_canonical(raw, MAX_INPUT_BYTES, "policy input")
    _validate_input(payload)
    return payload


def evaluate_policy_input_v1(raw: bytes, *, root: Path = ROOT) -> bytes:
    """Evaluate one canonical input into an authority-free canonical receipt."""

    root = root.resolve()
    validate_repository(root)
    input_receipt = decode_policy_input_v1(raw)
    pack = _policy_pack(root)
    if input_receipt["pack_sha256"] != pack["pack_sha256"]:
        raise PolicyPackContractError("policy input does not bind the current pack")

    rules_by_signal = {rule["signal"]: rule for rule in pack["rules"]}
    results = []
    for signal in SIGNALS:
        state = input_receipt["signals"][signal]
        rule = rules_by_signal[signal]
        disposition = (
            "observe" if state == "absent" else rule[f"{state}_disposition"]
        )
        reason_code = f"policy.{rule['rule_id']}.{state}"
        results.append(
            {
                "rule_id": rule["rule_id"],
                "signal": signal,
                "signal_state": state,
                "matched": state != "absent",
                "advisory_disposition": disposition,
                "reason_codes": [reason_code],
                "playbook_path": rule["playbook_path"],
                "playbook_sha256": rule["playbook_sha256"],
                "may_authorize_effects": False,
                "operational_authority": "none",
            }
        )

    counts = {state: 0 for state in SIGNAL_STATES}
    disposition_counts = {value: 0 for value in DISPOSITIONS}
    for result in results:
        counts[result["signal_state"]] += 1
        disposition_counts[result["advisory_disposition"]] += 1
    overall = max(
        (result["advisory_disposition"] for result in results),
        key=DISPOSITION_RANK.__getitem__,
    )
    payload: dict[str, Any] = {
        "schema_version": OUTPUT_VERSION,
        "input_receipt_id": input_receipt["input_receipt_id"],
        "input_sha256": _sha256(INPUT_BYTES_DOMAIN + raw),
        "pack_sha256": pack["pack_sha256"],
        "results": results,
        "summary": {
            "signal_count": len(SIGNALS),
            "absent": counts["absent"],
            "present": counts["present"],
            "unknown": counts["unknown"],
            "observe": disposition_counts["observe"],
            "challenge": disposition_counts["challenge"],
            "escalate": disposition_counts["escalate"],
            "abstain": disposition_counts["abstain"],
        },
        "overall_advisory_disposition": overall,
        "verdict_semantics": VERDICT_SEMANTICS,
        "may_authorize_effects": False,
        "operational_authority": "none",
    }
    payload["receipt_id"] = _identity(OUTPUT_DOMAIN, payload)
    _validate_output(payload, pack)
    encoded = _canonical_json(payload) + b"\n"
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise PolicyPackContractError("policy output exceeds the V1 byte limit")
    return encoded


def decode_policy_output_v1(raw: bytes, *, root: Path = ROOT) -> dict[str, Any]:
    payload = _decode_canonical(raw, MAX_OUTPUT_BYTES, "policy output")
    _validate_output(payload, _policy_pack(root.resolve()))
    return payload


def verify_policy_evaluation_pair_v1(
    input_raw: bytes,
    output_raw: bytes,
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Verify that output is the exact deterministic receipt for these input bytes."""

    decode_policy_input_v1(input_raw)
    output = decode_policy_output_v1(output_raw, root=root)
    expected = evaluate_policy_input_v1(input_raw, root=root)
    if output_raw != expected:
        raise PolicyPackContractError("policy input/output receipt pair does not match")
    return output


def expected_artifacts(root: Path = ROOT) -> dict[Path, bytes]:
    root = root.resolve()
    pack = _policy_pack(root)
    fixture = build_policy_input_v1(
        subject_sha256="a" * 64,
        source_class="synthetic_fixture",
        signals={
            "untrusted_instructions_detected": "present",
            "secret_exposure_risk": "absent",
            "generated_resource_unverified": "unknown",
            "git_change_control_unclear": "absent",
            "handoff_verification_incomplete": "present",
            "research_authorization_unclear": "absent",
            "observation_metadata_invalid": "absent",
        },
        root=root,
    )
    artifacts = {
        PACK_PATH: _canonical_json(pack) + b"\n",
        PACK_SCHEMA_PATH: _pretty_json(_pack_schema(pack)),
        INPUT_SCHEMA_PATH: _pretty_json(_input_schema()),
        OUTPUT_SCHEMA_PATH: _pretty_json(_output_schema(pack)),
        FIXTURE_PATH: encode_policy_input_v1(fixture),
    }
    manifest = {
        "schema_version": MANIFEST_VERSION,
        "pack_id": PACK_ID,
        "pack_sha256": pack["pack_sha256"],
        "canonicalization": "utf8-json-sort-keys-compact-lf-v1",
        "artifacts": {
            path.as_posix(): _sha256(payload)
            for path, payload in sorted(artifacts.items(), key=lambda item: item[0].as_posix())
        },
        "bound_files": {
            path.as_posix(): _lf_normalized_sha256(root / path)
            for path in BOUND_FILES
        },
        "verdict_semantics": VERDICT_SEMANTICS,
        "may_authorize_effects": False,
        "operational_authority": "none",
    }
    artifacts[MANIFEST_PATH] = _pretty_json(manifest)
    return artifacts


def generate(root: Path = ROOT) -> None:
    root = root.resolve()
    for relative, payload in expected_artifacts(root).items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)


def validate_repository(root: Path = ROOT) -> None:
    root = root.resolve()
    for relative, expected in expected_artifacts(root).items():
        target = root / relative
        if not target.is_file() or target.is_symlink() or target.read_bytes() != expected:
            raise PolicyPackContractError(f"generated policy-pack artifact drift: {relative.as_posix()}")
    pack = _decode_canonical((root / PACK_PATH).read_bytes(), MAX_OUTPUT_BYTES, "policy pack")
    _validate_pack(pack, root)


def _policy_pack(root: Path) -> dict[str, Any]:
    rules = []
    for spec in RULE_SPECS:
        playbook = _repo_file(root, spec["playbook_path"])
        rules.append(
            {
                "rule_id": spec["rule_id"],
                "signal": spec["signal"],
                "playbook_path": spec["playbook_path"],
                "playbook_sha256": _sha256(_lf_bytes(playbook)),
                "absent_disposition": "observe",
                "present_disposition": spec["present_disposition"],
                "unknown_disposition": spec["unknown_disposition"],
                "may_authorize_effects": False,
                "operational_authority": "none",
            }
        )
    payload: dict[str, Any] = {
        "schema_version": PACK_VERSION,
        "pack_id": PACK_ID,
        "policy_mode": POLICY_MODE,
        "playbook_digest_semantics": PLAYBOOK_DIGEST_SEMANTICS,
        "rules": rules,
        "allowed_dispositions": list(DISPOSITIONS),
        "verdict_semantics": VERDICT_SEMANTICS,
        "may_authorize_effects": False,
        "operational_authority": "none",
    }
    payload["pack_sha256"] = _identity(PACK_DOMAIN, payload)
    return payload


def _validate_pack(pack: dict[str, Any], root: Path) -> None:
    fields = {
        "schema_version", "pack_id", "pack_sha256", "policy_mode",
        "playbook_digest_semantics", "rules",
        "allowed_dispositions", "verdict_semantics", "may_authorize_effects",
        "operational_authority",
    }
    _require_fields(pack, fields, "policy pack")
    if pack["schema_version"] != PACK_VERSION or pack["pack_id"] != PACK_ID:
        raise PolicyPackContractError("unsupported policy pack identity")
    if pack["policy_mode"] != POLICY_MODE:
        raise PolicyPackContractError("policy pack mode is not advisory-only")
    if pack["playbook_digest_semantics"] != PLAYBOOK_DIGEST_SEMANTICS:
        raise PolicyPackContractError("policy pack playbook digest semantics drift")
    if pack["allowed_dispositions"] != list(DISPOSITIONS) or "allow" in pack["allowed_dispositions"]:
        raise PolicyPackContractError("policy pack disposition universe drift")
    if pack["verdict_semantics"] != VERDICT_SEMANTICS:
        raise PolicyPackContractError("policy pack verdict semantics drift")
    _require_no_authority(pack, "policy pack")
    rules = pack["rules"]
    if type(rules) is not list or len(rules) != len(RULE_SPECS):
        raise PolicyPackContractError("policy pack rule count drift")
    expected = _policy_pack(root)
    if pack != expected:
        raise PolicyPackContractError("policy pack differs from source-owned rules")
    if pack["pack_sha256"] != _identity(PACK_DOMAIN, pack):
        raise PolicyPackContractError("policy pack identity drift")


def _validate_input(payload: dict[str, Any]) -> None:
    fields = {
        "schema_version", "input_receipt_id", "pack_sha256", "subject_sha256",
        "subject_digest_semantics", "source_class", "signals", "raw_content_included",
        "digest_is_authentication", "may_authorize_effects", "operational_authority",
    }
    _require_fields(payload, fields, "policy input")
    if payload["schema_version"] != INPUT_VERSION:
        raise PolicyPackContractError("unsupported policy input version")
    for name in ("input_receipt_id", "pack_sha256", "subject_sha256"):
        _require_digest(payload[name], name)
    if payload["subject_digest_semantics"] != "caller_supplied_sanitized_subject_commitment":
        raise PolicyPackContractError("subject digest semantics drift")
    if payload["source_class"] not in SOURCE_CLASSES:
        raise PolicyPackContractError("unsupported policy input source class")
    signals = payload["signals"]
    if type(signals) is not dict or set(signals) != set(SIGNALS):
        raise PolicyPackContractError("policy input signals are not exhaustive")
    if any(type(value) is not str or value not in SIGNAL_STATES for value in signals.values()):
        raise PolicyPackContractError("policy input signal state is unsupported")
    if payload["raw_content_included"] is not False:
        raise PolicyPackContractError("policy input cannot include raw content")
    if payload["digest_is_authentication"] is not False:
        raise PolicyPackContractError("subject digest cannot authenticate identity or content")
    _require_no_authority(payload, "policy input")
    if payload["input_receipt_id"] != _identity(INPUT_DOMAIN, payload):
        raise PolicyPackContractError("policy input receipt identity drift")


def _validate_output(payload: dict[str, Any], pack: dict[str, Any]) -> None:
    fields = {
        "schema_version", "receipt_id", "input_receipt_id", "input_sha256",
        "pack_sha256", "results", "summary", "overall_advisory_disposition",
        "verdict_semantics", "may_authorize_effects", "operational_authority",
    }
    _require_fields(payload, fields, "policy output")
    if payload["schema_version"] != OUTPUT_VERSION:
        raise PolicyPackContractError("unsupported policy output version")
    for name in ("receipt_id", "input_receipt_id", "input_sha256", "pack_sha256"):
        _require_digest(payload[name], name)
    if payload["pack_sha256"] != pack["pack_sha256"]:
        raise PolicyPackContractError("policy output pack binding drift")
    results = payload["results"]
    if type(results) is not list or len(results) != len(SIGNALS):
        raise PolicyPackContractError("policy output result count drift")
    rules = {rule["signal"]: rule for rule in pack["rules"]}
    result_fields = {
        "rule_id", "signal", "signal_state", "matched", "advisory_disposition",
        "reason_codes", "playbook_path", "playbook_sha256", "may_authorize_effects",
        "operational_authority",
    }
    for index, result in enumerate(results):
        if type(result) is not dict:
            raise PolicyPackContractError("policy output result must be an object")
        _require_fields(result, result_fields, "policy output result")
        signal = SIGNALS[index]
        rule = rules[signal]
        if result["signal"] != signal or result["rule_id"] != rule["rule_id"]:
            raise PolicyPackContractError("policy output rule order or identity drift")
        if result["signal_state"] not in SIGNAL_STATES:
            raise PolicyPackContractError("policy output signal state is unsupported")
        if type(result["matched"]) is not bool or result["matched"] != (
            result["signal_state"] != "absent"
        ):
            raise PolicyPackContractError("policy output match accounting drift")
        expected_disposition = (
            "observe"
            if result["signal_state"] == "absent"
            else rule[f"{result['signal_state']}_disposition"]
        )
        if result["advisory_disposition"] != expected_disposition:
            raise PolicyPackContractError("policy output disposition drift")
        expected_reason = f"policy.{rule['rule_id']}.{result['signal_state']}"
        if result["reason_codes"] != [expected_reason]:
            raise PolicyPackContractError("policy output reason code drift")
        if result["playbook_path"] != rule["playbook_path"]:
            raise PolicyPackContractError("policy output playbook path drift")
        if result["playbook_sha256"] != rule["playbook_sha256"]:
            raise PolicyPackContractError("policy output playbook digest drift")
        _require_no_authority(result, "policy output result")
    _validate_summary(payload["summary"], results)
    expected_overall = max(
        (result["advisory_disposition"] for result in results),
        key=DISPOSITION_RANK.__getitem__,
    )
    if payload["overall_advisory_disposition"] != expected_overall:
        raise PolicyPackContractError("overall advisory disposition drift")
    if payload["verdict_semantics"] != VERDICT_SEMANTICS:
        raise PolicyPackContractError("policy output verdict semantics drift")
    _require_no_authority(payload, "policy output")
    if payload["receipt_id"] != _identity(OUTPUT_DOMAIN, payload):
        raise PolicyPackContractError("policy output receipt identity drift")


def _validate_summary(summary: Any, results: list[dict[str, Any]]) -> None:
    fields = {
        "signal_count", "absent", "present", "unknown", "observe", "challenge",
        "escalate", "abstain",
    }
    if type(summary) is not dict:
        raise PolicyPackContractError("policy output summary must be an object")
    _require_fields(summary, fields, "policy output summary")
    if any(type(value) is not int or value < 0 or value > len(SIGNALS) for value in summary.values()):
        raise PolicyPackContractError("policy output summary count is invalid")
    expected = {name: 0 for name in fields}
    expected["signal_count"] = len(results)
    for result in results:
        expected[result["signal_state"]] += 1
        expected[result["advisory_disposition"]] += 1
    if summary != expected:
        raise PolicyPackContractError("policy output summary accounting drift")


def _require_no_authority(value: dict[str, Any], label: str) -> None:
    if value.get("may_authorize_effects") is not False:
        raise PolicyPackContractError(f"{label} cannot authorize effects")
    if value.get("operational_authority") != "none":
        raise PolicyPackContractError(f"{label} has no operational authority")


def _require_fields(value: dict[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise PolicyPackContractError(f"{label} fields do not match V1")


def _require_digest(value: Any, label: str) -> None:
    if (
        type(value) is not str
        or len(value) != SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PolicyPackContractError(f"{label} must be lowercase SHA-256")


def _identity(domain: bytes, value: Mapping[str, Any]) -> str:
    payload = dict(value)
    if domain == PACK_DOMAIN:
        payload.pop("pack_sha256", None)
    if domain == INPUT_DOMAIN:
        payload.pop("input_receipt_id", None)
    if domain == OUTPUT_DOMAIN:
        payload.pop("receipt_id", None)
    return _sha256(domain + _canonical_json(payload))


def _decode_canonical(raw: bytes, max_bytes: int, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > max_bytes:
        raise PolicyPackContractError(f"{label} byte size is outside V1")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyPackContractError(f"{label} is not strict UTF-8 JSON") from exc
    _require_json_depth(text, label)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (
        json.JSONDecodeError,
        PolicyPackContractError,
        RecursionError,
    ) as exc:
        raise PolicyPackContractError(f"{label} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise PolicyPackContractError(f"{label} root must be an object")
    if _canonical_json(value) + b"\n" != raw:
        raise PolicyPackContractError(f"{label} is not canonical V1 JSON")
    return value


def _require_json_depth(text: str, label: str) -> None:
    """Reject pathological nesting independently of interpreter recursion limits."""

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise PolicyPackContractError(f"{label} exceeds V1 JSON nesting depth")
        elif character in "]}":
            depth -= 1


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyPackContractError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise PolicyPackContractError(f"non-finite JSON constant is forbidden: {value}")


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PolicyPackContractError("value is not canonical JSON data") from exc


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _lf_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    normalized = raw.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        raise PolicyPackContractError(f"bare carriage return in {path.name}")
    return normalized


def _lf_normalized_sha256(path: Path) -> str:
    return _sha256(_lf_bytes(path))


def _repo_file(root: Path, relative: str) -> Path:
    if (
        not relative
        or "\\" in relative
        or Path(relative).is_absolute()
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise PolicyPackContractError("policy-pack path is not repository-relative POSIX")
    unresolved = root / relative
    candidate = unresolved.resolve()
    if root not in candidate.parents or not candidate.is_file() or unresolved.is_symlink():
        raise PolicyPackContractError(f"unsafe or missing policy-pack path: {relative}")
    return candidate


def _digest_schema() -> dict[str, Any]:
    return {"type": "string", "pattern": "^[0-9a-f]{64}$"}


def _no_authority_properties() -> dict[str, Any]:
    return {
        "may_authorize_effects": {"const": False},
        "operational_authority": {"const": "none"},
    }


def _pack_schema(pack: dict[str, Any]) -> dict[str, Any]:
    properties = {
        "schema_version": {"const": PACK_VERSION},
        "pack_id": {"const": PACK_ID},
        "pack_sha256": _digest_schema(),
        "policy_mode": {"const": POLICY_MODE},
        "playbook_digest_semantics": {"const": PLAYBOOK_DIGEST_SEMANTICS},
        "rules": {"const": pack["rules"]},
        "allowed_dispositions": {"const": list(DISPOSITIONS)},
        "verdict_semantics": {"const": VERDICT_SEMANTICS},
        **_no_authority_properties(),
    }
    return _closed_schema("LLM Safety Policy Pack V1", properties)


def _input_schema() -> dict[str, Any]:
    signal_properties = {signal: {"enum": list(SIGNAL_STATES)} for signal in SIGNALS}
    properties = {
        "schema_version": {"const": INPUT_VERSION},
        "input_receipt_id": _digest_schema(),
        "pack_sha256": _digest_schema(),
        "subject_sha256": _digest_schema(),
        "subject_digest_semantics": {"const": "caller_supplied_sanitized_subject_commitment"},
        "source_class": {"enum": list(SOURCE_CLASSES)},
        "signals": {"type": "object", "additionalProperties": False,
                    "required": list(signal_properties), "properties": signal_properties},
        "raw_content_included": {"const": False},
        "digest_is_authentication": {"const": False},
        **_no_authority_properties(),
    }
    return _closed_schema("LLM Safety Policy Input Receipt V1", properties)


def _output_schema(pack: dict[str, Any]) -> dict[str, Any]:
    result_schemas = []
    for rule in pack["rules"]:
        result_properties = {
            "rule_id": {"const": rule["rule_id"]},
            "signal": {"const": rule["signal"]},
            "signal_state": {"enum": list(SIGNAL_STATES)},
            "matched": {"type": "boolean"},
            "advisory_disposition": {"enum": list(DISPOSITIONS)},
            "reason_codes": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1,
                "items": {
                    "type": "string",
                    "pattern": (
                        f"^policy\\.{rule['rule_id']}\\."
                        "(?:absent|present|unknown)$"
                    ),
                },
            },
            "playbook_path": {"const": rule["playbook_path"]},
            "playbook_sha256": {"const": rule["playbook_sha256"]},
            **_no_authority_properties(),
        }
        result_schemas.append(
            {
                "type": "object",
                "additionalProperties": False,
                "required": list(result_properties),
                "properties": result_properties,
            }
        )
    summary_names = (
        "signal_count", "absent", "present", "unknown", "observe", "challenge",
        "escalate", "abstain",
    )
    summary_properties = {
        name: {"type": "integer", "minimum": 0, "maximum": len(SIGNALS)}
        for name in summary_names
    }
    properties = {
        "schema_version": {"const": OUTPUT_VERSION},
        "receipt_id": _digest_schema(),
        "input_receipt_id": _digest_schema(),
        "input_sha256": _digest_schema(),
        "pack_sha256": _digest_schema(),
        "results": {
            "type": "array",
            "minItems": len(SIGNALS),
            "maxItems": len(SIGNALS),
            "prefixItems": result_schemas,
            "items": False,
        },
        "summary": {"type": "object", "additionalProperties": False,
                    "required": list(summary_properties), "properties": summary_properties},
        "overall_advisory_disposition": {"enum": list(DISPOSITIONS)},
        "verdict_semantics": {"const": VERDICT_SEMANTICS},
        **_no_authority_properties(),
    }
    return _closed_schema("LLM Safety Policy Evaluation Receipt V1", properties)


def _closed_schema(title: str, properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("generate", help="regenerate source-owned contract artifacts")
    subparsers.add_parser("check", help="fail on contract or source drift")
    evaluate_parser = subparsers.add_parser("evaluate", help="emit one canonical advisory receipt")
    evaluate_parser.add_argument("input", type=Path, help="canonical content-free input receipt")
    args = parser.parse_args(argv)
    if args.command == "generate":
        generate(ROOT)
        return 0
    if args.command == "check":
        validate_repository(ROOT)
        return 0
    try:
        raw = args.input.read_bytes()
        sys.stdout.buffer.write(evaluate_policy_input_v1(raw, root=ROOT))
    except OSError as exc:
        raise PolicyPackContractError("cannot read policy input receipt") from exc
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PolicyPackContractError as exc:
        print(f"policy-pack error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
