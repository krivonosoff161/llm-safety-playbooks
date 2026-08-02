"""Fail-closed validation for the P1 human observation-guidance contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

EXPECTED_OWNER_PIN = {
    "schema_version": "safety-playbooks-owner-contract-pin-v1.0",
    "owner_repository": "krivonosoff161/agentic-security-harness",
    "owner_commit": "9cb4532a2bc4212411974370bdf5cc0325648340",
    "contract_id": "portfolio-observation-v1.0",
    "vendored_schema_path": "contracts/portfolio-observation.v1.schema.json",
    "vendored_manifest_path": "contracts/portfolio-observation.v1.manifest.json",
    "schema_sha256": "19371f188b080accfdac489e985b9642f547c3300c0b56b44527eb97f550c26f",
    "owner_manifest_sha256": (
        "fecbe08da3e48250aaeff2ea19bf50efdbd2c3aa532af9cae8be50b4c8321554"
    ),
    "line_endings": "lf",
    "producer_attestation": "unattested_only",
    "operational_authority": "none",
}
EXPECTED_GUIDANCE_FIELDS = {
    "schema_version",
    "contract_id",
    "owner_pin_path",
    "guidance_mode",
    "required_metadata",
    "missing_or_invalid_metadata_disposition",
    "allowed_human_dispositions",
    "forbidden_promotions",
    "authority_envelope_interpretation",
    "producer_attestation_interpretation",
    "human_playbook_path",
    "human_playbook_sha256",
    "operational_authority",
}
EXPECTED_FORBIDDEN_PROMOTIONS = {
    "authority",
    "capability",
    "consent",
    "authenticated_identity",
    "allow_receipt",
    "producer_attestation",
}
EXPECTED_HUMAN_DISPOSITIONS = ("observe", "challenge", "escalate", "abstain")
EXPECTED_PLAYBOOK_SHA256 = "bd2c518c484072804f860d50d4b4ff52c246fafbaac4c7fb87db86aafd2f79f0"


class GuidanceContractError(ValueError):
    """Raised when local guidance or its pinned owner contract drifts."""


def validate(root: Path) -> None:
    """Validate exact owner bytes and the non-authoritative local guidance contract."""

    root = root.resolve()
    pin_path = _repo_file(root, "contracts/portfolio-observation.v1.owner-pin.json")
    guidance_path = _repo_file(root, "contracts/portfolio-observation-guidance.v1.json")
    pin = _load_json(pin_path)
    guidance = _load_json(guidance_path)
    if pin != EXPECTED_OWNER_PIN:
        raise GuidanceContractError("owner pin differs from the reviewed exact contract")
    if set(guidance) != EXPECTED_GUIDANCE_FIELDS:
        raise GuidanceContractError("guidance fields do not match V1")
    if guidance["schema_version"] != "portfolio-observation-guidance-v1.0":
        raise GuidanceContractError("unsupported guidance schema")
    if guidance["contract_id"] != EXPECTED_OWNER_PIN["contract_id"]:
        raise GuidanceContractError("guidance contract id drift")
    if guidance["owner_pin_path"] != pin_path.relative_to(root).as_posix():
        raise GuidanceContractError("guidance does not bind the reviewed owner pin")

    schema_path = _repo_file(root, _required_string(pin, "vendored_schema_path"))
    manifest_path = _repo_file(root, _required_string(pin, "vendored_manifest_path"))
    schema_bytes = _read_lf_bytes(schema_path)
    manifest_bytes = _read_lf_bytes(manifest_path)
    if hashlib.sha256(schema_bytes).hexdigest() != pin["schema_sha256"]:
        raise GuidanceContractError("vendored owner schema digest drift")
    if hashlib.sha256(manifest_bytes).hexdigest() != pin["owner_manifest_sha256"]:
        raise GuidanceContractError("vendored owner manifest digest drift")

    schema = _decode_json(schema_bytes, schema_path)
    manifest = _decode_json(manifest_bytes, manifest_path)
    required = schema.get("required")
    properties = schema.get("properties")
    if not isinstance(required, list) or not isinstance(properties, dict):
        raise GuidanceContractError("owner schema lacks required field metadata")
    if type(guidance["required_metadata"]) is not list:
        raise GuidanceContractError("required observation metadata must be a list")
    if len(required) != len(set(required)) or guidance["required_metadata"] != required:
        raise GuidanceContractError("required observation metadata drift")
    if schema.get("additionalProperties") is not False:
        raise GuidanceContractError("owner schema must reject unknown fields")
    if properties.get("operational_authority", {}).get("const") != "none":
        raise GuidanceContractError("owner schema permits operational authority")
    if properties.get("producer_attestation", {}).get("const") != "unattested":
        raise GuidanceContractError("owner schema promotes producer attestation")
    if any(
        promoted in properties
        for promoted in ("authority", "capability", "consent", "authenticated_identity", "allow_receipt")
    ):
        raise GuidanceContractError("owner observation exposes a forbidden promotion field")

    if manifest.get("schema_sha256") != pin["schema_sha256"]:
        raise GuidanceContractError("owner manifest does not bind the schema")
    expected_manifest_values = {
        "schema_version": "portfolio-observation-contract-manifest-v1.0",
        "contract_id": "portfolio-observation-v1.0",
        "canonicalization": "utf8-json-sort-keys-compact-utc-microseconds-lf-v1",
        "max_bytes": 4096,
        "max_entity_refs": 64,
        "max_parent_event_ids": 64,
        "max_adapter_fields": 128,
        "max_adapter_mappings": 128,
        "max_adapter_reason_codes": 64,
        "event_id_semantics": "producer_claim_shape_only",
        "producer_attestation": "unattested_only",
        "operational_authority": "none",
    }
    for field, expected in expected_manifest_values.items():
        if manifest.get(field) != expected:
            raise GuidanceContractError(f"owner manifest drift: {field}")

    if guidance["guidance_mode"] != "human_guidance_only":
        raise GuidanceContractError("playbooks cannot become enforcement")
    if guidance["missing_or_invalid_metadata_disposition"] != "abstain":
        raise GuidanceContractError("missing metadata must fail closed to abstain")
    if type(guidance["allowed_human_dispositions"]) is not list or tuple(
        guidance["allowed_human_dispositions"]
    ) != EXPECTED_HUMAN_DISPOSITIONS:
        raise GuidanceContractError("human dispositions drift or contain an allow decision")
    if type(guidance["forbidden_promotions"]) is not list or any(
        type(value) is not str for value in guidance["forbidden_promotions"]
    ):
        raise GuidanceContractError("forbidden promotions must be a string list")
    if set(guidance["forbidden_promotions"]) != EXPECTED_FORBIDDEN_PROMOTIONS:
        raise GuidanceContractError("forbidden promotion coverage drift")
    if len(guidance["forbidden_promotions"]) != len(EXPECTED_FORBIDDEN_PROMOTIONS):
        raise GuidanceContractError("forbidden promotions must be unique")
    if guidance["authority_envelope_interpretation"] != "evidence_pointer_only":
        raise GuidanceContractError("authority envelope was promoted beyond evidence")
    if guidance["producer_attestation_interpretation"] != "unattested_only":
        raise GuidanceContractError("producer identity was promoted to authenticated")
    if guidance["operational_authority"] != "none":
        raise GuidanceContractError("guidance cannot carry operational authority")

    playbook_path = _repo_file(root, _required_string(guidance, "human_playbook_path"))
    if guidance["human_playbook_sha256"] != EXPECTED_PLAYBOOK_SHA256:
        raise GuidanceContractError("human playbook reviewed digest drift")
    if hashlib.sha256(playbook_path.read_bytes()).hexdigest() != EXPECTED_PLAYBOOK_SHA256:
        raise GuidanceContractError("human playbook content drift")
    playbook = " ".join(playbook_path.read_text(encoding="utf-8").split()).lower()
    for phrase in (
        "human guidance only",
        "operational_authority=none",
        "abstain",
        "not consent",
        "not authenticated identity",
        "not an allow receipt",
    ):
        if phrase not in playbook:
            raise GuidanceContractError(f"human playbook boundary drift: {phrase}")
    if guidance["human_playbook_path"] not in (root / "README.md").read_text(encoding="utf-8"):
        raise GuidanceContractError("README does not expose the observation playbook")
    if "canonical-observation-review.md" not in (
        root / "docs" / "coverage-map.md"
    ).read_text(encoding="utf-8"):
        raise GuidanceContractError("coverage map does not expose the observation playbook")

    attributes = (root / ".gitattributes").read_text(encoding="utf-8").splitlines()
    for path in (
        pin_path,
        schema_path,
        manifest_path,
        guidance_path,
    ):
        rule = f"{path.relative_to(root).as_posix()} text eol=lf"
        if rule not in attributes:
            raise GuidanceContractError(f"missing LF attribute: {rule}")


def _repo_file(root: Path, relative: str) -> Path:
    posix = PurePosixPath(relative)
    if (
        not relative
        or "\\" in relative
        or Path(relative).is_absolute()
        or posix.is_absolute()
        or any(part in {"", ".", ".."} for part in posix.parts)
        or posix.as_posix() != relative
    ):
        raise GuidanceContractError("contract path is not a repository-relative POSIX path")
    unresolved = root / relative
    candidate = unresolved.resolve()
    if (
        root not in candidate.parents
        or not candidate.is_file()
        or unresolved.is_symlink()
    ):
        raise GuidanceContractError(f"unsafe or missing contract path: {relative}")
    return candidate


def _read_lf_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    if b"\r" in raw or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise GuidanceContractError(f"contract is not exactly LF-terminated: {path.name}")
    return raw


def _load_json(path: Path) -> dict[str, Any]:
    return _decode_json(_read_lf_bytes(path), path)


def _decode_json(raw: bytes, path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, GuidanceContractError) as exc:
        raise GuidanceContractError(f"invalid strict JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise GuidanceContractError(f"contract root must be an object: {path.name}")
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GuidanceContractError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise GuidanceContractError(f"non-finite JSON value is forbidden: {value}")


def _required_string(value: dict[str, Any], field: str) -> str:
    candidate = value.get(field)
    if not isinstance(candidate, str) or not candidate:
        raise GuidanceContractError(f"required string missing: {field}")
    return candidate


def main() -> int:
    validate(Path(__file__).resolve().parents[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
