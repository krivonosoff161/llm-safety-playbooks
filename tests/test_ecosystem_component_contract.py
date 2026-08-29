from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROOT_KEYS = {
    "schema_version",
    "component_id",
    "display_name",
    "repository",
    "visibility",
    "kind",
    "summary",
    "package",
    "owns",
    "consumes",
    "contracts",
    "docs",
    "compatibility",
    "integration_status",
    "evidence_refs",
    "claims",
    "non_claims",
    "authority",
}
HISTORICAL = {
    "docs/security-portfolio-roadmap.md",
    "docs/security-portfolio-roadmap-public.yaml",
    "docs/security-portfolio-roadmap-contract.json",
}


def load_manifest() -> dict[str, object]:
    return json.loads((ROOT / "component.yaml").read_text(encoding="utf-8"))


def test_component_manifest_is_closed_and_truthful() -> None:
    manifest = load_manifest()
    assert set(manifest) == ROOT_KEYS
    assert manifest["schema_version"] == "AgenticSecurityEcosystemComponent.v1"
    assert manifest["component_id"] == "llm-safety-playbooks"
    assert manifest["kind"] == "declarative_pack"
    assert manifest["integration_status"] == "standalone"
    assert manifest["authority"] == "none"
    assert manifest["package"] == {
        "name": "llm-safety-playbooks",
        "version": "0.1.0",
        "install": "pip install .",
        "entry_points": [],
    }
    compatibility = manifest["compatibility"]
    assert isinstance(compatibility, dict)
    platforms = compatibility["platforms"]
    assert isinstance(platforms, dict)
    assert set(platforms["tested"]) <= set(platforms["supported"])
    assert compatibility["python"] == ">=3.9"
    assert platforms == {
        "supported": ["linux", "windows"],
        "tested": ["linux", "windows"],
    }
    contracts = manifest["contracts"]
    assert isinstance(contracts, list)
    assert all(item["direction"] in {"provides", "consumes"} for item in contracts)
    assert {
        item["id"] for item in contracts if item["direction"] == "provides"
    } >= {
        "portfolio-observation-guidance",
        "policy-pack",
        "policy-input-receipt",
        "policy-evaluation-receipt",
    }


def test_document_roles_exist_and_preserve_historical_snapshots() -> None:
    manifest = load_manifest()
    docs = manifest["docs"]
    assert isinstance(docs, list)
    by_path = {item["path"]: item["role"] for item in docs}
    assert HISTORICAL <= set(by_path)
    assert all(by_path[path] == "historical" for path in HISTORICAL)
    assert all((ROOT / path).is_file() for path in by_path)
    assert all((ROOT / path).is_file() for path in manifest["evidence_refs"])


def test_front_door_points_to_component_and_ecosystem_roadmaps() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    roadmap = (ROOT / "docs" / "component-roadmap.md").read_text(encoding="utf-8")
    assert "docs/component-roadmap.md" in readme
    assert "agentic-security-harness/blob/main/docs/ecosystem-roadmap.md" in readme
    assert "standalone declarative guidance pack" in readme
    assert "data-only `llm-safety-playbooks` wheel" in readme
    assert "Historical portfolio snapshots" in roadmap
    assert "deterministic offline advisory evaluator" in roadmap
    component = (ROOT / "component.yaml").read_text(encoding="utf-8")
    assert "does not inspect raw content" in component
    assert "enforce security policy" in component


def test_install_docs_distinguish_source_extra_from_public_packages() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pack = (ROOT / "docs" / "policy-pack-v1.md").read_text(encoding="utf-8")

    for text in (readme, pack):
        assert "Harness `main`" in text
        assert "published Harness `v1.3.0` metadata does not contain" in text
    assert "Public `pip install agentic-security-harness[playbooks]` support" in readme
    assert "does not load entry points" in readme


class EcosystemComponentContractTests(unittest.TestCase):
    def test_closed_and_truthful_manifest(self) -> None:
        test_component_manifest_is_closed_and_truthful()

    def test_document_roles_and_history(self) -> None:
        test_document_roles_exist_and_preserve_historical_snapshots()

    def test_front_door_and_roadmaps(self) -> None:
        test_front_door_points_to_component_and_ecosystem_roadmaps()

    def test_source_and_public_install_boundary(self) -> None:
        test_install_docs_distinguish_source_extra_from_public_packages()
