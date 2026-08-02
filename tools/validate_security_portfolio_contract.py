"""Validate the digest-bound Security Portfolio module contract."""

import hashlib
import json
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    agent_contract = " ".join((root / "AGENTS.md").read_text(encoding="utf-8").split())
    for phrase in ("main", "codex/*", "never weaken", "separate owner gates", "grant no authority"):
        if phrase not in agent_contract:
            raise SystemExit(f"agent authority contract drift: {phrase}")
    contract = json.loads(
        (root / "docs" / "security-portfolio-roadmap-contract.json").read_text(encoding="utf-8")
    )
    if contract["schema_version"] != "SecurityPortfolioLocalContract.v2":
        raise SystemExit("unsupported contract schema")
    if contract["repository_id"] != "llm-safety-playbooks":
        raise SystemExit("wrong repository owner")
    projection_path = (root / contract["vendored_projection_path"]).resolve()
    if (
        root.resolve() not in projection_path.parents
        or not projection_path.is_file()
        or projection_path.is_symlink()
    ):
        raise SystemExit("unsafe vendored projection path")
    raw = projection_path.read_bytes()
    if len(raw) != contract["public_projection_size"]:
        raise SystemExit("vendored projection size drift")
    if hashlib.sha256(raw).hexdigest() != contract["public_projection_sha256"]:
        raise SystemExit("vendored projection digest drift")
    projection = json.loads(raw)
    if projection["roadmap_version"] != contract["roadmap_version"]:
        raise SystemExit("roadmap version drift")
    if projection["source_sha256"] != contract["upstream_private_source_sha256"]:
        raise SystemExit("private source commitment drift")
    repository = next(
        item for item in projection["repositories"] if item["id"] == contract["repository_id"]
    )
    if repository["roadmap_authority"] != contract["roadmap_authority"]:
        raise SystemExit("roadmap authority drift")
    expected = [
        {"id": item["id"], "status": item["status"]}
        for item in projection["modules"]
        if item["owner"] == contract["repository_id"]
    ]
    forbidden = sorted(
        {
            claim
            for item in projection["modules"]
            if item["owner"] == contract["repository_id"]
            for claim in item["forbidden_claims"]
        }
        | {"operational_authority"}
    )
    if (
        projection["authority"] != "none"
        or contract["owned_modules"] != expected
        or contract["authority"] != "none"
    ):
        raise SystemExit("module ownership or authority drift")
    if contract["forbidden_promotions"] != forbidden:
        raise SystemExit("forbidden promotion drift")
    if any(
        projection["status_profiles"][item["status"]]["authority"] != contract["authority"]
        for item in expected
    ):
        raise SystemExit("owned module status profile promotes authority")
    document = (root / "docs" / "security-portfolio-roadmap.md").read_text(encoding="utf-8")
    if contract["roadmap_version"] not in document or "`none`" not in document:
        raise SystemExit("human contract pin drift")
    if any(
        item["id"] not in document or item["status"] not in document
        for item in contract["owned_modules"]
    ):
        raise SystemExit("human module status drift")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
