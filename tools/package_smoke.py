"""Build-output and installed-wheel smoke for the data-only Playbooks package."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

EXPECTED_WHEEL = "llm_safety_playbooks-0.1.0-py3-none-any.whl"
EXPECTED_SDIST = "llm_safety_playbooks-0.1.0.tar.gz"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    args = parser.parse_args()
    dist = args.dist.resolve()
    wheel = dist / EXPECTED_WHEEL
    sdist = dist / EXPECTED_SDIST
    if not wheel.is_file() or not sdist.is_file():
        raise SystemExit("exact wheel/sdist set is missing")
    artifacts = sorted(path.name for path in dist.iterdir() if path.is_file())
    if artifacts != sorted([EXPECTED_SDIST, EXPECTED_WHEEL]):
        raise SystemExit(f"unexpected dist artifact set: {artifacts}")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    required = {
        "llm_safety_playbooks/__init__.py",
        "llm_safety_playbooks/data/policy-pack.v1.json",
        "llm_safety_playbooks/py.typed",
    }
    if not required <= names:
        raise SystemExit("wheel is missing the exact data-only package surface")
    if any(name.endswith("entry_points.txt") for name in names):
        raise SystemExit("data-only wheel unexpectedly declares an entry point")
    with tempfile.TemporaryDirectory() as temporary:
        target = Path(temporary) / "site"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-deps",
                "--no-compile",
                "--target",
                str(target),
                str(wheel),
            ],
            check=True,
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(target)
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                (
                    "import sys;sys.path.insert(0,sys.argv[1]);"
                    "import llm_safety_playbooks as p;"
                    "assert p.__version__=='0.1.0';"
                    "assert p.policy_pack_artifact_sha256()=="
                    "'1c8ca14e6ab83d92742f6fba0b0d1b1bc422ebe30163c6619e9c80f5413b8915'"
                ),
                str(target),
            ],
            check=True,
            env=environment,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
