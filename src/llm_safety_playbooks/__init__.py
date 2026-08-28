"""Exact data-only access to the reviewed LLM Safety Playbooks policy pack."""

from __future__ import annotations

import hashlib
from importlib.resources import files

__version__ = "0.1.0"
POLICY_PACK_ARTIFACT_SHA256 = (
    "1c8ca14e6ab83d92742f6fba0b0d1b1bc422ebe30163c6619e9c80f5413b8915"
)


class PolicyPackResourceError(ValueError):
    """Raised when installed package data differs from the reviewed artifact."""


def policy_pack_bytes() -> bytes:
    """Return exact canonical pack bytes without importing or executing playbook text."""

    payload = files("llm_safety_playbooks").joinpath("data/policy-pack.v1.json").read_bytes()
    if hashlib.sha256(payload).hexdigest() != POLICY_PACK_ARTIFACT_SHA256:
        raise PolicyPackResourceError("installed policy-pack artifact digest drift")
    return payload


def policy_pack_artifact_sha256() -> str:
    """Return the exact installed artifact digest after verifying its bytes."""

    policy_pack_bytes()
    return POLICY_PACK_ARTIFACT_SHA256


__all__ = [
    "POLICY_PACK_ARTIFACT_SHA256",
    "PolicyPackResourceError",
    "__version__",
    "policy_pack_artifact_sha256",
    "policy_pack_bytes",
]
