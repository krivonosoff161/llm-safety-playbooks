# Offline Policy Pack V1

Policy Pack V1 turns a closed set of caller-supplied risk signals into deterministic advisory
guidance. It is executable because the same canonical input bytes and source-owned pack always
produce the same canonical output bytes. It remains a guidance component: it neither inspects
raw subject content nor performs an effect.

## Contract surfaces

- `contracts/policy-pack.v1.json` binds seven ordered rules to reviewed playbook paths and
  SHA-256 digests using `sha256_lf_normalized_text_v1` semantics.
- `contracts/policy-input-receipt.v1.schema.json` defines a content-free input receipt.
- `contracts/policy-evaluation-receipt.v1.schema.json` defines the advisory output receipt.
- `contracts/policy-pack.v1.manifest.json` binds generated artifacts, source, playbooks, tests,
  documentation, component metadata, and CI.
- `tools/policy_pack.py` owns canonical generation, validation, decoding, and evaluation.

All generated JSON shapes are closed. Canonical receipts use sorted compact UTF-8 JSON with one
LF terminator. Duplicate fields, unknown fields, alternate whitespace, CRLF, missing signals,
wrong pack bindings, identity drift, and authority promotion fail closed.
Input receipts are limited to 16,384 bytes and all decoded JSON is limited to 64 structural
nesting levels, so rejection does not depend on an interpreter-specific recursion limit.
The pack schema fixes the exact ordered rule set, and the output schema fixes each ordered result
to its source-owned rule and reviewed playbook digest. The Python codec additionally enforces
cross-field disposition, match, summary, and content-identity relationships.

## Input boundary

The evaluator accepts exactly seven signal states, each `absent`, `present`, or `unknown`:

- `untrusted_instructions_detected`;
- `secret_exposure_risk`;
- `generated_resource_unverified`;
- `git_change_control_unclear`;
- `handoff_verification_incomplete`;
- `research_authorization_unclear`;
- `observation_metadata_invalid`.

The receipt contains only those states, a source class, the exact pack digest, and a
caller-supplied SHA-256 subject commitment. It cannot contain raw content. A subject digest is a
binding hint, not anonymity, authentication, provenance, consent, or proof that the caller mapped
signals correctly.

## Output boundary

Every signal produces exactly one ordered result with a reviewed playbook digest, sanitized
reason code, and one of `observe`, `challenge`, `escalate`, or `abstain`. There is no `allow`
disposition. `unknown` never reduces the rule's response below its configured risk disposition.
The overall advisory disposition is the most conservative result by the fixed pack order.

The pack, input, output, and every result carry:

```text
may_authorize_effects = false
operational_authority = none
```

Receipts are content-bound but unsigned. They do not authenticate a caller or model, prove signal
quality, classify raw content, grant permission, block a tool, or establish that an absent signal
is safe.

The manifest detects accidental drift inside a reviewed source tree. Because the generator can
refresh its own hashes, regeneration is not a signature, independent attestation, or proof that a
change is trustworthy. Review the source diff before accepting regenerated artifacts.

## Offline commands

Generate source-owned artifacts after an intentional contract change:

```text
python tools/policy_pack.py generate
```

Verify exact generated and source bindings:

```text
python tools/policy_pack.py check
```

Evaluate the committed synthetic fixture without a network or provider:

```text
python tools/policy_pack.py evaluate tests/fixtures/policy-pack-v1/valid/mixed-signals.json
```

The command writes one canonical advisory receipt to standard output. It performs no network,
provider, subprocess, filesystem mutation, approval, enforcement, or effect execution.
