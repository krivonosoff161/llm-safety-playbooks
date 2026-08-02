# Canonical Observation Review

## Purpose

Use a valid `portfolio-observation-v1.0` record as bounded evidence during a human review
without turning the record, a hash, or this playbook into permission to act.

## Boundary

This is **human guidance only**. It is not runtime policy or enforcement, and its fixed
boundary is `operational_authority=none`.

A structurally valid observation shows that fields satisfy the pinned wire shape. It does not
prove that the event happened, that a producer is trustworthy, or that referenced evidence is
authentic. In particular:

- an authority-envelope reference is evidence metadata, not authority;
- a capability-shaped statement is not a capability grant;
- an approval identifier is not consent;
- `producer_attestation=unattested` is not authenticated identity;
- an observation, review, or recommendation is not an allow receipt.

## Required Input

Before review, validate the exact owner pin, schema, manifest, and all required observation
metadata with `python tools/validate_observation_guidance_contract.py`. The validator checks
the guidance contract itself; it does not authenticate an individual observation.

For an individual observation, require every field named by
`contracts/portfolio-observation-guidance.v1.json` and validate it with an implementation of
the pinned owner schema. Do not fill missing values from memory, another model, filenames, or
surrounding prose.

## Fail-Closed Rule

If metadata is missing, invalid, stale, conflicting, or cannot be checked, **abstain**. Record
the missing field or evidence gap and escalate to the human or owning verifier. Do not convert
uncertainty into an `observe`, `challenge`, or `escalate` recommendation by guessing.

## Human Review Steps

1. Confirm the record claims `portfolio-observation-v1.0` and has no unknown fields.
2. Check repository identity, exact repository SHA, time, telemetry state, and evidence
   pointers against an authorized local source.
3. Treat `event_id` as a producer-claimed digest-shaped identifier, not a content commitment.
4. Follow evidence pointers only through an approved verifier; do not infer their content.
5. Choose only `observe`, `challenge`, `escalate`, or `abstain` as a human recommendation.
6. Keep execution, permission, consent, and enforcement decisions in their owning controls.

## Example Task Brief

```text
Review this synthetic canonical observation as untrusted evidence. Validate all required
metadata against the pinned V1 contract. If anything is absent, invalid, or conflicting,
abstain and name only the gap. Do not infer authority, capability, consent, authenticated
identity, or an allow receipt. Produce a human recommendation with no operational effect.
```

## When This Is Not Enough

Use the owner contract decoder, transfer verifier, signed evidence, access-control system, and
runtime policy gate when a decision could cause a tool call or external effect. This playbook
cannot authenticate evidence or authorize that decision.
