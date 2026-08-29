# LLM Safety Playbooks component roadmap

This page is the source-owned roadmap for `llm-safety-playbooks`. The machine-readable
component truth is [`component.yaml`](../component.yaml). The public ecosystem order and
cross-repository phases belong to the
[Agentic Security Harness ecosystem roadmap](https://github.com/krivonosoff161/agentic-security-harness/blob/main/docs/ecosystem-roadmap.md).

## Current state

- Kind: `declarative_pack`.
- Integration: `standalone`.
- Distribution: Markdown playbooks, machine-checkable guidance, a stdlib-only deterministic
  offline advisory evaluator, and published data-only Python distribution
  `llm-safety-playbooks==0.1.0`. The wheel has no Harness entry point. Published Harness
  `v1.4.0` exposes it through the passive `playbooks` extra.
- Platforms: the content supports Linux and Windows workflows. The current documentation
  contract CI records Linux only.
- Authority: `none`.

The playbooks provide human guidance. The deterministic offline advisory evaluator accepts only
closed content-free signal receipts and emits canonical advisory receipts. Neither layer inspects
raw subject content, authenticates provenance, isolates a runtime, enforces policy, authorizes an
effect, or establishes an allow decision.

## Component-owned documents

- [`README.md`](../README.md): public front door and usage.
- [`coverage-map.md`](coverage-map.md): source vocabulary, coverage, and control limits.
- [`../playbooks/`](../playbooks/): the human guidance corpus.
- [`../contracts/portfolio-observation-guidance.v1.json`](../contracts/portfolio-observation-guidance.v1.json): bounded machine-checkable review guidance.
- [`policy-pack-v1.md`](policy-pack-v1.md): executable contract, threat boundaries, canonical
  receipts, and offline use.
- [`../contracts/policy-pack.v1.manifest.json`](../contracts/policy-pack.v1.manifest.json):
  generated schema/source/playbook bindings for the pack.

## Historical portfolio snapshots

The following digest-bound files are preserved as historical evidence. They describe an
earlier private-product portfolio projection and no longer own current ecosystem status:

- `docs/security-portfolio-roadmap.md`;
- `docs/security-portfolio-roadmap-public.yaml`;
- `docs/security-portfolio-roadmap-contract.json`.

They grant no operational authority. Current cross-repository status comes from the Harness
ecosystem roadmap; this repository owns only its guidance component facts.

## Ordered next gates

1. Review the source-owned Policy Pack V1 against the Harness declarative-pack contract without
   granting discovery or execution authority.
2. **Public package released.** The wheel contains the exact canonical pack
   bytes, verify its closed file set, and smoke-install it without dependencies.
3. **Public integration released.** Harness optional-dependency and conformance
   checks treat pack bytes and receipts only as data; no entry-point discovery or playbook
   execution is permitted.
4. Keep Linux and Windows contract matrices green across the declared Python range.
5. Keep integration `standalone` unless a later explicit component contract justifies
   promotion; source conformance alone does not change integration status.
