# LLM Safety Playbooks component roadmap

This page is the source-owned roadmap for `llm-safety-playbooks`. The machine-readable
component truth is [`component.yaml`](../component.yaml). The public ecosystem order and
cross-repository phases belong to the
[Agentic Security Harness ecosystem roadmap](https://github.com/krivonosoff161/agentic-security-harness/blob/main/docs/ecosystem-roadmap.md).

## Current state

- Kind: `declarative_pack`.
- Integration: `standalone`.
- Distribution: Markdown playbooks and a machine-checkable guidance contract; there is no
  installable Python package or Harness entry point today.
- Platforms: the content supports Linux and Windows workflows. The current documentation
  contract CI records Linux only.
- Authority: `none`.

The playbooks provide human guidance. They do not execute checks, authenticate provenance,
isolate a runtime, enforce policy, or establish an allow decision.

## Component-owned documents

- [`README.md`](../README.md): public front door and usage.
- [`coverage-map.md`](coverage-map.md): source vocabulary, coverage, and control limits.
- [`../playbooks/`](../playbooks/): the human guidance corpus.
- [`../contracts/portfolio-observation-guidance.v1.json`](../contracts/portfolio-observation-guidance.v1.json): bounded machine-checkable review guidance.

## Historical portfolio snapshots

The following digest-bound files are preserved as historical evidence. They describe an
earlier private-product portfolio projection and no longer own current ecosystem status:

- `docs/security-portfolio-roadmap.md`;
- `docs/security-portfolio-roadmap-public.yaml`;
- `docs/security-portfolio-roadmap-contract.json`.

They grant no operational authority. Current cross-repository status comes from the Harness
ecosystem roadmap; this repository owns only its guidance component facts.

## Ordered next gates

1. Define the declarative-pack contract in the Harness Extension SDK.
2. Decide whether the pack remains repository-distributed or becomes a data-only package.
3. Add offline conformance fixtures for pack discovery without executing playbook text.
4. Record Linux and Windows contract tests before claiming cross-platform suite verification.
5. Promote integration beyond `standalone` only after a real Harness conformance test exists.

