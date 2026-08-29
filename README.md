# LLM Safety Playbooks

Ecosystem role and current integration status: [component roadmap](docs/component-roadmap.md).
The public cross-repository plan is owned by the
[Agentic Security Harness ecosystem roadmap](https://github.com/krivonosoff161/agentic-security-harness/blob/main/docs/ecosystem-roadmap.md).

Practical playbooks for making LLM and AI-agent boundaries explicit during
everyday work.

This repository is the lightweight companion to
[Agentic Security Harness](https://github.com/krivonosoff161/agentic-security-harness).
The harness measures boundary failures with traces and scorecards. These
playbooks help users write safer task briefs before a full benchmark or runtime
control is available.

Today this repository is a standalone declarative guidance pack with one executable,
deterministic offline advisory evaluator. The current source tree also builds a
data-only `llm-safety-playbooks` wheel containing the exact canonical Policy Pack V1 bytes.
Version `0.1.0` is published on PyPI. It is not a code-loading Harness extension, and Harness does not automatically discover
or execute it.

## Installable data package

Install the exact public distribution directly or through Harness:

```bash
python -m pip install llm-safety-playbooks==0.1.0
python -m pip install "agentic-security-harness[playbooks]==1.4.0"
```

The installed API exposes only verified canonical bytes:

```python
from llm_safety_playbooks import policy_pack_bytes

pack = policy_pack_bytes()
```

Importing the package does not load entry points, execute Markdown, inspect content, call a
provider, or authorize an effect. Published Harness `v1.4.0` exposes the package through
the passive `playbooks` extra; installation does not activate or execute the playbooks.

## Core Rule

```text
AI output is a proposal until it is checked.
```

That applies to:

- repo text, logs, and tool output;
- generated URLs, packages, API endpoints, and webhooks;
- credentials and configuration;
- Git operations;
- handoff notes between agents;
- security research tasks.

## What This Is

- Short Markdown playbooks.
- Reusable wording for humans working with LLMs and coding agents.
- Boundary reminders for common failure modes.
- A practical entry point for teams that do not need to run a full benchmark.

## What This Is Not

- Not a security product.
- Not a jailbreak or prompt-injection collection.
- Not a claim that prompts alone provide protection.
- Not a replacement for runtime controls, tests, policy enforcement, review, or
  benchmarks.
- Not guidance for live attacks, phishing, credential extraction, or provider
  abuse.

## Playbooks

| Playbook | Use when |
|---|---|
| [Data vs Instructions](playbooks/data-vs-instructions.md) | The model reads README files, issues, docs, logs, tool output, or other untrusted text. |
| [Secret Handling](playbooks/secret-handling.md) | A task may involve `.env`, tokens, credentials, logs, or private configuration. |
| [Generated Resource Check](playbooks/generated-resource-check.md) | The model suggests a URL, domain, package, API endpoint, webhook, or service portal. |
| [Git Agent Safety](playbooks/git-agent-safety.md) | A coding agent may edit files, create branches, push, or prepare a PR. |
| [Handoff Verification](playbooks/handoff-verification.md) | One agent, model, or human passes work to another. |
| [Safe Research Scope](playbooks/safe-research-scope.md) | A security-related task needs synthetic, mock, owned, or explicitly authorized boundaries. |
| [Canonical Observation Review](playbooks/canonical-observation-review.md) | A human reviews a pinned portfolio observation without promoting metadata into authority or an allow decision. |

## How To Use

Copy the relevant playbook section into your task brief, then adapt it to the
actual project. Keep it short. The point is to remove ambiguity before the
model acts.

Use this pattern:

```text
Task: <what you want done>
Boundary: <which playbook rule applies>
Evidence: <what should be checked before action>
Stop condition: <when the model should pause and ask>
```

For higher-assurance evaluation, use a harness, tests, policy gates, logs, and
reviewable artifacts. These playbooks are the first layer, not the final layer.

The machine-checkable P1 guidance contract is
[`contracts/portfolio-observation-guidance.v1.json`](contracts/portfolio-observation-guidance.v1.json).
Validate its exact owner schema/manifest pins and human-only boundary with:

```text
python tools/validate_observation_guidance_contract.py
```

This validation does not authenticate an observation and does not grant operational authority.

## Offline Policy Pack V1

[`Policy Pack V1`](docs/policy-pack-v1.md) maps seven caller-supplied, content-free risk signals
to `observe / challenge / escalate / abstain` guidance. It reads no prompt, secret, model output,
or subject content. Both its canonical input and output receipts are digest-bound and fixed to:

```text
may_authorize_effects = false
operational_authority = none
```

Validate the generated pack, schemas, synthetic fixture, documentation, and source bindings:

```text
python tools/policy_pack.py check
```

Evaluate the committed synthetic fixture entirely offline:

```text
python tools/policy_pack.py evaluate tests/fixtures/policy-pack-v1/valid/mixed-signals.json
```

The output is advice, not a correctness claim, allow decision, permission, or enforcement action.

Public ecosystem ordering and documentation authority live in the Harness-owned
[ecosystem roadmap](https://github.com/krivonosoff161/agentic-security-harness/blob/main/docs/ecosystem-roadmap.md).
The profile repository is a generated navigation surface. This repository owns only the
lightweight playbook layer, not the benchmark or runtime control layer.

For a source-backed view of what these playbooks cover and where they stop, see
[docs/coverage-map.md](docs/coverage-map.md).

## When This Is Not Enough

Use stronger controls when a task can mutate production systems, process
credentials, call external providers, install dependencies, execute code, move
money, send messages, or change access permissions.

Stronger controls include:

- runtime policy gates;
- tests and validators;
- allowlists and signed-source checks;
- logging and audit trails;
- peer review or maintainer approval;
- benchmark runs with [Agentic Security Harness](https://github.com/krivonosoff161/agentic-security-harness).

## Related Projects

- [Component roadmap](docs/component-roadmap.md)
  - source-owned status, platform evidence, historical projections, and next gates.
- [agentic-security-harness](https://github.com/krivonosoff161/agentic-security-harness)
  - trace-first benchmark for agentic AI boundary failures.
- [agentic-transfer-verifier](https://github.com/krivonosoff161/agentic-transfer-verifier)
  - research toolkit for provenance, trust, and authority handoffs.
- [ai-agent-handoff](https://github.com/krivonosoff161/ai-agent-handoff)
  - file-based handoff protocol for AI coding agents.
