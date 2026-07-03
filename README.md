# LLM Safety Playbooks

Practical playbooks for making LLM and AI-agent boundaries explicit during
everyday work.

This repository is the lightweight companion to
[Agentic Security Harness](https://github.com/krivonosoff161/agentic-security-harness).
The harness measures boundary failures with traces and scorecards. These
playbooks help users write safer task briefs before a full benchmark or runtime
control is available.

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

- [agentic-security-harness](https://github.com/krivonosoff161/agentic-security-harness)
  - trace-first benchmark for agentic AI boundary failures.
- [agentic-transfer-verifier](https://github.com/krivonosoff161/agentic-transfer-verifier)
  - research toolkit for provenance, trust, and authority handoffs.
- [ai-agent-handoff](https://github.com/krivonosoff161/ai-agent-handoff)
  - file-based handoff protocol for AI coding agents.
