# Coverage Map

This repository is intentionally small. It turns recurring LLM and coding-agent
safety lessons into short task-brief playbooks. It does not enforce policy by
itself.

The map below ties each playbook to common risk areas and stronger controls that
should exist when the task can mutate files, tools, infrastructure, accounts, or
money.

## Source Baseline

The playbooks are informed by these public references:

- OWASP Top 10 for LLM Applications 2025:
  <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- NIST AI RMF Generative AI Profile, NIST AI 600-1:
  <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- OpenAI agent safety guidance:
  <https://developers.openai.com/api/docs/guides/agent-builder-safety>
- OpenAI Agents SDK handoffs and guardrails:
  <https://openai.github.io/openai-agents-python/handoffs/>
  and <https://openai.github.io/openai-agents-python/guardrails/>
- Model Context Protocol security best practices:
  <https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices>
- W3C PROV overview and data model:
  <https://www.w3.org/TR/prov-overview/>
  and <https://www.w3.org/TR/prov-dm/>
- in-toto attestation framework and SLSA provenance:
  <https://github.com/in-toto/attestation>
  and <https://slsa.dev/spec/v0.1/provenance>

These sources do not make the playbooks authoritative. They give the repo a
shared vocabulary for risk, provenance, handoff, and evidence.

## Playbook Coverage

| Playbook | Primary problem | Related risk language | Stronger controls |
|---|---|---|---|
| [Data vs Instructions](../playbooks/data-vs-instructions.md) | Untrusted text tries to become an instruction source. | Prompt injection, tool output injection, untrusted context, excessive agency. | Runtime policy gates, data labels, parser boundaries, tool-call approval, benchmark traces. |
| [Secret Handling](../playbooks/secret-handling.md) | Secrets enter prompt context, logs, diffs, or handoffs. | Sensitive information disclosure, data privacy, information security. | Secret scanning, redaction, least privilege, separate secret stores, audit logs. |
| [Generated Resource Check](../playbooks/generated-resource-check.md) | Model suggests a URL, package, API endpoint, webhook, or service that may be wrong, hijacked, or unverified. | Supply-chain risk, generated-resource trust, information integrity. | Allowlist checks, registry/DNS verification, signed-source checks, sandbox install, dependency review. |
| [Git Agent Safety](../playbooks/git-agent-safety.md) | Agent edits, commits, pushes, or merges without enough review. | Change-control failure, excessive agency, supply-chain integrity. | Issue/branch/PR gates, CI, review rules, protected branches, signed commits or attestations where needed. |
| [Handoff Verification](../playbooks/handoff-verification.md) | Work moves between agents/humans without source, scope, confidence, or checked/not-checked fields. | Provenance loss, stale context, authority laundering. | Structured handoff files, verifier checks, hash/signature binding, approval records, replayable audit trail. |
| [Safe Research Scope](../playbooks/safe-research-scope.md) | Security work drifts from synthetic/owned/authorized scope toward live abuse. | Authorized testing boundary, misuse prevention, policy scope. | Explicit target authorization, mock fixtures, no real credentials, no third-party abuse, evidence redaction. |

## What The Playbooks Can Do

- Make the trusted instruction source explicit.
- Force the user or agent to name data boundaries before action.
- Create a short stop condition for ambiguous authority.
- Improve reviewability of LLM-assisted work.
- Provide reusable wording for issue, branch, PR, and handoff workflows.

## What They Cannot Do

- Prevent a model from ignoring the instruction.
- Prove a target is safe.
- Replace runtime isolation, access control, monitoring, or policy enforcement.
- Validate provenance by themselves.
- Detect every malicious or stale input.
- Turn untrusted third-party systems into authorized targets.

## When To Escalate Beyond A Playbook

Use stronger controls when any of these are true:

- The agent can execute commands, write files, install dependencies, send
  messages, create pull requests, merge code, or change access permissions.
- The task touches credentials, `.env`, private logs, tokens, customer data, or
  private model/provider configuration.
- The model is asked to trust output from another model, tool, MCP server,
  repository, ticket, browser page, or memory store.
- The result will be used as evidence for a public claim.
- The task has business, financial, legal, or security impact.

Escalation options:

- run a local benchmark with
  [Agentic Security Harness](https://github.com/krivonosoff161/agentic-security-harness);
- use structured handoff files from
  [ai-agent-handoff](https://github.com/krivonosoff161/ai-agent-handoff);
- validate provenance and authority with
  [agentic-transfer-verifier](https://github.com/krivonosoff161/agentic-transfer-verifier);
- require CI/review gates before merge;
- keep raw/private evidence out of public repositories.

## Design Rule

Each playbook should stay short enough to paste into a real task brief. If a
topic needs schemas, traces, scoring, or formal proof, it belongs in a verifier
or benchmark repository, not here.
