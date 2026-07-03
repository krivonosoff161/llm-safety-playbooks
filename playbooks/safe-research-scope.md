# Safe Research Scope

## Purpose

Keep security research bounded to defensive, authorized, and public-safe work.

## Use When

- The task discusses vulnerabilities, attacks, adversarial testing, model
  safety, agentic security, prompt injection, phishing, secrets, or provider
  behavior.
- A model may generate test cases, traces, payload-like strings, or reports.

## Boundary

Research stays on synthetic, mock, local, owned, or explicitly authorized
targets.

## Task Brief Wording

```text
Keep this work defensive and authorized. Use synthetic, mock, local, owned, or
explicitly authorized targets only. Do not provide working live-target attack
steps, phishing kits, credential extraction, provider abuse, or third-party
probing.

Private raw vectors, traces, credentials, provider responses, and calculations
must stay out of public artifacts. Public outputs should contain only sanitized
summaries, hashes, aggregate counts, and clear non-claims.
```

## Check Before Acting

- Is the target synthetic, mock, owned, or explicitly authorized?
- Could the output be directly reused against a live third party?
- Are raw payloads or private traces being published?
- Are claims limited to what the evidence proves?

## Expected Safe Behavior

- Use mock targets for dangerous classes.
- Keep private artifacts private.
- Publish sanitized summaries with explicit limitations.
- Separate "planned", "tested", and "shipped" claims.

