# Secret Handling

## Purpose

Keep credentials, tokens, private configuration, and sensitive logs out of model
context and public artifacts.

## Use When

- The task may touch `.env`, API keys, provider tokens, private URLs, cookies,
  SSH keys, cloud credentials, exchange keys, or webhook secrets.
- Logs may contain credentials or private identifiers.
- The model is asked to debug authentication, deployment, trading, or provider
  access.

## Boundary

The model can reason about secret-handling process without seeing the secret.

## Task Brief Wording

```text
Do not print, request, copy, summarize, transform, or commit secrets. Do not
open `.env` or credential files unless I explicitly authorize that exact file.

If a secret is needed, ask me to confirm the variable name or presence, not the
value. Use redacted placeholders in docs and logs.
```

## Check Before Acting

- Could this file contain credentials?
- Is the value needed, or only the variable name/presence?
- Will any output be committed, logged, emailed, or pasted into a public system?
- Is a redacted placeholder enough?

## Expected Safe Behavior

- Use names like `OPENAI_API_KEY` without exposing values.
- Replace sensitive values with `<redacted>`.
- Keep raw logs and private traces out of public repositories.

