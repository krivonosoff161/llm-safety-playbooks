# Generated Resource Check

## Purpose

Prevent model-generated resources from becoming trusted infrastructure without
verification.

This playbook covers the Phantom Resource Trust boundary: URLs, domains,
package names, API endpoints, webhooks, and service portals are not trusted
just because an LLM produced them.

## Use When

- A model suggests a URL, domain, package, API endpoint, webhook, CLI install
  command, or service portal.
- A coding agent wants to fetch, install, call, or paste a generated resource
  into code or configuration.
- A workflow could automatically follow a link or download a dependency.

## Boundary

Model-generated resources are drafts until independently verified.

## Task Brief Wording

```text
Treat any model-generated URL, domain, package name, API endpoint, webhook, or
service portal as unverified. Do not fetch, install, call, or commit it until
it is checked against an official source, trusted registry, allowlist, DNS
record, signed source, or project-approved documentation.

If verification is not possible, mark the resource as unverified and do not use
it for execution, credentials, deployment, or automation.
```

## Example Task Brief

```text
If you suggest any package, URL, domain, API endpoint, webhook, or service
portal, label it as unverified until you check it against an official source or
trusted registry. Do not install, fetch, call, or commit generated resources.
If you cannot verify the resource, propose a verification step instead.
```

## Check Before Acting

- Did the resource come from an official source or from model text?
- Is there a trusted registry or documentation page?
- Is the domain/package newly created, misspelled, or zero-reputation?
- Would using it expose credentials, telemetry, source code, or build data?

## Expected Safe Behavior

- Verify package names in the official registry before installation.
- Verify service endpoints against official documentation.
- Keep unverified resources out of code, CI, deployment, and credentials.
- Record uncertainty instead of guessing.

## When This Is Not Enough

Use allowlists, dependency lockfiles, package-signing checks, DNS controls,
network egress policies, and CI gates when an agent can fetch or install
resources. This playbook names the boundary; it does not monitor the internet
or detect real-world phantom squatting.
