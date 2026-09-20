# Security Policy

## Supported versions

Only the latest published Decibel release receives security fixes. Older
releases, pre-releases, and the unreleased `main` branch are not supported
release lines. A security fix may require upgrading to a new release.

Reports against `main` are welcome even though it is not a supported release,
especially when the issue also affects the latest published release.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's
[private vulnerability reporting form](https://github.com/ausimian/decibel/security/advisories/new).
Include:

- affected Decibel, Elixir, and Erlang/OTP versions;
- the Noise protocol name, role, key configuration, and relevant transport
  assumptions;
- a minimal reproduction or proof of concept;
- the expected security property and observed impact; and
- any known workaround or proposed mitigation.

The maintainer will coordinate investigation, remediation, and disclosure
through the private advisory. No response-time or remediation SLA is promised.

If GitHub reports that private vulnerability reporting is unavailable, do not
publish the report as an issue. The repository owner must enable the private
reporting feature before this policy provides a private contact route.
