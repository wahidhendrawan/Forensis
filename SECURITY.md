# Security Policy

## Supported versions

Only the latest release of Forensis gets security fixes. Please check that the problem still exists there before reporting.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository ([direct link](https://github.com/wahidhendrawan/Forensis/security/advisories/new)). Do not open a public issue, discussion or pull request, and do not post exploit details or credentials anywhere public.

Please include:

- the version or commit you tested, and how you deployed it (Docker Compose, bare metal)
- the smallest steps or input that reproduce the problem
- what an attacker gains (data exposure, code execution, privilege escalation, denial of service, …)

Remove real credentials, customer data and sensitive logs from any evidence you share.

You should get a first reply within 7 days. Fixed issues are credited in the release notes unless you ask otherwise.

## In scope

- Authentication, MFA, role or tenant isolation bypass
- Code execution, path traversal or denial of service from uploaded evidence (logs, PCAP, memory dumps, XML, YARA/Sigma rules)
- Server-side request forgery through rule sync or threat-intel lookups
- Secrets or other tenants' data leaking into reports, exports or logs

## Out of scope

- Actions an administrator can already take within their own tenant
- Weaknesses in a deployment that changed the documented defaults (for example exposing OpenSearch or Postgres publicly)

## Safe harbor

Good-faith research that follows this policy will not be treated as a violation of the license or of this policy. Only test against your own deployment, access no more data than needed to show the issue, and do not degrade services for other people.
