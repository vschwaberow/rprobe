# Security Policy

We take the security of rprobe seriously. Thank you for taking the time to responsibly disclose vulnerabilities.

## Reporting a Vulnerability

- Please do not file public GitHub issues for security vulnerabilities.
- Send a report to: volker@schwaberow.de
  - Optionally request a PGP key if you prefer encrypted communication.
- Include the following (as applicable):
  - A clear vulnerability description and potential impact
  - A minimal proof‑of‑concept (PoC) or steps to reproduce
  - Affected version/commit, platform, and configuration
  - Whether the issue is already public
  - Your preferred contact method and disclosure timeline preferences

We will acknowledge receipt within 72 hours and keep you informed of progress.

## Coordinated Disclosure & Timelines

- Triage and initial assessment: within 7 days
- Fix development and validation: based on severity and complexity
  - Critical/High: aim for 14–30 days
  - Medium/Low: aim for 30–60 days
- Public advisory: after a fix is available and users have a reasonable update window, coordinated with the reporter when possible

If a vulnerability is being actively exploited, we may expedite releases and communication.

## Scope & Safe Testing

rprobe is a security testing tool. When researching issues:

- Only test systems you own or are explicitly authorized to assess
- Follow applicable laws, terms of service, and ethical guidelines
- Avoid causing harm (e.g., excessive traffic, data exfiltration, service disruption)

We support good‑faith research and coordinated disclosure. Reports made in good faith will not result in legal action from project maintainers.

## Non‑Qualifying Issues (examples)

- Vulnerabilities requiring privileged local access that are out of project control
- Best‑practice disagreements without a concrete, actionable risk
- Vulnerabilities exclusively in third‑party dependencies (please report upstream). If they affect rprobe materially, feel free to notify us as well.

## Fixes, Releases, and Advisories

- Security fixes are released as normal versions and documented in `CHANGELOG.md`
- When appropriate, we will publish a security advisory summarizing the issue and mitigation steps
- Users are encouraged to keep rprobe up to date with the latest releases

## Contact & Updates

- Primary contact: volker@schwaberow.de
- For general questions that are not security‑sensitive, use regular GitHub issues

Thank you for helping keep the community safe.

