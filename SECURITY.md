# Security policy

Metis is intentionally exposed to hostile network input, so parser escapes and containment failures are treated seriously.

## Supported versions

Until the project reaches a stable release, security fixes are made on the default branch and the most recent tagged release only. Older `0.x` revisions may not receive backports.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

When this repository is public, use GitHub's **Security** tab and select **Report a vulnerability** to submit a private report. If private vulnerability reporting is not available, open a minimal issue asking the maintainer for a private contact channel without including technical details.

Include, where possible:

- the affected revision and deployment mode;
- a minimal reproducer or packet sequence;
- expected and observed behavior;
- impact and realistic preconditions; and
- whether the issue is already public or under active exploitation.

You should receive an acknowledgement within seven days. Timelines for validation, remediation, and disclosure depend on severity and reproducibility. Please allow a reasonable remediation window before public disclosure.

## Security-relevant scope

Examples include:

- memory, resource-exhaustion, or parser vulnerabilities reachable from the network;
- execution of submitted SQL, commands, binaries, paths, or network destinations;
- a way for the service identity to initiate outbound connections despite the documented boundary;
- traversal or overwrite outside configured telemetry and payload directories;
- exposure of deployment secrets or unintended credential material; and
- authentication or protocol behavior that materially defeats the documented deception controls.

General deployment-hardening questions, Internet scan noise, and attacker data already captured through explicitly enabled telemetry are not vulnerabilities by themselves.
