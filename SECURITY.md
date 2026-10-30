# Security

Version 0.1.x is the current development line. No independent security audit has
been performed. Scanning is read-only toward target files; inspection and reporting
still process untrusted names, metadata and local system output.

Use GitHub's **Report a vulnerability** button on the repository Security page if
private reporting is available. Otherwise contact the repository owner through an
available private GitHub contact channel before disclosing an exploit. No email
address or response-time guarantee is asserted. A public issue may describe a
non-sensitive symptom, without paths, tokens or exploit details.

Include the revision, OS/execution environment, synthetic reproduction, expected
boundary and observed behavior. Avoid personal reports and raw process arguments.
See [THREAT_MODEL.md](docs/THREAT_MODEL.md) and [PRIVACY.md](docs/PRIVACY.md).

Experimental actions use a separately approved, journaled native macOS Trash boundary. Report approval bypasses, stale-target execution, permanent-delete fallback, unsafe native argument handling or journal replay defects through the same private security channel. See docs/ACTIONS.md for known limits.
