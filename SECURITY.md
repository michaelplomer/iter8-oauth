# Security policy

iter8-oauth is an authorization server, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Please do not open a public issue, pull request or discussion for a suspected
vulnerability.

A useful report says which module is affected (`cimd`, `token`, `oauth-core`, `resource-server` or `as-app`),
the version or commit, how to reproduce the problem, and what an attacker could achieve with it.

This is maintained by one person in their spare time. You can expect an acknowledgement within a week, and an
estimate for a fix once the report is understood. Please allow time for a fix to be released before disclosing
the issue publicly.

## Supported versions

The project is at `0.x`. Only the latest release and the `main` branch receive security fixes.

## Known limitations

Some limits are documented rather than fixed, for example that state is held in memory and that the server
does no rate limiting of its own. The README lists them under "Security model and limits". Reports about those
are still welcome when they show a consequence the README does not describe.
