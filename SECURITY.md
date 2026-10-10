# Security policy

## Scope and supported version

Only the current 1.1.x repository version is under review. There is no support SLA. This is a local diagnostic; its output never establishes vulnerability exploitability or authorizes suppression. No third-party infrastructure testing is part of the project.

Run as an unprivileged Linux user with private, stable input and output directories. Input datasets and reports may contain sensitive identifiers. Do not submit credentials, confidential VEX documents, customer data, or identifying local paths in issues or pull requests.

## Reporting a suspected flaw

If the repository's GitHub **Security → Report a vulnerability** control is available, use it for a private report. Private vulnerability reporting must be enabled by the repository owner; its availability is not asserted before publication.

If that control is unavailable, open a minimal issue asking for a private reporting channel, without exploit detail, sensitive attachments, or identifying data. There is no published private mailbox and no guaranteed response time.

Use a minimized synthetic local fixture. Include the affected revision, Python/Linux versions, expected and observed behavior, and whether files outside the fixture were accessed or modified. Avoid tests against third-party repositories or services.

## Trust and safety boundaries

Input parsing is bounded and schema decisions fail explicitly. Read paths reject symlinks using descriptor-based opens; report destinations are created exclusively. These measures assume directories controlled by the caller. Hostile concurrent mutation, hard-link provenance, signature/author verification, immutable snapshots, crash-atomic report pairs, and all resource-exhaustion scenarios remain unverified.

The program performs no network or subprocess operations. The tests use subprocesses only to check local CLI behavior. GitHub Actions necessarily retrieves its checkout and Python runtime; that is separate from the tool's offline execution contract.
