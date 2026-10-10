# Supported input contract

This contract describes accepted inputs for the diagnostic. It is stricter and narrower than complete OpenVEX/PURL specifications; it is not a full conformance validator.

## Local repositories

`--repo NAME=DIR` is repeated in descending priority order. Names are unique, 1–64 characters from letters, digits, dot, underscore or hyphen. Supply 2–16 repositories.

Each root has `index.json` with a valid timestamp in `updated_at` and an array `packages`. Each entry has a supported PURL in `id`, a safe relative `location`, and either no `format` or `format: openvex`. CSAF and unknown formats are rejected because skipping them would alter priority. Duplicate canonical index identities are errors.

Document locations use forward slashes and reject absolute paths, empty segments, `.`, `..`, backslashes, control characters and symlinks. The tool consumes unpacked files and does not retrieve manifests or extract archives.

For ordinary package types, index IDs omit version, qualifiers and subpath. OCI requires exactly `repository_url` as its index qualifier, identifying the repository independently of a version or digest.

## Findings

A findings file is an array containing at most 10,000 objects, each with exactly `purl` and `vulnerability`. The latter must match the accepted `CVE-year-number` syntax. These syntax checks do not confirm that a CVE exists or applies.

The format intentionally lacks scanner product/subcomponent context and does not accept raw scanner JSON or SBOM formats. Duplicate findings retain their indices and can generate duplicate observations.

## OpenVEX profile

Opened documents require:

- Exact context `https://openvex.dev/ns/v0.2.0`.
- A nonempty absolute document `@id`, nonempty `author`, valid `timestamp`, positive integer `version`, and a bounded `statements` array.
- Each statement requires a vulnerability name or identifier, nonempty products, a valid status and an explicit or inherited valid timestamp.
- `not_affected` requires an allowed justification or a nonempty impact statement. `affected` requires a nonempty action statement.
- Products need a PURL in `@id` or `identifiers.purl`. An additional IRI `@id` may coexist with that PURL.

Names, aliases and identifiers are matched as documented in architecture.md. Products without PURLs, nonempty or incorrectly typed subcomponents, unsupported package types and PURL subpaths fail explicitly. CPE/hash-only matching is unsupported. Empty subcomponent arrays are accepted. Fields not used for decisions are not a substitute for independent full-schema validation. Authors and signatures are not authenticated.

Supported package types: `deb`, `apk`, `rpm`, `npm`, `maven`, `generic`, `pypi`, `golang`, `oci`. Names/versions are normalized only according to the implemented profile, not every ecosystem rule. Versions match exactly; qualifiers are directional subsets. Text is bounded and rejects control characters and unpaired surrogates. Malformed percent encodings and duplicate qualifiers are rejected.

Timestamps require an uppercase `T`, a timezone `Z` or numeric offset, and at most nine fractional digits. Naive timestamps and leap seconds are rejected. Latest-time contradictions are errors. This conservative policy is not necessarily how another VEX consumer resolves a tie.

## Resource limits

| Budget | Limit |
| --- | ---: |
| Bytes in one JSON input | 2,000,000 |
| Bytes read across an audit | 16,000,000 |
| JSON nesting depth | 64 |
| Findings | 10,000 |
| Index packages per repository | 20,000 |
| Statements per opened document | 20,000 |
| Products across one document | 20,000 |
| Repositories | 16 |
| Opened documents across repositories | 128 |
| Product comparisons | 1,000,000 |
| Observations | 10,000 |

Byte limits are decimal, not MiB. Limits are checked explicitly; exceeding one fails the audit and produces no successful verdict. Split large datasets. They are not guarantees of a universal RSS or wall-clock bound.

Only documents referenced by supplied findings are opened. The program therefore validates neither all documents nor the completeness of an entire repository. Reports explicitly leave unreferenced documents NOT_VERIFIED.

## Output contract

JSON includes `version`, `profile`, `evidence_classification`, repository order, findings checked, observations, assessments, summary and resource counters. `summary` counts observations, not unique packages or CVEs. Every finding's chain records index presence, status and reason.

Output paths must be distinct new files in existing, stable directories. Existing files and links are refused. Output files are mode 0600. Ordinary failure cleanup does not guarantee recovery after a forced process termination or power loss.
