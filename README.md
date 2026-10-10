# VEX Shadow Audit

An offline Python diagnostic for investigating **VEX repository precedence**. Given local OpenVEX repositories and a curated list of vulnerability findings, it identifies candidate silent shadows and priority/status disagreements without suppressing findings or modifying VEX data.

This is a defensive engineering portfolio project about a **known public behavior**. It is neither a new vulnerability disclosure nor an official Trivy fix. It does not assess whether a vulnerability is exploitable.

## The problem

A repository index routes a package to a VEX document. That document may contain no applicable statement for a particular vulnerability or package version. A precedence policy that stops at the first indexed package can leave relevant statements in later repositories unexamined.

The implementation models that package-level policy for a deliberately limited input profile. It keeps these cases separate:

| Result | Meaning in this model |
| --- | --- |
| `SILENT_SHADOW` | The first indexed repository has no applicable statement, while a later repository has `not_affected` or `fixed`. |
| `STATUS_CONFLICT_REVIEW` | The first indexed repository has `affected` or `under_investigation`, while a later repository has one of those two filtering statuses. This can be an intentional priority decision. |

Both are **INFERRED candidates for manual review**, not instructions to suppress. Every relevant lower-priority repository is reported, so counts represent observations rather than unique CVEs. Two filtering statuses are not labeled as a disagreement by this diagnostic.

## Quick start

Linux and Python 3.10 or newer are required. The verified local environment is Linux Mint 22.3 with Python 3.12.3. The runtime uses only the Python standard library: no pip installation, network access, credentials, or privileged execution is required.

From a local checkout:

```sh
python3 vex_shadow_audit.py \
  --repo high=examples/repo_high \
  --repo low=examples/repo_low \
  --findings examples/findings.json \
  --json-out report.json \
  --markdown-out report.md
```

Expected output:

```text
Checked 3 findings; 1 silent shadows; 1 conflicts
```

Destinations must be **new files** in existing directories. Successful execution returns 0; invalid input, unsupported context, resource-limit violations, or output errors return 2. Files are created with mode 0600. Use new report names when repeating a run.

All example data is synthetic, with fictional vulnerability identifiers and `example.invalid` document identifiers. It represents no incident or assertion about an actual package.

## Inputs and outputs

Supply 2–16 unpacked local repositories in descending priority order. Each has an `index.json` with `updated_at` and `packages` entries containing `id`, relative `location`, and optional `format: openvex`. Version, qualifiers, and subpath are omitted from index IDs, except the required OCI `repository_url` qualifier.

Findings use a curated JSON array with exactly these fields:

```json
[{"purl":"pkg:deb/debian/perl-base@1?arch=amd64","vulnerability":"CVE-2099-10001"}]
```

OpenVEX documents must use the v0.2.0 context and the supported fields described in [the input contract](docs/input-contract.md). This tool does not consume native scanner JSON, an SBOM, container images, or Trivy configuration.

The JSON report includes observations, resource counters and a per-finding repository chain. Reasons distinguish `NOT_INDEXED`, `NO_VULNERABILITY_STATEMENT`, `NO_APPLICABLE_PRODUCT`, and `APPLICABLE_STATEMENT`. The Markdown report presents candidate observations for human review. Unreferenced documents remain **NOT_VERIFIED**.

## Architecture

A single auditable runtime module separates file handling, parsing and matching, repository lookup, and report generation. Documents are validated before matching, compiled by vulnerability identifier, and cached for repeated queries. Exact timestamps retain nanoseconds. A shared budget bounds input bytes, opened documents, comparisons, and observations.

See [architecture and decision rules](docs/architecture.md) for the functions and processing flow.

## Security boundaries

The runtime rejects symlinks while opening every path component through directory descriptors, requires regular input files, and restricts document locations to safe relative paths. It rejects duplicate JSON keys, excessive nesting, invalid UTF-8, surrogate text and nonstandard numeric constants. Output files use exclusive creation; ordinary write failures trigger cleanup. External report values are escaped for HTML and Markdown.

Run as an unprivileged user in private directories that remain stable during the audit. These checks do not establish immutable input snapshots, protect against all hostile concurrent changes, validate VEX signatures, or make two report files an atomic transaction across crashes. Reports can reveal supplied package identifiers; treat them according to your input's sensitivity. See [SECURITY.md](SECURITY.md).

## Tests and evidence

```sh
python3 -m unittest discover -s tests -v
```

The 55-test baseline was rechecked before portfolio preparation. The portfolio suite retains the same count and strengthens an original contradiction test so it reaches the actual decision rule. Tests exercise precedence permutations, version and qualifier matching, case-sensitive Maven identity, OCI repository identity, aliases, duplicate and conflicting statements, timestamps, malformed inputs, resource limits, symlinks, permissions, existing outputs and rollback.

Recorded local results and reproducible commands are in [validation](docs/validation.md). A [GitHub Actions workflow](.github/workflows/tests.yml) is prepared for Linux with Python 3.10, 3.12 and 3.14. A configured matrix is not evidence that those hosted jobs have passed; no CI status badge is claimed before an actual run.

## Relationship to Trivy

[Trivy issue #11081](https://github.com/aquasecurity/trivy/issues/11081) describes the same package-level shadow mechanism. [PR #11082](https://github.com/aquasecurity/trivy/pull/11082) proposes applying precedence only when an applicable statement exists. The model here was checked against [Trivy v0.73.0 repository code](https://github.com/aquasecurity/trivy/blob/v0.73.0/pkg/vex/repo.go) and its OpenVEX consumer, rather than inferred solely from a test suite.

This project observes candidate consequences in local exports; it does not apply the upstream patch or change Trivy. It makes **no claim of runtime parity** with Trivy. Upstream status and behavior may change; confirm the scanner version and actual context before acting on an observation. [References](docs/references.md) record the version boundaries.

## Limitations

The supported PURL types are `deb`, `apk`, `rpm`, `npm`, `maven`, `generic`, `pypi`, `golang`, and `oci`. This is not a universal PURL or JSON-LD validator. CSAF, unsupported PURL types, PURL subpaths, nonempty subcomponent context, products without a PURL, and ambiguous alias histories are rejected rather than silently skipped. Matching and normalization cover the declared profile, not every ecosystem corner case.

Limits include 2 MB per JSON file, 16 MB total input, depth 64, 10,000 findings, 20,000 index entries/statements/products per respective file, 128 documents, 1,000,000 comparisons, and 10,000 observations. Exceeding a limit fails the audit; split the batch. These budgets are not universal RAM or wall-clock guarantees.

Production datasets, adversarial concurrency, complete scanner equivalence, signatures, and other operating systems have not been verified. Full technical boundaries are in [the input contract](docs/input-contract.md).

## Engineering demonstrated

The repository provides inspectable examples of typed Python and standard-library design, defensive file I/O, bounded parsing, conservative security decisions, regression and adversarial testing, specification/source review, and explicit separation of evidence from inference. Its research concerns a documented behavior, with no claim of discovery credit or upstream contribution.

## License and contributions

MIT; see [LICENSE](LICENSE), [NOTICE](NOTICE), and [provenance](docs/provenance.md). This repository is intended for public technical study and portfolio review, not a commercial product offer. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules.
