# Validation record

Review date: 2026-10-10. Evidence vocabulary: VERIFIED (executed check or inspected source), OBSERVED (direct observation), INFERRED (reasoned conclusion), HYPOTHESIS, and NOT_VERIFIED.

## Reproducible local checks

Use an unprivileged Linux account and a checkout whose parent path contains no symlink:

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile vex_shadow_audit.py tests/test_audit.py tests/test_regressions.py
```

On hosts that permit unprivileged user and network namespaces:

```sh
unshare --user --map-current-user --net python3 -m unittest discover -s tests -v
```

Optional line-coverage instrumentation, using the standard library:

```sh
python3 -m trace --count --missing --summary --coverdir coverage --module unittest discover -s tests
```

The `--missing` flag matters: percentages computed only from observed lines can overstate coverage. Line coverage is not branch coverage or proof of input completeness.

## Recorded checks on this portfolio candidate

| Check | Classification and result |
| --- | --- |
| Baseline 1.1.0 before preparation | VERIFIED: 55/55 tests passed in a separate critical review. |
| Portfolio suite, Python 3.12.3 | VERIFIED: 55/55 passed, no errors or skips. |
| Portfolio suite in isolated network namespace | VERIFIED: 55/55 passed while preserving a nonzero UID. |
| Module and test syntax | VERIFIED: Python compilation passed. |
| GitHub-hosted workflow | NOT_VERIFIED: configured, awaiting authorized first push and actual runs. |

The first strengthened-test run used an expected error phrase that differed from the runtime's actual contradiction message and failed. The expected phrase was corrected to the specific existing contradiction error; the decision code was unchanged. Both failed runs were retained in private preparation evidence, and the final 55-test runs passed.

## Test scope

The suite contains 55 tests across the original eight cases and 47 subsequent regressions. The portfolio copy improves the original contradiction fixture by providing valid metadata, action and justification fields and asserting the specific contradiction error. This prevents another validation failure from accidentally satisfying that assertion.

Checks include positive/negative precedence, empty repositories, three-repository permutations, all relevant lower-priority candidates, duplicate findings, filtering/non-filtering statuses, version/qualifier direction, case-sensitive and percent-encoded identities, OCI repository separation, aliases, invalid schema fields, nanosecond/offset selection, malformed and oversized JSON, work/collection budgets, missing files, FIFO and symlink rejection, traversal, real permissions, exclusive output creation, rollback, controlled CLI errors, Unicode surrogates, and inert Markdown rendering.

One socket-mock test verifies that the in-process CLI does not open a socket during the patched execution. It does not establish that module import is isolated, nor does it independently block every possible network route. The separate network-namespace execution supports the offline claim for the executed suite. Source inspection also checks the absence of networking/subprocess operations in the runtime.

## Findings retained as engineering evidence

| Historical problem | Regression or engineering response |
| --- | --- |
| Output could overwrite findings or follow a link | Exclusive creation, existing-output/link tests and write-failure cleanup. |
| Whole-PURL lowercasing conflated Maven artifacts | Type-aware normalization and case/encoding regressions. |
| `fixed` was omitted from filtering-status analysis | Positive fixed-shadow and fixed-high-priority negative tests. |
| Invalid data or unsupported context looked like silence | Explicit schema errors and rejection of unsupported formats/context. |
| Nanosecond timestamps were conflated | Integer timestamps and latest-time regressions. |
| Work had only per-file limits | Shared byte/document/comparison/observation budgets. |

The original version's own eight tests passed despite defects. Additional regressions reproduced failures; the corrected suite subsequently passed. During the earlier hardening review, escaping Markdown initially broke an original expected literal; the code was corrected and that failure was preserved in private audit evidence. No earlier failed run is presented as successful.

## Environment and boundaries

The locally tested environment is Linux Mint 22.3 with Python 3.12.3 and a nonzero UID. The prepared workflow schedules Ubuntu with Python 3.10, 3.12 and 3.14; hosted CI results are NOT_VERIFIED until the first authorized push and actual workflow run. No badges assert success in advance.

NOT_VERIFIED: differential execution of Trivy, production datasets, every OpenVEX/PURL form, hostile concurrent filesystem mutation, signature/author authenticity, crash recovery, universal memory/time bounds, and other operating systems. Unsupported input is rejected; it must not be interpreted as an absence of findings.

A separate critical review checks functional behavior, test relevance, claims, privacy and rights. A code-review result is evidence about the scoped candidate, not certification or independent human authorship of the project.
