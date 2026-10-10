# Contributing

Keep changes small, defensive, and reproducible with synthetic local fixtures. Do not add automatic vulnerability suppression, remote scanning, telemetry, credential handling, or networking to the runtime without a separately reviewed design change.

## Local checks

Use Linux, Python 3.10 or later, and an unprivileged account:

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile vex_shadow_audit.py tests/test_audit.py tests/test_regressions.py
```

No third-party test packages are required. Permission tests deliberately fail when run as UID 0. A configured CI Python version is not verified until that job actually passes.

Add a regression fixture for behavior changes. Assert the specific failure condition where possible, so an unrelated schema error cannot make the test pass. Do not weaken existing assertions to obtain a green result. Keep fixtures self-contained and non-sensitive.

Document any change to matching rules, validation strictness, input formats, budgets or exit behavior. Distinguish VERIFIED execution/source evidence, OBSERVED facts, INFERRED conclusions, HYPOTHESIS, and NOT_VERIFIED limitations. Tests that match an implementation are insufficient evidence of full scanner compatibility.

Describe the problem, resulting behavior, relevant limitations, and commands actually run in a pull request. Do not claim discovery credit, upstream authorship, endorsements, or checks performed by someone else.

Submitting a contribution does not permit third-party code with incompatible terms. Contributions must be yours to license under this repository's MIT License; preserve required attribution. Follow SECURITY.md for sensitive findings.
