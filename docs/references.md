# Technical references

Public sources were reviewed on 2026-10-10. No third-party implementation or patch is distributed here. Source review establishes what a specified source does, not runtime equivalence with an installed scanner.

| Source | Use and boundary |
| --- | --- |
| [Trivy v0.73.0 repository consumer](https://github.com/aquasecurity/trivy/blob/v0.73.0/pkg/vex/repo.go) | VERIFIED by source inspection: lookup by indexed package and stop after the first matching repository. |
| [Trivy v0.73.0 OpenVEX consumer](https://github.com/aquasecurity/trivy/blob/v0.73.0/pkg/vex/openvex.go) | VERIFIED by source inspection: selected latest statement can filter `not_affected` or `fixed`. |
| [Trivy v0.73.0 dependency manifest](https://github.com/aquasecurity/trivy/blob/v0.73.0/go.mod) | Pins the examined consumer dependencies: go-vex v0.2.7 and packageurl-go v0.1.6. These are references, not Python dependencies. |
| [go-vex v0.2.7 matching](https://github.com/openvex/go-vex/blob/v0.2.7/pkg/vex/vex.go) and [statement ordering](https://github.com/openvex/go-vex/blob/v0.2.7/pkg/vex/statement.go) | Directional PURL comparison and history ordering. Unsupported subpaths and ambiguous primary-name histories are declined by this project. |
| [packageurl-go v0.1.6](https://github.com/package-url/packageurl-go/blob/v0.1.6/packageurl.go) | Consumer normalization reference; no claim of passing the entire upstream corpus. |
| [Aqua VEX Repository Specification v0.1](https://github.com/aquasecurity/vex-repo-spec) | Index layout and OCI repository identity. Distribution manifests are outside this tool's input profile. |
| [OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | Document and statement decision fields; the project supports the v0.2.0 context and a restricted subset. This link is mutable. |
| [Trivy issue #11081](https://github.com/aquasecurity/trivy/issues/11081) | KNOWN_PUBLIC report of the same shadow mechanism. Its existence does not give this project discovery credit. |
| [Trivy PR #11082](https://github.com/aquasecurity/trivy/pull/11082) | KNOWN_PUBLIC proposal changing statement precedence. Observed open and unmerged at review time; no upstream patch/tests were executed here. |
| [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use) | Least privilege and immutable action references in the prepared workflow. |

Before drawing a scanner-specific conclusion, verify its actual version, full product/subcomponent context, supported document formats, and current upstream behavior. Neither public issue claims nor local Python tests independently reproduce the reporter's production incident.
