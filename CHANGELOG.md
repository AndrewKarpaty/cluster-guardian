# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Pod Security Standards compliance mapping: security findings are tagged with the PSS controls they violate, the Security section reports how many observable controls pass, and `--framework pss` filters the report to compliance-relevant findings (#30)
- Unused and orphaned resource detection: unused ConfigMaps/Secrets (with auto-generated ones excluded), unmounted and unbound PVCs, Services matching no pods, Ingress paths routing to missing Services, HPAs targeting missing workloads, and PDBs selecting nothing (#29). Secret contents are stripped at collection time; only names and types are kept.
- Certificates section: Ingress TLS certificates expiring within 30 days (critical under 7 days or already expired), Ingresses referencing missing TLS secrets, and cert-manager Certificate resources that are not Ready, detected via the optional-CRD pattern (#22). Only the public `tls.crt` of TLS secrets is retained in memory.

### Changed

- Removed the deprecated Go Report Card badge from the README

## [0.1.0] - 2026-07-17

### Added

- Cluster analysis CLI: workload, health, security, monitoring, GitOps, and cost optimization checks
- PodDisruptionBudget and topology spread checks: multi-replica workloads without a PDB, PDBs that allow zero voluntary disruptions, and workloads without topologySpreadConstraints or pod anti-affinity (#16)
- Report export in JSON, Markdown, and HTML
- Web dashboard and REST API (`serve`)
- Cluster documentation generation (`docs`)
- `--fail-on` exit-code gating for CI/CD
- Dockerfile (distroless, non-root)
- CI, release automation (GoReleaser + GHCR image), linting, and Dependabot
