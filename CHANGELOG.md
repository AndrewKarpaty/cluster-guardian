# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
