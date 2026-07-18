# Cluster Guardian

[![Build Status][actions-badge]][actions-url]
[![Go Reference][godoc-badge]][godoc-url]
[![Release][release-badge]][release-url]
[![License: MIT][license-badge]][license-url]

[actions-badge]: https://github.com/AndrewKarpaty/cluster-guardian/actions/workflows/ci.yml/badge.svg
[actions-url]: https://github.com/AndrewKarpaty/cluster-guardian/actions/workflows/ci.yml
[godoc-badge]: https://pkg.go.dev/badge/github.com/AndrewKarpaty/cluster-guardian.svg
[godoc-url]: https://pkg.go.dev/github.com/AndrewKarpaty/cluster-guardian
[release-badge]: https://img.shields.io/github/v/release/AndrewKarpaty/cluster-guardian?include_prereleases
[release-url]: https://github.com/AndrewKarpaty/cluster-guardian/releases
[license-badge]: https://img.shields.io/badge/License-MIT-blue.svg
[license-url]: LICENSE

Cluster Guardian is an open-source tool that analyzes Kubernetes clusters and provides actionable recommendations for improving reliability, security, performance, and operational efficiency.

```
✔ Cluster: production

⚠ Namespace: payments
  • 5 Pods missing resource requests
  • 2 CrashLoopBackOff containers
  • Deployment "api" uses :latest tag
  • Missing HorizontalPodAutoscaler

⚠ Security
  • 8 containers running as root
  • 3 namespaces without NetworkPolicies

⚠ Monitoring
  • 4 Services are not scraped by Prometheus
  • Missing alerts for Redis and PostgreSQL

💰 Optimization
  • Estimated CPU overprovisioning: 68%
  • Estimated Memory overprovisioning: 41%
```

## Features

* Cluster health analysis
* Workload validation (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs)
* Resource optimization using Prometheus metrics
* Detection of unhealthy workloads (CrashLoopBackOff, Pending, ImagePullBackOff, OOMKilled, restart storms)
* Identification of missing CPU/Memory requests and limits
* Readiness, Liveness, and Startup Probe validation
* PodDisruptionBudget coverage and topology spread validation
* Unused resource detection (ConfigMaps, Secrets, PVCs, Services without pods, dangling Ingress/HPA/PDB targets)
* TLS certificate checks (Ingress certificates near expiry, missing TLS secrets, cert-manager Certificate readiness)
* Deprecated API detection (kubent-style, severity based on the cluster's version)
* Security checks (root containers, privileged pods, dangerous capabilities, host namespaces, RBAC, Network Policies)
* Pod Security Standards compliance summary (`--framework pss` shows only PSS-mapped findings)
* Monitoring validation (Prometheus, Alertmanager, ServiceMonitors, PodMonitors, PrometheusRules)
* Argo CD / Flux health integration
* Cost optimization recommendations
* Automatic cluster documentation generation
* Export reports in JSON, Markdown, and HTML
* REST API and Web Dashboard
* CLI for automation and CI/CD integration

## Installation

```sh
go install github.com/AndrewKarpaty/cluster-guardian@latest
```

Or build from source:

```sh
git clone https://github.com/AndrewKarpaty/cluster-guardian.git
cd cluster-guardian
go build -o cluster-guardian .
```

### Docker

```sh
docker build -t cluster-guardian .

# CLI: analyze using your local kubeconfig
docker run --rm -v ~/.kube:/kube:ro -e KUBECONFIG=/kube/config cluster-guardian

# Dashboard: bind to 0.0.0.0 so the published port is reachable
docker run --rm -p 8080:8080 -v ~/.kube:/kube:ro -e KUBECONFIG=/kube/config \
  cluster-guardian serve --listen 0.0.0.0:8080
```

When running in-cluster (e.g. as a Deployment for the dashboard), no kubeconfig is needed — the ServiceAccount token is picked up automatically.

## Usage

Analyze the cluster from your current kubeconfig context:

```sh
cluster-guardian
```

Common options:

```sh
cluster-guardian analyze \
  --context production \                    # kubeconfig context
  -n payments -n checkout \                 # limit to specific namespaces
  --prometheus-url http://localhost:9090 \  # enable usage-based cost analysis
  --verbose                                 # show remediation hints for each finding
```

If Prometheus is not exposed outside the cluster, port-forward it first:

```sh
kubectl port-forward -n monitoring svc/prometheus-operated 9090:9090
cluster-guardian --prometheus-url http://localhost:9090
```

### Export reports

```sh
cluster-guardian analyze -o json     --output-file report.json
cluster-guardian analyze -o markdown --output-file report.md
cluster-guardian analyze -o html     --output-file report.html
```

### Cluster documentation

Generate Markdown documentation of workloads, services, and ingresses:

```sh
cluster-guardian docs --output-file CLUSTER.md
```

### Web dashboard and REST API

```sh
cluster-guardian serve --listen 127.0.0.1:8080
```

The dashboard supports filtering by severity and namespace, free-text search,
collapsible sections, an auto-refresh toggle, and JSON/Markdown download
buttons. Filtering and search also work in `-o html` file exports.

| Endpoint                   | Description                                      |
|----------------------------|--------------------------------------------------|
| `GET /`                    | Web dashboard (HTML report)                      |
| `GET /api/report`          | Report as JSON (`?refresh=true` bypasses cache)  |
| `GET /api/report/markdown` | Report as Markdown                               |
| `GET /healthz`             | Liveness probe                                   |

### CI/CD integration

Use `--fail-on` to gate pipelines on findings:

```sh
cluster-guardian analyze --fail-on critical   # exit code 3 on critical findings
cluster-guardian analyze --fail-on warning    # exit code 2 on warnings or worse
```

## Checks

| Area         | What is checked                                                                                     |
|--------------|-----------------------------------------------------------------------------------------------------|
| Workloads    | Missing resource requests/limits, `:latest` tags, missing probes, single replicas, missing HPAs, missing or drain-blocking PodDisruptionBudgets, missing topology spread |
| Health       | CrashLoopBackOff, ImagePullBackOff, Pending pods, OOMKilled containers, restart storms               |
| Security     | Root/privileged containers, dangerous capabilities, host network/PID/IPC, namespaces without NetworkPolicies, wildcard ClusterRoles, cluster-admin ServiceAccounts; findings are tagged with Pod Security Standards controls and summarized per framework |
| Monitoring   | Prometheus/Alertmanager presence, ServiceMonitor scrape coverage, missing alerts for Redis, PostgreSQL, Kafka, and other stateful services |
| Hygiene      | Unused ConfigMaps and Secrets, unmounted or unbound PVCs, Services matching no pods, Ingress paths to missing Services, HPAs targeting missing workloads, PDBs selecting nothing |
| Certificates | Ingress TLS certificates expiring within 30 days (critical under 7), Ingresses referencing missing TLS secrets, cert-manager Certificates not Ready |
| Deprecations | Objects still written with deprecated API versions (from managedFields / last-applied), critical when the API is removed in the next minor version or earlier |
| GitOps       | Argo CD Application health and sync status, Flux Kustomization/HelmRelease readiness                 |
| Optimization | CPU and memory overprovisioning, estimated from requests vs. actual usage in Prometheus              |

System namespaces (`kube-system`, etc.) are skipped by default; include them with `--include-system`.

## Requirements

- Kubernetes 1.25+ with read-only access (a `view`-like ClusterRole covers most checks; RBAC checks additionally need read access to ClusterRoles and ClusterRoleBindings, and Secret hygiene checks need list access to Secrets — only names and types are read, secret data is never held. Checks whose resources are not readable are skipped silently.)
- Optional: Prometheus for usage-based optimization checks
- Optional: Prometheus Operator, Argo CD, Flux, or cert-manager CRDs — detected automatically

## License

MIT — see [LICENSE](LICENSE).
