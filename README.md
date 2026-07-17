# Cluster Guardian

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
* Security checks (root containers, privileged pods, dangerous capabilities, host namespaces, RBAC, Network Policies)
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
| Workloads    | Missing resource requests/limits, `:latest` tags, missing probes, single replicas, missing HPAs      |
| Health       | CrashLoopBackOff, ImagePullBackOff, Pending pods, OOMKilled containers, restart storms               |
| Security     | Root/privileged containers, dangerous capabilities, host network/PID/IPC, namespaces without NetworkPolicies, wildcard ClusterRoles, cluster-admin ServiceAccounts |
| Monitoring   | Prometheus/Alertmanager presence, ServiceMonitor scrape coverage, missing alerts for Redis, PostgreSQL, Kafka, and other stateful services |
| GitOps       | Argo CD Application health and sync status, Flux Kustomization/HelmRelease readiness                 |
| Optimization | CPU and memory overprovisioning, estimated from requests vs. actual usage in Prometheus              |

System namespaces (`kube-system`, etc.) are skipped by default; include them with `--include-system`.

## Requirements

- Kubernetes 1.25+ with read-only access (a `view`-like ClusterRole covers most checks; RBAC checks additionally need read access to ClusterRoles and ClusterRoleBindings)
- Optional: Prometheus for usage-based optimization checks
- Optional: Prometheus Operator, Argo CD, or Flux CRDs — detected automatically

## License

MIT — see [LICENSE](LICENSE).
