# Contributing to Cluster Guardian

Thanks for your interest in contributing!

## Development setup

You need Go (version pinned in [`.go-version`](.go-version)) and access to a Kubernetes cluster for manual testing — [kind](https://kind.sigs.k8s.io/) or minikube work fine.

```sh
git clone https://github.com/AndrewKarpaty/cluster-guardian.git
cd cluster-guardian
make build          # build ./cluster-guardian
make test           # go test -race ./...
make lint           # golangci-lint run (install: https://golangci-lint.run/welcome/install/)
```

Run against your current kubeconfig context:

```sh
./cluster-guardian analyze --verbose
```

## Making changes

1. Fork the repo and create a branch from `main`.
2. Make your change. Checks live in `internal/checks` and are pure functions over a `kube.Snapshot` — add tests with synthetic snapshots (see `internal/checks/checks_test.go`); no cluster or mocks needed.
3. Ensure `make test` and `make lint` pass.
4. Open a pull request — the template will guide you. Reference any related issue.

Keep pull requests focused: one logical change per PR is much easier to review.

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/AndrewKarpaty/cluster-guardian/issues/new/choose). For security vulnerabilities, see [SECURITY.md](SECURITY.md) — please do not open a public issue.
