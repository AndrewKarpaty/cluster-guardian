// Package analyzer orchestrates the cluster snapshot and all checks into a
// single Report.
package analyzer

import (
	"context"
	"time"

	"github.com/AndrewKarpaty/cluster-guardian/internal/checks"
	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// Options control the scope of an analysis run.
type Options struct {
	// Namespaces limits the analysis; empty means all non-system namespaces.
	Namespaces []string
	// IncludeSystem also analyzes kube-system and friends.
	IncludeSystem bool
	// PrometheusURL enables usage-based optimization checks when set.
	PrometheusURL string
	// ClusterName overrides the display name (defaults to the kube context).
	ClusterName string
}

// Run collects a snapshot and produces the full report.
func Run(ctx context.Context, client *kube.Client, opts Options) (*report.Report, error) {
	snapshot, err := client.Collect(ctx, opts.Namespaces)
	if err != nil {
		return nil, err
	}
	r := Analyze(ctx, snapshot, opts)
	if r.ClusterName == "" {
		r.ClusterName = client.Context
	}
	r.Context = client.Context
	return r, nil
}

// Analyze runs every check over an existing snapshot. Split from Run so tests
// can feed synthetic snapshots.
func Analyze(ctx context.Context, snapshot *kube.Snapshot, opts Options) *report.Report {
	namespaces := snapshot.AppNamespaces(opts.IncludeSystem, opts.Namespaces)

	r := &report.Report{
		ClusterName:       opts.ClusterName,
		KubernetesVersion: snapshot.ClusterVersion,
		GeneratedAt:       time.Now().UTC(),
		Namespaces:        checks.Namespaces(snapshot, namespaces),
		Sections: []report.Section{
			checks.Security(snapshot, namespaces),
			checks.Monitoring(snapshot, namespaces),
			checks.Certificates(snapshot, namespaces),
			checks.Deprecations(snapshot, namespaces),
			checks.GitOps(snapshot),
			checks.Optimization(ctx, snapshot, namespaces, opts.PrometheusURL),
		},
	}
	r.Finalize()
	return r
}
