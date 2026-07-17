package checks

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

func int32Ptr(v int32) *int32 { return &v }
func int64Ptr(v int64) *int64 { return &v }
func boolPtr(v bool) *bool    { return &v }

func pod(ns, name string, mutate func(*corev1.Pod)) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "registry.example.com/app:v1.2.3"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

func withRequests(p *corev1.Pod) {
	p.Spec.Containers[0].Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
	}
}

func deployment(ns, name, image string, replicas int32) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(replicas),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}},
			},
		},
	}
}

func findMessage(fs []report.Finding, substr string) *report.Finding {
	for i := range fs {
		if strings.Contains(fs[i].Message, substr) {
			return &fs[i]
		}
	}
	return nil
}

func TestIsLatestImage(t *testing.T) {
	cases := map[string]bool{
		"nginx":                        true,
		"nginx:latest":                 true,
		"nginx:1.27":                   false,
		"registry.io:5000/team/app":    true,
		"registry.io:5000/team/app:v1": false,
		"app@sha256:deadbeef":          false,
		"registry.io/team/app:latest":  true,
	}
	for image, want := range cases {
		if got := isLatestImage(image); got != want {
			t.Errorf("isLatestImage(%q) = %v, want %v", image, got, want)
		}
	}
}

func TestNamespaceFindings(t *testing.T) {
	s := &kube.Snapshot{
		Pods: []corev1.Pod{
			pod("payments", "api-1", nil), // missing requests
			pod("payments", "api-2", withRequests),
			pod("payments", "worker-1", func(p *corev1.Pod) {
				withRequests(p)
				p.Status.ContainerStatuses = []corev1.ContainerStatus{{
					RestartCount: 3,
					State:        corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
				}}
			}),
			pod("payments", "pending-1", func(p *corev1.Pod) {
				withRequests(p)
				p.Status.Phase = corev1.PodPending
			}),
		},
		Deployments: []appsv1.Deployment{
			deployment("payments", "api", "registry.io/payments/api:latest", 3),
			deployment("payments", "worker", "registry.io/payments/worker:v2", 1),
		},
	}

	sections := Namespaces(s, []string{"payments"})
	if len(sections) != 1 {
		t.Fatalf("expected 1 namespace section, got %d", len(sections))
	}
	fs := sections[0].Findings

	for _, want := range []string{
		"missing resource requests",
		"CrashLoopBackOff",
		"stuck in Pending",
		`Deployment "api" uses :latest tag`,
		"Missing HorizontalPodAutoscaler",
		"single-replica",
	} {
		if findMessage(fs, want) == nil {
			t.Errorf("expected a finding containing %q, got: %+v", want, messages(fs))
		}
	}
	if f := findMessage(fs, "CrashLoopBackOff"); f != nil && f.Severity != report.SeverityCritical {
		t.Errorf("CrashLoopBackOff should be critical, got %s", f.Severity)
	}
	// Two pods lack requests? Only api-1 does.
	if f := findMessage(fs, "missing resource requests"); f != nil && !strings.HasPrefix(f.Message, "1 Pod ") {
		t.Errorf("expected exactly 1 pod missing requests, got %q", f.Message)
	}
}

func TestSecurity(t *testing.T) {
	s := &kube.Snapshot{
		Pods: []corev1.Pod{
			pod("payments", "root-pod", nil), // no securityContext at all -> root
			pod("payments", "nonroot-pod", func(p *corev1.Pod) {
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(true), RunAsUser: int64Ptr(1000),
				}
			}),
			pod("payments", "priv-pod", func(p *corev1.Pod) {
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: boolPtr(true)}
			}),
			pod("secure", "ok-pod", func(p *corev1.Pod) {
				p.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)}
			}),
		},
		NetworkPolicies: []networkingv1.NetworkPolicy{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "secure", Name: "default-deny"}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "danger"},
			RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "payments", Name: "app-sa"}},
		}},
	}

	sec := Security(s, []string{"payments", "secure"})
	fs := sec.Findings

	// root-pod and priv-pod count as root (privileged has no runAsNonRoot either).
	if f := findMessage(fs, "running as root"); f == nil || !strings.HasPrefix(f.Message, "2 ") {
		t.Errorf("expected 2 containers running as root, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "privileged"); f == nil || f.Severity != report.SeverityCritical {
		t.Errorf("expected critical privileged finding, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "without NetworkPolicies"); f == nil || !strings.Contains(f.Message, "payments") {
		t.Errorf("expected payments flagged without NetworkPolicies, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "cluster-admin"); f == nil || !strings.Contains(f.Message, "payments/app-sa") {
		t.Errorf("expected cluster-admin ServiceAccount finding, got: %+v", messages(fs))
	}
}

func TestMonitoringMissingAlerts(t *testing.T) {
	s := &kube.Snapshot{
		HasServiceMonitorCRD: false,
		Pods: []corev1.Pod{
			pod("monitoring", "prom", func(p *corev1.Pod) { p.Spec.Containers[0].Image = "quay.io/prometheus/prometheus:v2.50.0" }),
			pod("monitoring", "am", func(p *corev1.Pod) { p.Spec.Containers[0].Image = "quay.io/prometheus/alertmanager:v0.27.0" }),
			pod("payments", "redis-0", func(p *corev1.Pod) { p.Spec.Containers[0].Image = "redis:7.2" }),
			pod("payments", "db-0", func(p *corev1.Pod) { p.Spec.Containers[0].Image = "postgres:16" }),
		},
	}
	sec := Monitoring(s, []string{"payments", "monitoring"})
	f := findMessage(sec.Findings, "Missing alerts for")
	if f == nil {
		t.Fatalf("expected missing-alerts finding, got: %+v", messages(sec.Findings))
	}
	if !strings.Contains(f.Message, "Redis") || !strings.Contains(f.Message, "PostgreSQL") {
		t.Errorf("expected Redis and PostgreSQL in %q", f.Message)
	}
}

func TestDisruptionFindings(t *testing.T) {
	labeled := func(d appsv1.Deployment, lbls map[string]string) appsv1.Deployment {
		d.Spec.Template.Labels = lbls
		return d
	}
	spread := func(d appsv1.Deployment) appsv1.Deployment {
		d.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{
			{MaxSkew: 1, TopologyKey: "topology.kubernetes.io/zone"},
		}
		return d
	}
	pdbFor := func(name string, lbls map[string]string, spec policyv1.PodDisruptionBudgetSpec) policyv1.PodDisruptionBudget {
		spec.Selector = &metav1.LabelSelector{MatchLabels: lbls}
		return policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: name},
			Spec:       spec,
		}
	}

	s := &kube.Snapshot{
		Deployments: []appsv1.Deployment{
			// No PDB, no spread constraints -> flagged twice.
			labeled(deployment("payments", "api", "img:v1", 3), map[string]string{"app": "api"}),
			// Covered by a PDB, has spread constraints, but the PDB blocks drains.
			spread(labeled(deployment("payments", "web", "img:v1", 3), map[string]string{"app": "web"})),
			// Single replica: out of scope for disruption checks.
			deployment("payments", "solo", "img:v1", 1),
		},
		StatefulSets: []appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "db"},
			Spec: appsv1.StatefulSetSpec{
				Replicas: int32Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "db"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "db", Image: "img:v1"}}},
				},
			},
		}},
		PDBs: []policyv1.PodDisruptionBudget{
			pdbFor("web-pdb", map[string]string{"app": "web"}, policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
			}),
			// minAvailable == replicas also allows zero disruptions.
			pdbFor("db-pdb", map[string]string{"app": "db"}, policyv1.PodDisruptionBudgetSpec{
				MinAvailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 3},
			}),
		},
	}

	fs := disruptionFindings(s, "payments")

	f := findMessage(fs, "without a PodDisruptionBudget")
	if f == nil || !strings.Contains(f.Message, "api") {
		t.Errorf("expected api flagged without a PDB, got: %+v", messages(fs))
	}
	if f != nil && (strings.Contains(f.Message, "web") || strings.Contains(f.Message, "solo")) {
		t.Errorf("web (covered) and solo (single replica) must not be flagged: %q", f.Message)
	}
	var zeroDisruption []string
	for _, f := range fs {
		if strings.Contains(f.Message, "zero voluntary disruptions") {
			zeroDisruption = append(zeroDisruption, f.Message)
			if f.Severity != report.SeverityWarning {
				t.Errorf("zero-disruption PDB should be a warning, got %s", f.Severity)
			}
		}
	}
	if len(zeroDisruption) != 2 {
		t.Errorf("expected web-pdb and db-pdb flagged as blocking, got: %v", zeroDisruption)
	}
	f = findMessage(fs, "topologySpreadConstraints")
	if f == nil || !strings.Contains(f.Message, "api") || !strings.Contains(f.Message, "db") {
		t.Errorf("expected api and db flagged without spreading, got: %+v", messages(fs))
	}
	if f != nil && strings.Contains(f.Message, "web") {
		t.Errorf("web has spread constraints and must not be flagged: %q", f.Message)
	}
}

func messages(fs []report.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Message
	}
	return out
}
