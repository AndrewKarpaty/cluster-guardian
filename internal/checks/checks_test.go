package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

	// PSS mapping: privileged and run-as-root fail, host namespaces and
	// capabilities pass -> 2 of 4.
	if f := findMessage(fs, "privileged"); f == nil || len(f.Controls) == 0 || f.Controls[0] != "PSS/baseline:privileged" {
		t.Errorf("privileged finding should be tagged with its PSS control, got: %+v", f)
	}
	f := findMessage(fs, "Pod Security Standards")
	if f == nil {
		t.Fatalf("expected a PSS compliance summary, got: %+v", messages(fs))
	}
	if !strings.Contains(f.Message, "2 of 4") ||
		!strings.Contains(f.Message, "Privileged Containers") ||
		!strings.Contains(f.Message, "Running as Non-root") {
		t.Errorf("unexpected PSS summary: %q", f.Message)
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

func TestUnusedFindings(t *testing.T) {
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Namespace: "payments", Name: name}
	}
	s := &kube.Snapshot{
		Pods: []corev1.Pod{
			pod("payments", "api-1", func(p *corev1.Pod) {
				p.Labels = map[string]string{"app": "api"}
				p.Spec.Volumes = []corev1.Volume{
					{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}}}},
					{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: "data-pvc"}}},
				}
				p.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{
					{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "app-secret"}}},
				}
			}),
		},
		ConfigMaps: []corev1.ConfigMap{
			{ObjectMeta: meta("app-config")},       // referenced via volume
			{ObjectMeta: meta("old-config")},       // unused
			{ObjectMeta: meta("kube-root-ca.crt")}, // auto-generated, never flagged
		},
		Secrets: []corev1.Secret{
			{ObjectMeta: meta("app-secret")},                                           // referenced via envFrom
			{ObjectMeta: meta("stale-secret")},                                         // unused
			{ObjectMeta: meta("sa-token"), Type: corev1.SecretTypeServiceAccountToken}, // generated
		},
		PVCs: []corev1.PersistentVolumeClaim{
			{ObjectMeta: meta("data-pvc"), Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
			{ObjectMeta: meta("orphan-pvc"), Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}},
		},
		Services: []corev1.Service{
			{ObjectMeta: meta("api"), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}}},
			{ObjectMeta: meta("ghost"), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "ghost"}}},
		},
		Ingresses: []networkingv1.Ingress{{
			ObjectMeta: meta("web"),
			Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{Backend: networkingv1.IngressBackend{
						Service: &networkingv1.IngressServiceBackend{Name: "missing-svc"}}}},
				}},
			}}},
		}},
		HPAs: []autoscalingv2.HorizontalPodAutoscaler{{
			ObjectMeta: meta("ghost-hpa"),
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "gone"},
			},
		}},
		PDBs: []policyv1.PodDisruptionBudget{{
			ObjectMeta: meta("empty-pdb"),
			Spec: policyv1.PodDisruptionBudgetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nobody"}},
			},
		}},
	}

	fs := unusedFindings(s, "payments")

	cases := []struct{ substr, expect, reject string }{
		{"unused ConfigMap", "old-config", "app-config"},
		{"unused Secret", "stale-secret", "app-secret"},
		{"not mounted", "orphan-pvc", "data-pvc"},
		{"unbound PVC", "orphan-pvc", "data-pvc"},
		{"no matching Pods", "ghost", "api"},
		{"missing Service", "missing-svc", ""},
		{"targeting", "ghost-hpa", ""},
		{"selecting no Pods", "empty-pdb", ""},
	}
	for _, tc := range cases {
		f := findMessage(fs, tc.substr)
		if f == nil {
			t.Errorf("expected a finding containing %q, got: %+v", tc.substr, messages(fs))
			continue
		}
		if f.Severity != report.SeverityInfo {
			t.Errorf("%q should be info severity, got %s", tc.substr, f.Severity)
		}
		if !strings.Contains(f.Message, tc.expect) {
			t.Errorf("finding %q should mention %q", f.Message, tc.expect)
		}
		if tc.reject != "" && strings.Contains(f.Message, tc.reject) {
			t.Errorf("finding %q must not mention %q", f.Message, tc.reject)
		}
	}
	if f := findMessage(fs, "kube-root-ca"); f != nil {
		t.Errorf("kube-root-ca.crt must never be flagged: %q", f.Message)
	}
	if f := findMessage(fs, "sa-token"); f != nil {
		t.Errorf("service-account token secrets must never be flagged: %q", f.Message)
	}
}

// tlsSecret builds a kubernetes.io/tls Secret holding a freshly generated
// self-signed certificate that expires at notAfter.
func tlsSecret(t *testing.T, ns, name string, notAfter time.Time) corev1.Secret {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
	}
}

func ingressTLS(ns, name string, secretNames ...string) networkingv1.Ingress {
	var tls []networkingv1.IngressTLS
	for _, sn := range secretNames {
		tls = append(tls, networkingv1.IngressTLS{SecretName: sn})
	}
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       networkingv1.IngressSpec{TLS: tls},
	}
}

func TestCertificates(t *testing.T) {
	now := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	s := &kube.Snapshot{
		HasSecretAccess: true,
		Secrets: []corev1.Secret{
			tlsSecret(t, "payments", "soon-tls", now.Add(3*day)),
			tlsSecret(t, "payments", "month-tls", now.Add(20*day)),
			tlsSecret(t, "payments", "ok-tls", now.Add(90*day)),
			tlsSecret(t, "payments", "dead-tls", now.Add(-2*day)),
		},
		Ingresses: []networkingv1.Ingress{
			ingressTLS("payments", "web", "soon-tls", "month-tls", "ok-tls", "dead-tls", "ghost-tls"),
		},
		HasCertManager: true,
		Certificates: []unstructured.Unstructured{{Object: map[string]any{
			"metadata": map[string]any{"namespace": "payments", "name": "api-cert"},
			"status": map[string]any{"conditions": []any{
				map[string]any{"type": "Ready", "status": "False", "reason": "IssuerNotFound"},
			}},
		}}},
	}

	fs := certificates(s, []string{"payments"}, now).Findings

	if f := findMessage(fs, `"payments/soon-tls" expires in 3 days`); f == nil || f.Severity != report.SeverityCritical {
		t.Errorf("expected critical for 3-day expiry, got: %+v", messages(fs))
	}
	if f := findMessage(fs, `"payments/month-tls" expires in 20 days`); f == nil || f.Severity != report.SeverityWarning {
		t.Errorf("expected warning for 20-day expiry, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "ok-tls"); f != nil {
		t.Errorf("90-day certificate must not be flagged: %q", f.Message)
	}
	if f := findMessage(fs, `"payments/dead-tls" expired 2 days ago`); f == nil || f.Severity != report.SeverityCritical {
		t.Errorf("expected critical for expired cert, got: %+v", messages(fs))
	}
	if f := findMessage(fs, `missing TLS secret "ghost-tls"`); f == nil || f.Severity != report.SeverityWarning {
		t.Errorf("expected missing-secret warning, got: %+v", messages(fs))
	}
	if f := findMessage(fs, `Certificate "payments/api-cert" is not Ready (IssuerNotFound)`); f == nil {
		t.Errorf("expected cert-manager not-Ready finding, got: %+v", messages(fs))
	}

	// Without secret access the missing-secret check must stay silent.
	noAccess := &kube.Snapshot{
		Ingresses: []networkingv1.Ingress{ingressTLS("payments", "web", "ghost-tls")},
	}
	if fs := certificates(noAccess, []string{"payments"}, now).Findings; len(fs) != 0 {
		t.Errorf("expected no findings without secret access, got: %+v", messages(fs))
	}
}

func TestDeprecations(t *testing.T) {
	managed := func(api string) []metav1.ManagedFieldsEntry {
		return []metav1.ManagedFieldsEntry{{Manager: "helm", APIVersion: api}}
	}
	s := &kube.Snapshot{
		ClusterVersion: "v1.24.9+eks",
		CronJobs: []batchv1.CronJob{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "payments", Name: "report",
				Annotations: map[string]string{
					"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"batch/v1beta1","kind":"CronJob"}`,
				},
			},
		}},
		HPAs: []autoscalingv2.HorizontalPodAutoscaler{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "payments", Name: "api-hpa",
				ManagedFields: managed("autoscaling/v2beta2"),
			},
		}},
		Ingresses: []networkingv1.Ingress{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "payments", Name: "web",
				ManagedFields: managed("networking.k8s.io/v1beta1"),
			},
		}},
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "payments", Name: "api",
				ManagedFields: managed("apps/v1"), // current version: no finding
			},
		}},
	}

	fs := Deprecations(s, []string{"payments"}).Findings

	// batch/v1beta1 is removed in 1.25 = next minor after 1.24 -> critical.
	if f := findMessage(fs, "batch/v1beta1"); f == nil || f.Severity != report.SeverityCritical || !strings.Contains(f.Message, "removed in 1.25") {
		t.Errorf("expected critical removed-in-1.25 for batch/v1beta1, got: %+v", messages(fs))
	}
	// autoscaling/v2beta2 is removed in 1.26, two minors away -> warning.
	if f := findMessage(fs, "autoscaling/v2beta2"); f == nil || f.Severity != report.SeverityWarning || !strings.Contains(f.Message, "deprecated since 1.23") {
		t.Errorf("expected deprecation warning for autoscaling/v2beta2, got: %+v", messages(fs))
	}
	// networking.k8s.io/v1beta1 Ingress was removed in 1.22, already gone -> critical.
	if f := findMessage(fs, "networking.k8s.io/v1beta1"); f == nil || f.Severity != report.SeverityCritical || !strings.Contains(f.Message, "removed since 1.22") {
		t.Errorf("expected critical removed-since for v1beta1 Ingress, got: %+v", messages(fs))
	}
	if f := findMessage(fs, "apps/v1,"); f != nil {
		t.Errorf("current API versions must not be flagged: %q", f.Message)
	}
	if len(fs) != 3 {
		t.Errorf("expected exactly 3 findings, got %d: %+v", len(fs), messages(fs))
	}
}

func messages(fs []report.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Message
	}
	return out
}
