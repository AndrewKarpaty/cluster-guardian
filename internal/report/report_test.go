package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleReport() *Report {
	r := &Report{
		ClusterName:       "production",
		KubernetesVersion: "v1.31.0",
		GeneratedAt:       time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		Namespaces: []NamespaceSection{{
			Name: "payments",
			Findings: []Finding{
				{Severity: SeverityWarning, Message: "5 Pods missing resource requests"},
				{Severity: SeverityCritical, Message: "2 CrashLoopBackOff containers"},
			},
		}},
		Sections: []Section{{
			ID: "security", Title: "Security", Icon: "🔒",
			Findings: []Finding{{Severity: SeverityWarning, Message: "8 containers running as root", Hint: "Set runAsNonRoot."}},
		}},
	}
	r.Finalize()
	return r
}

func TestFinalizeAndMaxSeverity(t *testing.T) {
	r := sampleReport()
	if r.Summary.Total != 3 || r.Summary.Warnings != 2 || r.Summary.Critical != 1 {
		t.Errorf("unexpected summary: %+v", r.Summary)
	}
	if r.MaxSeverity() != SeverityCritical {
		t.Errorf("expected critical max severity, got %s", r.MaxSeverity())
	}
}

func TestFilterControls(t *testing.T) {
	r := sampleReport()
	r.Sections[0].Findings[0].Controls = []string{"PSS/restricted:run-as-nonroot"}
	r.FilterControls("pss/")

	if got := len(r.Sections[0].Findings); got != 1 {
		t.Fatalf("expected 1 tagged security finding to survive, got %d", got)
	}
	if got := len(r.Namespaces[0].Findings); got != 0 {
		t.Errorf("untagged namespace findings should be filtered out, got %d", got)
	}
	if r.Summary.Total != 1 || r.Summary.Critical != 0 {
		t.Errorf("summary not recomputed after filtering: %+v", r.Summary)
	}
}

func TestWriteTerminal(t *testing.T) {
	var buf bytes.Buffer
	WriteTerminal(&buf, sampleReport(), TerminalOptions{NoColor: true, Verbose: true})
	out := buf.String()
	for _, want := range []string{
		"✖ Cluster: production",
		"Namespace: payments",
		"• 5 Pods missing resource requests",
		"Security",
		"↳ Set runAsNonRoot.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("NoColor output should not contain ANSI escapes")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Namespaces[0].Findings[1].Severity != SeverityCritical {
		t.Error("severity did not survive JSON round trip")
	}
}

func TestWriteHTMLEscapes(t *testing.T) {
	r := sampleReport()
	r.Namespaces[0].Findings[0].Message = `Deployment "<script>alert(1)</script>" uses :latest tag`
	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Error("HTML output must escape finding messages")
	}
}

func TestWriteDashboard(t *testing.T) {
	var file, dash bytes.Buffer
	if err := WriteHTML(&file, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if err := WriteDashboard(&dash, sampleReport()); err != nil {
		t.Fatal(err)
	}

	// Client-side filtering ships in both variants.
	for _, want := range []string{`id="search"`, `id="nsfilter"`, `data-sev="critical"`, `<details class="card" open`} {
		if !strings.Contains(file.String(), want) || !strings.Contains(dash.String(), want) {
			t.Errorf("expected %q in both HTML variants", want)
		}
	}
	// Live controls need the REST API and are dashboard-only.
	for _, live := range []string{`id="autorefresh"`, `href="/api/report"`, `href="/api/report/markdown"`} {
		if !strings.Contains(dash.String(), live) {
			t.Errorf("expected %q in dashboard output", live)
		}
		if strings.Contains(file.String(), live) {
			t.Errorf("%q must not appear in file-export HTML", live)
		}
	}
}

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "# Cluster report: production") || !strings.Contains(out, "### payments") {
		t.Errorf("unexpected markdown:\n%s", out)
	}
}
