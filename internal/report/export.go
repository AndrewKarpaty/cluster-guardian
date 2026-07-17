package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WriteJSON renders the report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteMarkdown renders the report as a Markdown document.
func WriteMarkdown(w io.Writer, r *Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Cluster report: %s\n\n", r.ClusterName)
	fmt.Fprintf(&b, "Generated %s", r.GeneratedAt.Format("2006-01-02 15:04 UTC"))
	if r.KubernetesVersion != "" {
		fmt.Fprintf(&b, " • Kubernetes %s", r.KubernetesVersion)
	}
	b.WriteString("\n\n")

	fmt.Fprintf(&b, "| Namespaces | Findings | Warnings | Critical |\n|---|---|---|---|\n| %d | %d | %d | %d |\n\n",
		r.Summary.Namespaces, r.Summary.Total, r.Summary.Warnings, r.Summary.Critical)

	writeFindings := func(findings []Finding) {
		for _, f := range findings {
			fmt.Fprintf(&b, "- **%s** — %s", f.Severity, f.Message)
			if f.Hint != "" {
				fmt.Fprintf(&b, "\n  - _%s_", f.Hint)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Namespaces\n\n")
	for _, ns := range r.Namespaces {
		if len(ns.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s\n\n", ns.Name)
		writeFindings(ns.Findings)
	}
	if healthy := healthyNamespaces(r); len(healthy) > 0 {
		fmt.Fprintf(&b, "Healthy namespaces: %s\n\n", strings.Join(healthy, ", "))
	}

	for _, sec := range r.Sections {
		if len(sec.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s %s\n\n", sec.Icon, sec.Title)
		writeFindings(sec.Findings)
	}

	_, err := io.WriteString(w, b.String())
	return err
}
