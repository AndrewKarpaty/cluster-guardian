package report

import (
	"fmt"
	"io"
	"strings"
)

// TerminalOptions configure the CLI renderer.
type TerminalOptions struct {
	NoColor bool
	// Verbose prints remediation hints under each finding.
	Verbose bool
}

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiDim    = "\033[2m"
	ansiBold   = "\033[1m"
)

// WriteTerminal renders the report for humans in a terminal.
func WriteTerminal(w io.Writer, r *Report, opts TerminalOptions) {
	color := func(code, s string) string {
		if opts.NoColor {
			return s
		}
		return code + s + ansiReset
	}
	symbol := func(s Severity) string {
		switch s {
		case SeverityCritical:
			return color(ansiRed, "✖")
		case SeverityWarning:
			return color(ansiYellow, "⚠")
		case SeverityInfo:
			return color(ansiCyan, "ℹ")
		default:
			return color(ansiGreen, "✔")
		}
	}

	fmt.Fprintf(w, "%s %s\n", symbol(r.MaxSeverity()), color(ansiBold, "Cluster: "+r.ClusterName))
	var meta []string
	if r.KubernetesVersion != "" {
		meta = append(meta, "Kubernetes "+r.KubernetesVersion)
	}
	meta = append(meta, fmt.Sprintf("score %d/100 (%s)", r.Summary.Score, r.Summary.Grade))
	meta = append(meta, fmt.Sprintf("%d namespaces analyzed", r.Summary.Namespaces))
	if r.Summary.Critical > 0 || r.Summary.Warnings > 0 {
		meta = append(meta, fmt.Sprintf("%d warnings, %d critical", r.Summary.Warnings, r.Summary.Critical))
	}
	fmt.Fprintf(w, "  %s\n", color(ansiDim, strings.Join(meta, " • ")))

	writeFindings := func(findings []Finding) {
		for _, f := range findings {
			bullet := "•"
			switch f.Severity {
			case SeverityCritical:
				bullet = color(ansiRed, "•")
			case SeverityWarning:
				bullet = color(ansiYellow, "•")
			}
			fmt.Fprintf(w, "  %s %s\n", bullet, f.Message)
			if opts.Verbose && f.Hint != "" {
				fmt.Fprintf(w, "    %s\n", color(ansiDim, "↳ "+f.Hint))
			}
		}
	}

	for _, ns := range r.Namespaces {
		if len(ns.Findings) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s %s\n", symbol(ns.MaxSeverity()), color(ansiBold, "Namespace: "+ns.Name))
		writeFindings(ns.Findings)
	}
	if healthy := healthyNamespaces(r); len(healthy) > 0 {
		fmt.Fprintf(w, "\n%s %s\n", symbol(SeverityOK),
			color(ansiDim, fmt.Sprintf("%d healthy namespaces: %s", len(healthy), strings.Join(healthy, ", "))))
	}

	for _, sec := range r.Sections {
		if len(sec.Findings) == 0 {
			continue
		}
		prefix := symbol(sec.MaxSeverity())
		if sec.ID == "optimization" {
			prefix = sec.Icon
		}
		fmt.Fprintf(w, "\n%s %s\n", prefix, color(ansiBold, sec.Title))
		writeFindings(sec.Findings)
	}

	fmt.Fprintln(w)
}

func healthyNamespaces(r *Report) []string {
	var out []string
	for _, ns := range r.Namespaces {
		if len(ns.Findings) == 0 {
			out = append(out, ns.Name)
		}
	}
	return out
}
