// Package report defines the analysis result model and its renderers
// (terminal, JSON, Markdown, HTML).
package report

import (
	"encoding/json"
	"fmt"
	"time"
)

// Severity of a single finding.
type Severity int

// Severity levels, ordered from least to most severe.
const (
	SeverityOK Severity = iota
	SeverityInfo
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityOK:
		return "ok"
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// MarshalJSON encodes the severity as its string name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON decodes a severity from its string name.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch v {
	case "ok":
		*s = SeverityOK
	case "info":
		*s = SeverityInfo
	case "warning":
		*s = SeverityWarning
	case "critical":
		*s = SeverityCritical
	default:
		return fmt.Errorf("unknown severity %q", v)
	}
	return nil
}

// Finding is a single observation about the cluster.
type Finding struct {
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Object   string   `json:"object,omitempty"`
	Hint     string   `json:"hint,omitempty"`
}

// Section groups findings under a topic (Security, Monitoring, ...).
type Section struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Icon     string    `json:"icon"`
	Findings []Finding `json:"findings"`
}

// MaxSeverity returns the highest severity among the section's findings.
func (s Section) MaxSeverity() Severity { return maxSeverity(s.Findings) }

// NamespaceSection holds per-namespace workload findings.
type NamespaceSection struct {
	Name     string    `json:"name"`
	Findings []Finding `json:"findings"`
}

// MaxSeverity returns the highest severity among the namespace's findings.
func (n NamespaceSection) MaxSeverity() Severity { return maxSeverity(n.Findings) }

// Summary aggregates finding counts across the whole report.
type Summary struct {
	Namespaces int `json:"namespaces"`
	Total      int `json:"totalFindings"`
	Info       int `json:"info"`
	Warnings   int `json:"warnings"`
	Critical   int `json:"critical"`
}

// Report is the full analysis result.
type Report struct {
	ClusterName       string             `json:"clusterName"`
	Context           string             `json:"context,omitempty"`
	KubernetesVersion string             `json:"kubernetesVersion,omitempty"`
	GeneratedAt       time.Time          `json:"generatedAt"`
	Namespaces        []NamespaceSection `json:"namespaces"`
	Sections          []Section          `json:"sections"`
	Summary           Summary            `json:"summary"`
}

// Finalize recomputes the summary from the collected findings.
func (r *Report) Finalize() {
	s := Summary{Namespaces: len(r.Namespaces)}
	count := func(fs []Finding) {
		for _, f := range fs {
			s.Total++
			switch f.Severity {
			case SeverityInfo:
				s.Info++
			case SeverityWarning:
				s.Warnings++
			case SeverityCritical:
				s.Critical++
			}
		}
	}
	for _, ns := range r.Namespaces {
		count(ns.Findings)
	}
	for _, sec := range r.Sections {
		count(sec.Findings)
	}
	r.Summary = s
}

// MaxSeverity returns the highest severity present anywhere in the report.
func (r *Report) MaxSeverity() Severity {
	highest := SeverityOK
	for _, ns := range r.Namespaces {
		if v := ns.MaxSeverity(); v > highest {
			highest = v
		}
	}
	for _, sec := range r.Sections {
		if v := sec.MaxSeverity(); v > highest {
			highest = v
		}
	}
	return highest
}

func maxSeverity(fs []Finding) Severity {
	highest := SeverityOK
	for _, f := range fs {
		if f.Severity > highest {
			highest = f.Severity
		}
	}
	return highest
}
