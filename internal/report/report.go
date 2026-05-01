package report

import (
	"fmt"
	"io"
	"os"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/risk"
)

// Build populates the Summary of a ScanReport.
func Build(r *model.ScanReport) {
	r.Summary.TotalSecrets = len(r.Secrets)
	r.Summary.TotalReferences = len(r.References)

	for _, s := range r.Secrets {
		if !s.Used {
			r.Summary.UnusedSecrets++
		}
	}
	for _, f := range r.Findings {
		switch f.Risk {
		case "high":
			r.Summary.HighRiskFindings++
		case "medium":
			r.Summary.MediumRiskFindings++
		case "low":
			r.Summary.LowRiskFindings++
		}
	}
}

// Write renders the report in the requested format and writes it to w.
func Write(r *model.ScanReport, format string, w io.Writer) error {
	switch format {
	case "json":
		return WriteJSON(r, w)
	case "markdown":
		return WriteMarkdown(r, w)
	default:
		return WriteText(r, w)
	}
}

// WriteToOutput writes the report to a file or stdout.
func WriteToOutput(r *model.ScanReport, format, outputPath string) error {
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		return Write(r, format, f)
	}
	return Write(r, format, os.Stdout)
}

// ShouldFailOnRisk returns true if the report contains findings at or above the threshold.
func ShouldFailOnRisk(r *model.ScanReport, threshold string) bool {
	level := risk.Parse(threshold)
	if level == risk.None {
		return false
	}
	for _, f := range r.Findings {
		if risk.GTE(risk.Parse(f.Risk), level) {
			return true
		}
	}
	return false
}
