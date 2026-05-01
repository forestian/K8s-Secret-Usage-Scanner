package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

// WriteText renders the report as human-readable text.
func WriteText(r *model.ScanReport, w io.Writer) error {
	p := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format+"\n", args...)
	}

	p("K8s Secret Usage Scanner")
	p("")
	p("Mode: %s", r.Mode)
	p("Scanned files: %d", r.ScannedFiles)
	p("Scanned resources: %d", r.ScannedResources)
	p("")
	p("Summary:")
	p("  Secrets found:       %d", r.Summary.TotalSecrets)
	p("  Secret references:   %d", r.Summary.TotalReferences)
	p("  Unused secrets:      %d", r.Summary.UnusedSecrets)
	p("  High risk findings:  %d", r.Summary.HighRiskFindings)
	p("  Medium risk findings:%d", r.Summary.MediumRiskFindings)
	p("  Low risk findings:   %d", r.Summary.LowRiskFindings)

	if len(r.Secrets) > 0 {
		p("")
		p("Secret Usage:")
		p("")
		p("%-20s  %-30s  %-4s  %s", "NAMESPACE", "SECRET", "USED", "REFS")
		p("%s  %s  %s  %s", strings.Repeat("-", 20), strings.Repeat("-", 30), strings.Repeat("-", 4), strings.Repeat("-", 4))
		for _, s := range r.Secrets {
			used := "no"
			if s.Used {
				used = "yes"
			}
			p("%-20s  %-30s  %-4s  %d", ns(s.Namespace), s.Name, used, s.RefCount)
		}
	}

	if len(r.References) > 0 {
		p("")
		p("References:")
		p("")
		p("%-30s  %-20s  %-28s  %s", "SECRET", "NAMESPACE", "TYPE", "RESOURCE")
		p("%s  %s  %s  %s", strings.Repeat("-", 30), strings.Repeat("-", 20), strings.Repeat("-", 28), strings.Repeat("-", 30))
		for _, ref := range r.References {
			resource := fmt.Sprintf("%s/%s", ref.ResourceKind, ref.ResourceName)
			if ref.ContainerName != "" {
				resource += " container=" + ref.ContainerName
			}
			p("%-30s  %-20s  %-28s  %s", ref.SecretName, ns(ref.Namespace), ref.RefType, resource)
		}
	}

	if len(r.Findings) > 0 {
		p("")
		p("Findings:")
		for _, f := range r.Findings {
			p("")
			p("[%s] %s", strings.ToUpper(f.Risk), f.Title)
			if f.SecretName != "" {
				p("  Secret: %s/%s", ns(f.Namespace), f.SecretName)
			}
			p("  Rule: %s", f.RuleID)
			if f.Evidence != "" {
				p("  Evidence: %s", f.Evidence)
			}
			p("")
			p("  Explanation:")
			p("  %s", f.Explanation)
			p("")
			p("  Suggestion:")
			p("  %s", f.Suggestion)
		}
	}

	return nil
}

func ns(namespace string) string {
	if namespace == "" {
		return "(default)"
	}
	return namespace
}
