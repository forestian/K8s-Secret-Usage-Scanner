package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

// WriteMarkdown renders the report as GitHub-flavored Markdown.
func WriteMarkdown(r *model.ScanReport, w io.Writer) error {
	p := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format+"\n", args...)
	}

	p("# K8s Secret Usage Scanner")
	p("")
	p("**Mode:** %s | **Scanned files:** %d | **Scanned resources:** %d", r.Mode, r.ScannedFiles, r.ScannedResources)
	p("")
	p("## Summary")
	p("")
	p("| Metric | Count |")
	p("|---|---:|")
	p("| Secrets found | %d |", r.Summary.TotalSecrets)
	p("| Secret references | %d |", r.Summary.TotalReferences)
	p("| Unused secrets | %d |", r.Summary.UnusedSecrets)
	p("| High risk findings | %d |", r.Summary.HighRiskFindings)
	p("| Medium risk findings | %d |", r.Summary.MediumRiskFindings)
	p("| Low risk findings | %d |", r.Summary.LowRiskFindings)

	if len(r.Secrets) > 0 {
		p("")
		p("## Secret Usage")
		p("")
		p("| Namespace | Secret | Used | References |")
		p("|---|---|---:|---:|")
		for _, s := range r.Secrets {
			used := "no"
			if s.Used {
				used = "yes"
			}
			p("| %s | %s | %s | %d |", mdNS(s.Namespace), s.Name, used, s.RefCount)
		}
	}

	if len(r.References) > 0 {
		p("")
		p("## References")
		p("")
		p("| Secret | Namespace | Type | Resource |")
		p("|---|---|---|---|")
		for _, ref := range r.References {
			resource := fmt.Sprintf("%s/%s", ref.ResourceKind, ref.ResourceName)
			if ref.ContainerName != "" {
				resource += " `container=" + ref.ContainerName + "`"
			}
			p("| %s | %s | %s | %s |", ref.SecretName, mdNS(ref.Namespace), ref.RefType, resource)
		}
	}

	if len(r.Findings) > 0 {
		p("")
		p("## Findings")
		for _, f := range r.Findings {
			p("")
			p("### %s / %s", strings.ToUpper(f.Risk), f.RuleID)
			p("")
			p("**%s**", f.Title)
			p("")
			if f.SecretName != "" {
				p("**Secret:** `%s/%s`", mdNS(f.Namespace), f.SecretName)
				p("")
			}
			if f.Evidence != "" {
				p("**Evidence:** %s", f.Evidence)
				p("")
			}
			p("%s", f.Explanation)
			p("")
			p("**Suggestion:** %s", f.Suggestion)
		}
	}

	return nil
}

func mdNS(namespace string) string {
	if namespace == "" {
		return "(default)"
	}
	return namespace
}
