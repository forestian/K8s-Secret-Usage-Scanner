package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

func sampleReport() *model.ScanReport {
	r := &model.ScanReport{
		Mode:             "manifests",
		ScannedFiles:     2,
		ScannedResources: 5,
		Secrets: []model.SecretInventoryItem{
			{Name: "my-secret", Namespace: "default", Used: true, RefCount: 2},
			{Name: "unused", Namespace: "default", Used: false, RefCount: 0},
		},
		References: []model.SecretReference{
			{SecretName: "my-secret", Namespace: "default", RefType: "env", ResourceKind: "Deployment", ResourceName: "app"},
			{SecretName: "my-secret", Namespace: "default", RefType: "volume", ResourceKind: "Deployment", ResourceName: "app"},
		},
		Findings: []model.Finding{
			{Risk: "medium", RuleID: "env-secret-ref", Title: "Secret injected as environment variable", SecretName: "my-secret", Namespace: "default"},
			{Risk: "low", RuleID: "unused-secret", Title: "Secret appears unused", SecretName: "unused", Namespace: "default"},
		},
	}
	Build(r)
	return r
}

func TestBuildSummary(t *testing.T) {
	r := sampleReport()
	if r.Summary.TotalSecrets != 2 {
		t.Errorf("expected 2 secrets, got %d", r.Summary.TotalSecrets)
	}
	if r.Summary.TotalReferences != 2 {
		t.Errorf("expected 2 references, got %d", r.Summary.TotalReferences)
	}
	if r.Summary.UnusedSecrets != 1 {
		t.Errorf("expected 1 unused, got %d", r.Summary.UnusedSecrets)
	}
	if r.Summary.MediumRiskFindings != 1 {
		t.Errorf("expected 1 medium finding, got %d", r.Summary.MediumRiskFindings)
	}
	if r.Summary.LowRiskFindings != 1 {
		t.Errorf("expected 1 low finding, got %d", r.Summary.LowRiskFindings)
	}
}

func TestJSONReport(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := WriteJSON(r, &buf); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	var decoded model.ScanReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if decoded.Mode != "manifests" {
		t.Errorf("expected mode=manifests, got %s", decoded.Mode)
	}
	if len(decoded.Secrets) != 2 {
		t.Errorf("expected 2 secrets in JSON, got %d", len(decoded.Secrets))
	}
	if len(decoded.Findings) != 2 {
		t.Errorf("expected 2 findings in JSON, got %d", len(decoded.Findings))
	}
}

func TestMarkdownReport(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := WriteMarkdown(r, &buf); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "# K8s Secret Usage Scanner") {
		t.Error("markdown missing title")
	}
	if !strings.Contains(out, "## Summary") {
		t.Error("markdown missing Summary section")
	}
	if !strings.Contains(out, "## Secret Usage") {
		t.Error("markdown missing Secret Usage section")
	}
	if !strings.Contains(out, "## Findings") {
		t.Error("markdown missing Findings section")
	}
	if !strings.Contains(out, "env-secret-ref") {
		t.Error("markdown missing finding rule ID")
	}
}

func TestTextReport(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := WriteText(r, &buf); err != nil {
		t.Fatalf("WriteText error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "K8s Secret Usage Scanner") {
		t.Error("text missing title")
	}
	if !strings.Contains(out, "my-secret") {
		t.Error("text missing secret name")
	}
	if !strings.Contains(out, "env-secret-ref") {
		t.Error("text missing finding rule ID")
	}
}

func TestShouldFailOnRisk(t *testing.T) {
	r := sampleReport() // has medium and low findings

	if ShouldFailOnRisk(r, "none") {
		t.Error("should not fail on 'none'")
	}
	if !ShouldFailOnRisk(r, "low") {
		t.Error("should fail on 'low' (has low findings)")
	}
	if !ShouldFailOnRisk(r, "medium") {
		t.Error("should fail on 'medium' (has medium findings)")
	}
	if ShouldFailOnRisk(r, "high") {
		t.Error("should not fail on 'high' (no high findings)")
	}
}

func TestShouldFailOnRisk_NoFindings(t *testing.T) {
	r := &model.ScanReport{}
	Build(r)
	if ShouldFailOnRisk(r, "low") {
		t.Error("should not fail when there are no findings")
	}
}
