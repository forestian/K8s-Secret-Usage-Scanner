package analyzer

import (
	"testing"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

func TestUnusedSecretFinding(t *testing.T) {
	secrets := []model.SecretInventoryItem{
		{Name: "unused", Namespace: "default"},
	}
	_, findings := Analyze(secrets, nil, Options{IncludeUnused: true})
	if !hasFinding(findings, "unused-secret") {
		t.Error("expected unused-secret finding, got none")
	}
}

func TestUnusedSecretNotReportedWithoutFlag(t *testing.T) {
	secrets := []model.SecretInventoryItem{
		{Name: "unused", Namespace: "default"},
	}
	_, findings := Analyze(secrets, nil, Options{IncludeUnused: false})
	if hasFinding(findings, "unused-secret") {
		t.Error("should not report unused-secret when include-unused is false")
	}
}

func TestUsedSecretNotUnused(t *testing.T) {
	secrets := []model.SecretInventoryItem{
		{Name: "used", Namespace: "default"},
	}
	refs := []model.SecretReference{
		{SecretName: "used", Namespace: "default", RefType: "env", ResourceKind: "Deployment", ResourceName: "app", ResourceNamespace: "default"},
	}
	updated, findings := Analyze(secrets, refs, Options{IncludeUnused: true})
	if hasFinding(findings, "unused-secret") {
		t.Error("should not report used secret as unused")
	}
	if !updated[0].Used {
		t.Error("secret should be marked as used")
	}
	if updated[0].RefCount != 1 {
		t.Errorf("expected refcount=1, got %d", updated[0].RefCount)
	}
}

func TestWidelyUsedSecretFinding(t *testing.T) {
	secrets := []model.SecretInventoryItem{
		{Name: "popular", Namespace: "default"},
	}
	var refs []model.SecretReference
	for i := 0; i < 6; i++ {
		refs = append(refs, model.SecretReference{
			SecretName:        "popular",
			Namespace:         "default",
			RefType:           "env",
			ResourceKind:      "Deployment",
			ResourceName:      "app",
			ResourceNamespace: "default",
			ContainerName:     string(rune('a' + i)),
		})
	}
	_, findings := Analyze(secrets, refs, Options{})
	if !hasFinding(findings, "widely-used-secret") {
		t.Error("expected widely-used-secret finding")
	}
}

func TestEnvSecretFinding(t *testing.T) {
	secrets := []model.SecretInventoryItem{{Name: "s", Namespace: "default"}}
	refs := []model.SecretReference{
		{SecretName: "s", Namespace: "default", RefType: "env", ResourceKind: "Deployment", ResourceName: "app", ResourceNamespace: "default"},
	}
	_, findings := Analyze(secrets, refs, Options{})
	if !hasFinding(findings, "env-secret-ref") {
		t.Error("expected env-secret-ref finding")
	}
}

func TestEnvFromSecretFinding(t *testing.T) {
	secrets := []model.SecretInventoryItem{{Name: "s", Namespace: "default"}}
	refs := []model.SecretReference{
		{SecretName: "s", Namespace: "default", RefType: "envFrom", ResourceKind: "Deployment", ResourceName: "app", ResourceNamespace: "default"},
	}
	_, findings := Analyze(secrets, refs, Options{})
	if !hasFinding(findings, "env-secret-ref") {
		t.Error("expected env-secret-ref finding for envFrom")
	}
}

func TestVolumeFinding(t *testing.T) {
	secrets := []model.SecretInventoryItem{{Name: "s", Namespace: "default"}}
	refs := []model.SecretReference{
		{SecretName: "s", Namespace: "default", RefType: "volume", ResourceKind: "Deployment", ResourceName: "app", ResourceNamespace: "default"},
	}
	_, findings := Analyze(secrets, refs, Options{})
	if !hasFinding(findings, "volume-secret-ref") {
		t.Error("expected volume-secret-ref finding")
	}
}

func TestImagePullSecretFinding(t *testing.T) {
	secrets := []model.SecretInventoryItem{{Name: "reg", Namespace: "default"}}
	refs := []model.SecretReference{
		{SecretName: "reg", Namespace: "default", RefType: "imagePullSecret", ResourceKind: "Pod", ResourceName: "mypod", ResourceNamespace: "default"},
	}
	_, findings := Analyze(secrets, refs, Options{})
	if !hasFinding(findings, "image-pull-secret") {
		t.Error("expected image-pull-secret finding")
	}
}

func TestReferencedSecretNotInManifests(t *testing.T) {
	// No secrets in inventory, but a ref exists
	secrets := []model.SecretInventoryItem{}
	refs := []model.SecretReference{
		{SecretName: "missing", Namespace: "default", RefType: "env", ResourceKind: "Deployment", ResourceName: "app", ResourceNamespace: "default"},
	}
	_, findings := Analyze(secrets, refs, Options{ClusterMode: false})
	if !hasFinding(findings, "referenced-secret-not-in-manifests") {
		t.Error("expected referenced-secret-not-in-manifests finding")
	}
}

func TestReferencedSecretNotInManifests_NotInClusterMode(t *testing.T) {
	secrets := []model.SecretInventoryItem{}
	refs := []model.SecretReference{
		{SecretName: "missing", Namespace: "default", RefType: "env", ResourceKind: "Deployment", ResourceName: "app", ResourceNamespace: "default"},
	}
	_, findings := Analyze(secrets, refs, Options{ClusterMode: true})
	if hasFinding(findings, "referenced-secret-not-in-manifests") {
		t.Error("should not report referenced-secret-not-in-manifests in cluster mode")
	}
}

func hasFinding(findings []model.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
