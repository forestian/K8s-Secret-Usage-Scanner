package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFile_SingleYAML(t *testing.T) {
	content := `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: default
`
	path := writeTempFile(t, "single.yaml", content)
	resources, errs := ParseFile(path)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	r := resources[0]
	if r.Kind != "Secret" {
		t.Errorf("expected kind=Secret, got %s", r.Kind)
	}
	if r.Metadata.Name != "my-secret" {
		t.Errorf("expected name=my-secret, got %s", r.Metadata.Name)
	}
	if r.Metadata.Namespace != "default" {
		t.Errorf("expected namespace=default, got %s", r.Metadata.Namespace)
	}
}

func TestParseFile_MultiDocumentYAML(t *testing.T) {
	content := `apiVersion: v1
kind: Secret
metadata:
  name: secret-one
  namespace: default
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
  namespace: default
`
	path := writeTempFile(t, "multi.yaml", content)
	resources, errs := ParseFile(path)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
	if resources[0].Kind != "Secret" {
		t.Errorf("expected first kind=Secret, got %s", resources[0].Kind)
	}
	if resources[1].Kind != "Deployment" {
		t.Errorf("expected second kind=Deployment, got %s", resources[1].Kind)
	}
}

func TestParseFile_EmptyDocSkipped(t *testing.T) {
	content := `---
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
`
	path := writeTempFile(t, "empty.yaml", content)
	resources, errs := ParseFile(path)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
}

func TestParseFile_JSON(t *testing.T) {
	content := `{
  "apiVersion": "v1",
  "kind": "Secret",
  "metadata": {
    "name": "json-secret",
    "namespace": "test"
  }
}`
	path := writeTempFile(t, "secret.json", content)
	resources, errs := ParseFile(path)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Metadata.Name != "json-secret" {
		t.Errorf("expected name=json-secret, got %s", resources[0].Metadata.Name)
	}
}

func TestWalkDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.yaml"), "")
	writeFile(t, filepath.Join(dir, "b.yml"), "")
	writeFile(t, filepath.Join(dir, "c.json"), "")
	writeFile(t, filepath.Join(dir, "d.txt"), "")
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(sub, "e.yaml"), "")

	files, err := WalkDir(dir)
	if err != nil {
		t.Fatalf("WalkDir error: %v", err)
	}
	if len(files) != 4 {
		t.Errorf("expected 4 files (.yaml/.yml/.json), got %d: %v", len(files), files)
	}
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
