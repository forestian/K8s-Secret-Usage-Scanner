package manifest

import (
	"testing"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

func TestSecretInventoryDetection(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: prod
`)
	result := ScanResources(resources, "")
	if len(result.Secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(result.Secrets))
	}
	if result.Secrets[0].Name != "my-secret" {
		t.Errorf("expected my-secret, got %s", result.Secrets[0].Name)
	}
}

func TestDeploymentEnvSecretRef(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db-secret
                  key: password
`)
	result := ScanResources(resources, "")
	refs := findRefs(result.References, "db-secret", string(model.RefTypeEnv))
	if len(refs) == 0 {
		t.Fatal("expected env ref for db-secret, found none")
	}
	if refs[0].ContainerName != "app" {
		t.Errorf("expected container=app, got %s", refs[0].ContainerName)
	}
	if refs[0].Key != "password" {
		t.Errorf("expected key=password, got %s", refs[0].Key)
	}
}

func TestDeploymentEnvFromSecretRef(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          envFrom:
            - secretRef:
                name: app-config-secret
`)
	result := ScanResources(resources, "")
	refs := findRefs(result.References, "app-config-secret", string(model.RefTypeEnvFrom))
	if len(refs) == 0 {
		t.Fatal("expected envFrom ref for app-config-secret, found none")
	}
}

func TestVolumeSecretRef(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
      volumes:
        - name: certs
          secret:
            secretName: tls-secret
`)
	result := ScanResources(resources, "")
	refs := findRefs(result.References, "tls-secret", string(model.RefTypeVolume))
	if len(refs) == 0 {
		t.Fatal("expected volume ref for tls-secret, found none")
	}
}

func TestProjectedVolumeSecretRef(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
      volumes:
        - name: proj
          projected:
            sources:
              - secret:
                  name: projected-secret
`)
	result := ScanResources(resources, "")
	refs := findRefs(result.References, "projected-secret", string(model.RefTypeProjectedVolume))
	if len(refs) == 0 {
		t.Fatal("expected projectedVolume ref for projected-secret, found none")
	}
}

func TestImagePullSecretOnPod(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  namespace: default
spec:
  imagePullSecrets:
    - name: registry-creds
  containers:
    - name: app
      image: myapp:latest
`)
	result := ScanResources(resources, "")
	refs := findRefs(result.References, "registry-creds", string(model.RefTypeImagePullSecret))
	if len(refs) == 0 {
		t.Fatal("expected imagePullSecret ref for registry-creds, found none")
	}
}

func TestServiceAccountImagePullSecret(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
  namespace: default
imagePullSecrets:
  - name: sa-registry-secret
`)
	result := ScanResources(resources, "")
	refs := findRefs(result.References, "sa-registry-secret", string(model.RefTypeServiceAccountPullSecret))
	if len(refs) == 0 {
		t.Fatal("expected serviceAccountImagePullSecret ref, found none")
	}
}

func TestInitContainerEnvSecretRef(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  template:
    spec:
      initContainers:
        - name: init
          env:
            - name: INIT_TOKEN
              valueFrom:
                secretKeyRef:
                  name: init-secret
                  key: token
      containers:
        - name: app
          image: nginx
`)
	result := ScanResources(resources, "")
	refs := findRefs(result.References, "init-secret", string(model.RefTypeEnv))
	if len(refs) == 0 {
		t.Fatal("expected env ref in initContainer for init-secret, found none")
	}
	if refs[0].ContainerName != "init" {
		t.Errorf("expected container=init, got %s", refs[0].ContainerName)
	}
}

func TestNamespaceFilter(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: v1
kind: Secret
metadata:
  name: ns-a-secret
  namespace: ns-a
---
apiVersion: v1
kind: Secret
metadata:
  name: ns-b-secret
  namespace: ns-b
`)
	result := ScanResources(resources, "ns-a")
	if len(result.Secrets) != 1 {
		t.Fatalf("expected 1 secret after ns filter, got %d", len(result.Secrets))
	}
	if result.Secrets[0].Name != "ns-a-secret" {
		t.Errorf("expected ns-a-secret, got %s", result.Secrets[0].Name)
	}
}

func TestCronJobSecretRef(t *testing.T) {
	resources := parseYAMLString(t, `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: my-cron
  namespace: default
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              env:
                - name: API_KEY
                  valueFrom:
                    secretKeyRef:
                      name: cron-secret
                      key: api_key
`)
	result := ScanResources(resources, "")
	refs := findRefs(result.References, "cron-secret", string(model.RefTypeEnv))
	if len(refs) == 0 {
		t.Fatal("expected env ref in CronJob for cron-secret, found none")
	}
}

// helpers

func parseYAMLString(t *testing.T, yaml string) []*KubeResource {
	t.Helper()
	path := writeTempFile(t, "test.yaml", yaml)
	resources, errs := ParseFile(path)
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}
	return resources
}

func findRefs(refs []model.SecretReference, secretName, refType string) []model.SecretReference {
	var out []model.SecretReference
	for _, r := range refs {
		if r.SecretName == secretName && r.RefType == refType {
			out = append(out, r)
		}
	}
	return out
}
