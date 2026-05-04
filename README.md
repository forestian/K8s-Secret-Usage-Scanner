# ksecret-map

Find where every Kubernetes Secret is used — before you rotate, delete, or wonder what breaks.

## Quick Demo

```bash
ksecret-map scan --dir ./examples --include-unused
```

```
K8s Secret Usage Scanner

Mode: manifest
Scanned files: 4
Scanned resources: 4

Summary:
  Secrets found:        2
  Secret references:    3
  Unused secrets:       1
  High risk findings:   0
  Medium risk findings: 1
  Low risk findings:    2

Secret Usage:

NAMESPACE             SECRET                          USED  REFS
--------------------  ------------------------------  ----  ----
monitoring            loki-s3-secret                  yes   3
(default)             unused-secret                   no    0

References:

SECRET                          NAMESPACE             TYPE                          RESOURCE
------------------------------  --------------------  ----------------------------  ------------------------------
loki-s3-secret                  monitoring            env                           Deployment/loki-backend container=loki
loki-s3-secret                  monitoring            env                           Deployment/loki-backend container=loki
loki-s3-secret                  monitoring            volume                        Deployment/loki-backend

Findings:

[MEDIUM] Secret injected via environment variable
  Secret: monitoring/loki-s3-secret
  Rule: env-secret-ref

  Explanation:
  Secrets injected as environment variables are visible in process listings and may appear in logs.

  Suggestion:
  Consider mounting the Secret as a volume or using an external secrets manager.

[LOW] Secret exists but has no references
  Secret: (default)/unused-secret
  Rule: unused-secret

  Explanation:
  This Secret has no detected references in the scanned manifests.

  Suggestion:
  Verify whether this Secret is still needed and remove it if not.
```

## Demo

GIF demo coming soon.

## Quick Start

Download a prebuilt binary from the [GitHub Releases page](https://github.com/forestian/K8s-Secret-Usage-Scanner/releases):

```bash
# Linux / macOS
tar -xzf ksecret-map_<version>_<os>_<arch>.tar.gz
chmod +x ksecret-map
./ksecret-map version

# Windows — extract the archive and run:
ksecret-map.exe version
```

Build from source:

```bash
git clone https://github.com/forestian/K8s-Secret-Usage-Scanner
cd K8s-Secret-Usage-Scanner
go build -o ksecret-map .
```

## Use Cases

- **Before rotating a Secret** — know every workload and container that depends on it
- **Cleaning up stale Secrets** — find which Secrets have zero references across all manifests
- **CI gate** — fail the pipeline if risky Secret patterns are detected (`--fail-on-risk medium`)
- **Security audit** — spot Secrets exposed as environment variables (higher blast radius than volume mounts)
- **Cross-namespace review** — detect Secret references that cross namespace boundaries

## Why it matters

Kubernetes Secrets accumulate over time. Teams lose track of which Secrets are still in use, which workloads reference them, and how. Before rotating or deleting a Secret, you need to know its blast radius. `ksecret-map` makes that visible in seconds — without ever reading or printing Secret values.

## Commands

### `ksecret-map scan`

Scan manifests or a live cluster for Secret usage. Exactly one of `--file`, `--dir`, or `--cluster` is required.

| Flag | Default | Description |
|---|---|---|
| `--file` | | Single manifest file (.yaml, .yml, .json) |
| `--dir` | | Directory scanned recursively |
| `--cluster` | | Live cluster scan via kubeconfig |
| `--namespace` | all | Filter output by namespace |
| `--secret` | all | Filter results by Secret name |
| `--format` | `text` | Output format: `text`, `json`, `markdown` |
| `--output` | stdout | Write output to a file |
| `--include-unused` | false | Emit findings for Secrets with no detected references |
| `--fail-on-risk` | `none` | Exit non-zero at or above risk level: `low`, `medium`, `high` |

**Common examples:**

```bash
# Scan a directory
ksecret-map scan --dir ./manifests

# Report unused Secrets
ksecret-map scan --dir ./manifests --include-unused

# Filter by namespace or Secret name
ksecret-map scan --dir ./manifests --namespace monitoring
ksecret-map scan --dir ./manifests --secret loki-s3-secret

# Live cluster scan
ksecret-map scan --cluster --namespace monitoring

# CI gate — fail on medium or higher risk
ksecret-map scan --dir ./manifests --fail-on-risk medium

# Markdown output for PR comments
ksecret-map scan --cluster --namespace monitoring --format markdown --output report.md
```

### `ksecret-map version`

```
ksecret-map version 0.1.0
```

## Example Output

**JSON** (useful for scripting or downstream tools):

```bash
ksecret-map scan --dir ./manifests --format json
```

```json
{
  "Mode": "manifest",
  "ScannedFiles": 4,
  "ScannedResources": 4,
  "Summary": {
    "TotalSecrets": 2,
    "TotalReferences": 3,
    "UnusedSecrets": 1,
    "HighRiskFindings": 0,
    "MediumRiskFindings": 1,
    "LowRiskFindings": 2
  },
  ...
}
```

**Markdown** (suitable for GitHub PR comments):

```bash
ksecret-map scan --dir ./manifests --format markdown --output report.md
```

## Detected Reference Types

| Type | Description |
|---|---|
| `env` | `env[].valueFrom.secretKeyRef` in containers or initContainers |
| `envFrom` | `envFrom[].secretRef` in containers or initContainers |
| `volume` | `volumes[].secret.secretName` in pod spec |
| `projectedVolume` | `volumes[].projected.sources[].secret.name` |
| `imagePullSecret` | `spec.imagePullSecrets` on pod or workload template |
| `serviceAccountImagePullSecret` | `imagePullSecrets` on a ServiceAccount |
| `csi` | `volumes[].csi.nodePublishSecretRef.name` |
| `annotation` | Reloader, Vault, External Secrets, and ArgoCD annotations |

## Finding Rules

| Risk | Rule ID | Trigger |
|---|---|---|
| low | `unused-secret` | Secret exists but has no references (requires `--include-unused`) |
| medium | `widely-used-secret` | Secret referenced by more than 5 resources |
| low | `image-pull-secret` | Secret used as imagePullSecret |
| medium | `env-secret-ref` | Secret injected via environment variable |
| low | `volume-secret-ref` | Secret mounted as a volume |
| medium | `missing-secret-in-namespace` | Secret exists in a different namespace than the referencing workload |
| low | `referenced-secret-not-in-manifests` | Secret is referenced but no matching Secret manifest was found (manifest mode only) |

## Scanned Resources

Pod · Deployment · StatefulSet · DaemonSet · ReplicaSet · Job · CronJob · ServiceAccount

## Safety

`ksecret-map` is **read-only**:

- **Never reads or prints Secret data values** — only analyzes names, namespaces, and references
- **No cluster writes** — manifest mode requires no cluster access; cluster mode is read-only
- Safe to run in CI pipelines and air-gapped environments (manifest mode is fully offline)

## Limitations

- Manifest mode cannot detect dynamically injected Secrets (Vault sidecar, External Secrets Operator, custom controllers). These may appear as "referenced but not found" findings.
- Cluster mode requires kubeconfig with read access. RBAC errors are surfaced as warnings; scanning continues for accessible resources.
- Annotation-based references are matched by key pattern, not by resolving external controller state.
- Helm-rendered manifests must be pre-rendered; `ksecret-map` does not execute Helm.
- ReplicaSets owned by Deployments produce duplicate reference entries (intentional — direct RS references can exist independently).
- Cross-namespace Secret references are flagged as findings; whether they are a real problem depends on your setup.

## Roadmap

- GitHub Actions integration and PR comment bot
- External Secrets Operator and SealedSecrets support
- Helm chart pre-rendering
- Vault integration
- Admission controller mode
- ArgoCD deep integration

---

Part of the [Forestian Cloud Native Toolkit](https://github.com/forestian) — small CLI tools for Kubernetes, observability, GitOps, and platform engineering.
