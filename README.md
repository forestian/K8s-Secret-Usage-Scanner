# ksecret-map

`ksecret-map` scans Kubernetes manifests or a live cluster and maps where Secrets are used. It helps DevOps, SRE, DevSecOps, and platform engineers answer:

- **Where is this Secret used?**
- **Which Secrets are unused?**
- **Which workloads depend on this Secret?**
- **Can I safely delete or rotate this Secret?**

## Why Secret usage mapping matters

Kubernetes Secrets accumulate over time. Teams frequently lose track of which Secrets are still in use, which workloads reference them, and via what mechanism (env var, volume, imagePullSecret, etc.). Before rotating or deleting a Secret, you need to know its blast radius. `ksecret-map` makes that visible in seconds.

## Security

`ksecret-map` **never reads, prints, or writes Secret data values**. It only analyzes Secret names, namespaces, references, and resource metadata. No Secret values are decoded or stored.

## Installation

```bash
git clone https://github.com/k8s-secret-usage-scanner/ksecret-map
cd ksecret-map
go build -o ksecret-map .
```

Or run directly:

```bash
go run . scan --dir ./manifests
```

## Commands

### `ksecret-map version`

Print the version.

```
ksecret-map version 0.1.0
```

### `ksecret-map scan`

Scan manifests or a live cluster for Secret usage.

**Flags:**

| Flag | Description | Default |
|---|---|---|
| `--file` | Path to a single manifest file (.yaml, .yml, .json) | |
| `--dir` | Path to a directory (scanned recursively) | |
| `--cluster` | Scan a live cluster via kubeconfig | |
| `--namespace` | Filter by namespace | all |
| `--secret` | Filter results by Secret name | all |
| `--format` | Output format: `text`, `json`, `markdown` | `text` |
| `--output` | Write output to a file instead of stdout | stdout |
| `--include-unused` | Report Secrets with no detected references | false |
| `--fail-on-risk` | Exit non-zero on findings at or above risk level: `none`, `low`, `medium`, `high` | `none` |

Exactly one of `--file`, `--dir`, or `--cluster` is required.

## Examples

### Manifest scanning

Scan a single file:

```bash
ksecret-map scan --file examples/deployment-with-secret.yaml
```

Scan a directory recursively:

```bash
ksecret-map scan --dir ./manifests
```

Scan a directory and report unused Secrets:

```bash
ksecret-map scan --dir ./manifests --include-unused
```

Filter by namespace:

```bash
ksecret-map scan --dir ./manifests --namespace monitoring
```

Filter by Secret name:

```bash
ksecret-map scan --dir ./manifests --secret loki-s3-secret
```

### Live cluster scanning

Scan all accessible namespaces:

```bash
ksecret-map scan --cluster
```

Scan a specific namespace:

```bash
ksecret-map scan --cluster --namespace monitoring
```

Filter by Secret name in the cluster:

```bash
ksecret-map scan --cluster --namespace monitoring --secret loki-s3-secret
```

### Output formats

JSON output:

```bash
ksecret-map scan --dir ./manifests --format json
```

Markdown output (suitable for GitHub PR comments):

```bash
ksecret-map scan --cluster --namespace monitoring --format markdown --output report.md
```

### `--include-unused`

By default, Secrets with no detected references are silently tracked in the inventory but do not generate findings. Pass `--include-unused` to emit a `low`-risk finding for each unused Secret.

```bash
ksecret-map scan --dir ./manifests --include-unused
```

### `--fail-on-risk`

Exit with a non-zero status code if any findings meet or exceed the specified risk level. The report is always printed before exit.

```bash
# Fail if any medium or high risk findings exist (useful in CI)
ksecret-map scan --dir ./manifests --fail-on-risk medium

# Fail only on high risk findings
ksecret-map scan --cluster --fail-on-risk high
```

Risk levels (ordered): `none` < `low` < `medium` < `high`

## Detected reference types

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

## Finding rules

| Risk | Rule ID | Trigger |
|---|---|---|
| low | `unused-secret` | Secret exists but has no references (requires `--include-unused`) |
| medium | `widely-used-secret` | Secret referenced by more than 5 resources |
| low | `image-pull-secret` | Secret used as imagePullSecret |
| medium | `env-secret-ref` | Secret injected via environment variable |
| low | `volume-secret-ref` | Secret mounted as a volume |
| medium | `missing-secret-in-namespace` | Secret exists in a different namespace than the referencing workload |
| low | `referenced-secret-not-in-manifests` | Secret is referenced but no matching Secret manifest was found (manifest mode only) |

## Scanned resources

- Pod
- Deployment
- StatefulSet
- DaemonSet
- ReplicaSet
- Job
- CronJob
- ServiceAccount

## Limitations

- **Manifest mode** cannot detect dynamically injected Secrets (e.g., via Vault sidecar, External Secrets Operator, or custom controllers). These may appear as "referenced but not found" findings.
- **Cluster mode** requires kubeconfig and read access. RBAC permission errors are surfaced as warnings and scanning continues for accessible resources.
- Annotation-based references are matched by key pattern, not by resolving external controller state.
- Helm-rendered manifests must be pre-rendered to files; `ksecret-map` does not execute Helm.
- Cross-namespace Secret references are flagged as a finding because Kubernetes enforces namespace scoping, but whether this is a real problem depends on your setup.
- ReplicaSets owned by Deployments will produce duplicate reference entries. This is intentional — direct ReplicaSet references can exist independently.

## Roadmap (not yet implemented)

- GitHub Actions integration
- GitHub PR comment bot
- Secret rotation planner
- External Secrets Operator support
- SealedSecrets support
- Vault integration
- Helm chart pre-rendering
- ArgoCD deep integration
- Admission controller mode
