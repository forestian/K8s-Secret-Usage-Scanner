package analyzer

import (
	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

// Options controls analyzer behavior.
type Options struct {
	IncludeUnused bool
	ClusterMode   bool
}

// Analyze enriches the Secret inventory with usage data and produces Findings.
func Analyze(secrets []model.SecretInventoryItem, refs []model.SecretReference, opts Options) ([]model.SecretInventoryItem, []model.Finding) {
	// Build a lookup: namespace/name -> index in secrets slice.
	type nsKey struct{ ns, name string }
	secretIdx := make(map[nsKey]int)
	for i, s := range secrets {
		secretIdx[nsKey{s.Namespace, s.Name}] = i
	}

	// Count references per secret.
	refCounts := make(map[nsKey]int)
	for _, ref := range refs {
		refCounts[nsKey{ref.Namespace, ref.SecretName}]++
	}

	// Update inventory.
	for i := range secrets {
		k := nsKey{secrets[i].Namespace, secrets[i].Name}
		secrets[i].RefCount = refCounts[k]
		secrets[i].Used = secrets[i].RefCount > 0
	}

	var findings []model.Finding

	// Per-secret rules.
	for _, s := range secrets {
		if !s.Used && opts.IncludeUnused {
			findings = append(findings, ruleUnusedSecret(s))
		}
		if s.RefCount > widelyUsedThreshold {
			findings = append(findings, ruleWidelyUsed(s))
		}
	}

	// Per-reference rules.
	// Deduplicate: only emit one finding per (ruleID, secret, resource).
	type dedupKey struct{ rule, secret, ns, resource string }
	seen := make(map[dedupKey]bool)

	for _, ref := range refs {
		switch ref.RefType {
		case string(model.RefTypeImagePullSecret), string(model.RefTypeServiceAccountPullSecret):
			k := dedupKey{"image-pull-secret", ref.SecretName, ref.Namespace, ref.ResourceName}
			if !seen[k] {
				seen[k] = true
				findings = append(findings, ruleImagePullSecret(ref))
			}
		case string(model.RefTypeEnv), string(model.RefTypeEnvFrom):
			k := dedupKey{"env-secret-ref", ref.SecretName, ref.Namespace, ref.ResourceName + ref.ContainerName}
			if !seen[k] {
				seen[k] = true
				findings = append(findings, ruleEnvSecretRef(ref))
			}
		case string(model.RefTypeVolume), string(model.RefTypeProjectedVolume):
			k := dedupKey{"volume-secret-ref", ref.SecretName, ref.Namespace, ref.ResourceName}
			if !seen[k] {
				seen[k] = true
				findings = append(findings, ruleVolumeSecretRef(ref))
			}
		}

		// Missing secret in namespace (manifest mode only).
		if !opts.ClusterMode {
			refNS := ref.ResourceNamespace
			if refNS == "" {
				refNS = ref.Namespace
			}
			// Check if a Secret with this name exists in the referenced namespace.
			_, existsInRefNS := secretIdx[nsKey{refNS, ref.SecretName}]
			_, existsInRefNS2 := secretIdx[nsKey{ref.Namespace, ref.SecretName}]

			if !existsInRefNS && !existsInRefNS2 {
				// Secret not found in manifests at all.
				k := dedupKey{"referenced-secret-not-in-manifests", ref.SecretName, ref.Namespace, ""}
				if !seen[k] {
					seen[k] = true
					findings = append(findings, ruleReferencedSecretNotInManifests(ref))
				}
			} else if existsInRefNS2 && !existsInRefNS && refNS != ref.Namespace {
				// Secret exists in a different namespace only.
				k := dedupKey{"missing-secret-in-namespace", ref.SecretName, refNS, ref.ResourceName}
				if !seen[k] {
					seen[k] = true
					findings = append(findings, ruleMissingSecretInNamespace(ref))
				}
			}
		}
	}

	return secrets, findings
}
