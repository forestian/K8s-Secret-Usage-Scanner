package analyzer

import (
	"fmt"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

const widelyUsedThreshold = 5

func ruleUnusedSecret(item model.SecretInventoryItem) model.Finding {
	return model.Finding{
		Risk:        "low",
		RuleID:      "unused-secret",
		Title:       "Secret appears unused",
		Explanation: "This Secret exists but no workload or service account reference was found by the scanner.",
		Suggestion:  "Verify manually before deleting. Some controllers or applications may reference Secrets dynamically.",
		SecretName:  item.Name,
		Namespace:   item.Namespace,
	}
}

func ruleWidelyUsed(item model.SecretInventoryItem) model.Finding {
	return model.Finding{
		Risk:        "medium",
		RuleID:      "widely-used-secret",
		Title:       "Secret is used by many resources",
		Explanation: "This Secret is referenced by multiple workloads. Rotating or changing it may affect many applications.",
		Suggestion:  "Review blast radius before rotation or modification.",
		SecretName:  item.Name,
		Namespace:   item.Namespace,
		Evidence:    fmt.Sprintf("Referenced by %d resources", item.RefCount),
	}
}

func ruleImagePullSecret(ref model.SecretReference) model.Finding {
	return model.Finding{
		Risk:        "low",
		RuleID:      "image-pull-secret",
		Title:       "Secret used as imagePullSecret",
		Explanation: "This Secret is used for image registry authentication.",
		Suggestion:  "Verify registry credential rotation procedures before changing it.",
		SecretName:  ref.SecretName,
		Namespace:   ref.Namespace,
		Evidence:    fmt.Sprintf("%s/%s", ref.ResourceKind, ref.ResourceName),
	}
}

func ruleEnvSecretRef(ref model.SecretReference) model.Finding {
	ev := fmt.Sprintf("%s/%s", ref.ResourceKind, ref.ResourceName)
	if ref.ContainerName != "" {
		ev += " container=" + ref.ContainerName
	}
	return model.Finding{
		Risk:        "medium",
		RuleID:      "env-secret-ref",
		Title:       "Secret injected as environment variable",
		Explanation: "Secret values injected through environment variables may be visible in process environments and require pod restart after rotation.",
		Suggestion:  "Consider mounted files for some use cases and plan restarts after rotation.",
		SecretName:  ref.SecretName,
		Namespace:   ref.Namespace,
		Evidence:    ev,
	}
}

func ruleVolumeSecretRef(ref model.SecretReference) model.Finding {
	return model.Finding{
		Risk:        "low",
		RuleID:      "volume-secret-ref",
		Title:       "Secret mounted as volume",
		Explanation: "This Secret is mounted into a pod as a volume.",
		Suggestion:  "Confirm application reload behavior after Secret changes.",
		SecretName:  ref.SecretName,
		Namespace:   ref.Namespace,
		Evidence:    fmt.Sprintf("%s/%s", ref.ResourceKind, ref.ResourceName),
	}
}

func ruleMissingSecretInNamespace(ref model.SecretReference) model.Finding {
	return model.Finding{
		Risk:        "medium",
		RuleID:      "missing-secret-in-namespace",
		Title:       "Secret may be missing in workload namespace",
		Explanation: "Kubernetes Secret references are namespace-scoped. The workload may not find the Secret if it does not exist in the same namespace.",
		Suggestion:  "Create the Secret in the workload namespace or adjust the manifest.",
		SecretName:  ref.SecretName,
		Namespace:   ref.ResourceNamespace,
		Evidence:    fmt.Sprintf("%s/%s references %s", ref.ResourceKind, ref.ResourceName, ref.SecretName),
	}
}

func ruleReferencedSecretNotInManifests(ref model.SecretReference) model.Finding {
	return model.Finding{
		Risk:        "low",
		RuleID:      "referenced-secret-not-in-manifests",
		Title:       "Referenced Secret not found in scanned manifests",
		Explanation: "The Secret is referenced but no matching Secret manifest was found in the scanned input.",
		Suggestion:  "This may be normal if Secrets are managed externally, but verify deployment dependencies.",
		SecretName:  ref.SecretName,
		Namespace:   ref.Namespace,
		Evidence:    fmt.Sprintf("%s/%s", ref.ResourceKind, ref.ResourceName),
	}
}
