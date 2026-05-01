package manifest

import (
	"strings"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

// ScanResult holds everything extracted from a set of manifests.
type ScanResult struct {
	Secrets    []model.SecretInventoryItem
	References []model.SecretReference
	Files      int
	Resources  int
}

// ScanResources extracts Secret inventory and references from a slice of
// decoded KubeResource objects.
func ScanResources(resources []*KubeResource, filterNS string) *ScanResult {
	result := &ScanResult{}

	for _, r := range resources {
		result.Resources++

		if filterNS != "" && r.Metadata.Namespace != "" && r.Metadata.Namespace != filterNS {
			continue
		}

		switch r.Kind {
		case "Secret":
			result.Secrets = append(result.Secrets, model.SecretInventoryItem{
				Name:       r.Metadata.Name,
				Namespace:  r.Metadata.Namespace,
				Source:     "manifest",
				SourceFile: r.SourceFile,
			})
		case "Pod":
			refs := extractFromPodSpec(r.Raw["spec"], r.Kind, r.Metadata.Name, r.Metadata.Namespace, r.SourceFile)
			refs = append(refs, extractFromAnnotations(r.Metadata.Annotations, r.Kind, r.Metadata.Name, r.Metadata.Namespace, r.SourceFile)...)
			result.References = append(result.References, refs...)
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
			refs := extractFromWorkload(r.Raw, r.Kind, r.Metadata.Name, r.Metadata.Namespace, r.SourceFile)
			refs = append(refs, extractFromAnnotations(r.Metadata.Annotations, r.Kind, r.Metadata.Name, r.Metadata.Namespace, r.SourceFile)...)
			result.References = append(result.References, refs...)
		case "Job":
			refs := extractFromWorkload(r.Raw, r.Kind, r.Metadata.Name, r.Metadata.Namespace, r.SourceFile)
			refs = append(refs, extractFromAnnotations(r.Metadata.Annotations, r.Kind, r.Metadata.Name, r.Metadata.Namespace, r.SourceFile)...)
			result.References = append(result.References, refs...)
		case "CronJob":
			refs := extractFromCronJob(r.Raw, r.Metadata.Name, r.Metadata.Namespace, r.SourceFile)
			refs = append(refs, extractFromAnnotations(r.Metadata.Annotations, r.Kind, r.Metadata.Name, r.Metadata.Namespace, r.SourceFile)...)
			result.References = append(result.References, refs...)
		case "ServiceAccount":
			refs := extractFromServiceAccount(r.Raw, r.Metadata.Name, r.Metadata.Namespace, r.SourceFile)
			result.References = append(result.References, refs...)
		}
	}

	return result
}

// extractFromWorkload handles Deployment/StatefulSet/DaemonSet/ReplicaSet/Job
// which all have spec.template.spec.
func extractFromWorkload(raw map[string]interface{}, kind, name, ns, file string) []model.SecretReference {
	spec := nestedMap(raw, "spec")
	if spec == nil {
		return nil
	}
	template := nestedMap(spec, "template")
	if template == nil {
		return nil
	}
	podSpec := nestedMap(template, "spec")
	if podSpec == nil {
		return nil
	}

	refs := extractFromPodSpec(podSpec, kind, name, ns, file)

	// Also scan template annotations for reloader-style annotations.
	if meta, ok := template["metadata"].(map[string]interface{}); ok {
		ann := make(map[string]string)
		if annRaw, ok := meta["annotations"].(map[string]interface{}); ok {
			for k, v := range annRaw {
				if sv, ok := v.(string); ok {
					ann[k] = sv
				}
			}
		}
		refs = append(refs, extractFromAnnotations(ann, kind, name, ns, file)...)
	}

	return refs
}

// extractFromCronJob drills into spec.jobTemplate.spec.template.spec.
func extractFromCronJob(raw map[string]interface{}, name, ns, file string) []model.SecretReference {
	spec := nestedMap(raw, "spec")
	if spec == nil {
		return nil
	}
	jobTemplate := nestedMap(spec, "jobTemplate")
	if jobTemplate == nil {
		return nil
	}
	jobSpec := nestedMap(jobTemplate, "spec")
	if jobSpec == nil {
		return nil
	}
	template := nestedMap(jobSpec, "template")
	if template == nil {
		return nil
	}
	podSpec := nestedMap(template, "spec")
	if podSpec == nil {
		return nil
	}
	return extractFromPodSpec(podSpec, "CronJob", name, ns, file)
}

// extractFromPodSpec handles the actual pod spec map.
func extractFromPodSpec(podSpecRaw interface{}, kind, name, ns, file string) []model.SecretReference {
	podSpec, ok := podSpecRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	var refs []model.SecretReference

	// imagePullSecrets at pod level
	if ips, ok := podSpec["imagePullSecrets"].([]interface{}); ok {
		for _, item := range ips {
			if m, ok := item.(map[string]interface{}); ok {
				if sname, ok := m["name"].(string); ok && sname != "" {
					refs = append(refs, model.SecretReference{
						SecretName:        sname,
						Namespace:         ns,
						RefType:           string(model.RefTypeImagePullSecret),
						ResourceKind:      kind,
						ResourceName:      name,
						ResourceNamespace: ns,
						SourceFile:        file,
					})
				}
			}
		}
	}

	// volumes
	if volumes, ok := podSpec["volumes"].([]interface{}); ok {
		for _, vol := range volumes {
			vm, ok := vol.(map[string]interface{})
			if !ok {
				continue
			}
			// volumes[*].secret.secretName
			if secret, ok := vm["secret"].(map[string]interface{}); ok {
				if sname, ok := secret["secretName"].(string); ok && sname != "" {
					refs = append(refs, model.SecretReference{
						SecretName:        sname,
						Namespace:         ns,
						RefType:           string(model.RefTypeVolume),
						ResourceKind:      kind,
						ResourceName:      name,
						ResourceNamespace: ns,
						SourceFile:        file,
					})
				}
			}
			// volumes[*].projected.sources[*].secret.name
			if projected, ok := vm["projected"].(map[string]interface{}); ok {
				if sources, ok := projected["sources"].([]interface{}); ok {
					for _, src := range sources {
						sm, ok := src.(map[string]interface{})
						if !ok {
							continue
						}
						if secretSrc, ok := sm["secret"].(map[string]interface{}); ok {
							if sname, ok := secretSrc["name"].(string); ok && sname != "" {
								refs = append(refs, model.SecretReference{
									SecretName:        sname,
									Namespace:         ns,
									RefType:           string(model.RefTypeProjectedVolume),
									ResourceKind:      kind,
									ResourceName:      name,
									ResourceNamespace: ns,
									SourceFile:        file,
								})
							}
						}
					}
				}
			}
			// volumes[*].csi.nodePublishSecretRef.name
			if csi, ok := vm["csi"].(map[string]interface{}); ok {
				if ref, ok := csi["nodePublishSecretRef"].(map[string]interface{}); ok {
					if sname, ok := ref["name"].(string); ok && sname != "" {
						refs = append(refs, model.SecretReference{
							SecretName:        sname,
							Namespace:         ns,
							RefType:           string(model.RefTypeCSI),
							ResourceKind:      kind,
							ResourceName:      name,
							ResourceNamespace: ns,
							SourceFile:        file,
						})
					}
				}
			}
		}
	}

	// containers + initContainers
	for _, containerKey := range []string{"containers", "initContainers"} {
		containers, ok := podSpec[containerKey].([]interface{})
		if !ok {
			continue
		}
		for _, c := range containers {
			cm, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			containerName, _ := cm["name"].(string)

			// env[*].valueFrom.secretKeyRef.name
			if envList, ok := cm["env"].([]interface{}); ok {
				for _, e := range envList {
					em, ok := e.(map[string]interface{})
					if !ok {
						continue
					}
					if vf, ok := em["valueFrom"].(map[string]interface{}); ok {
						if skr, ok := vf["secretKeyRef"].(map[string]interface{}); ok {
							if sname, ok := skr["name"].(string); ok && sname != "" {
								key, _ := skr["key"].(string)
								refs = append(refs, model.SecretReference{
									SecretName:        sname,
									Namespace:         ns,
									RefType:           string(model.RefTypeEnv),
									ResourceKind:      kind,
									ResourceName:      name,
									ResourceNamespace: ns,
									ContainerName:     containerName,
									Key:               key,
									SourceFile:        file,
								})
							}
						}
					}
				}
			}

			// envFrom[*].secretRef.name
			if envFromList, ok := cm["envFrom"].([]interface{}); ok {
				for _, ef := range envFromList {
					efm, ok := ef.(map[string]interface{})
					if !ok {
						continue
					}
					if sr, ok := efm["secretRef"].(map[string]interface{}); ok {
						if sname, ok := sr["name"].(string); ok && sname != "" {
							refs = append(refs, model.SecretReference{
								SecretName:        sname,
								Namespace:         ns,
								RefType:           string(model.RefTypeEnvFrom),
								ResourceKind:      kind,
								ResourceName:      name,
								ResourceNamespace: ns,
								ContainerName:     containerName,
								SourceFile:        file,
							})
						}
					}
				}
			}
		}
	}

	return refs
}

// extractFromServiceAccount reads imagePullSecrets from a ServiceAccount.
func extractFromServiceAccount(raw map[string]interface{}, name, ns, file string) []model.SecretReference {
	var refs []model.SecretReference
	if ips, ok := raw["imagePullSecrets"].([]interface{}); ok {
		for _, item := range ips {
			if m, ok := item.(map[string]interface{}); ok {
				if sname, ok := m["name"].(string); ok && sname != "" {
					refs = append(refs, model.SecretReference{
						SecretName:        sname,
						Namespace:         ns,
						RefType:           string(model.RefTypeServiceAccountPullSecret),
						ResourceKind:      "ServiceAccount",
						ResourceName:      name,
						ResourceNamespace: ns,
						SourceFile:        file,
					})
				}
			}
		}
	}
	return refs
}

// extractFromAnnotations checks well-known annotation keys for secret references.
func extractFromAnnotations(ann map[string]string, kind, name, ns, file string) []model.SecretReference {
	var refs []model.SecretReference
	for k, v := range ann {
		if isSecretAnnotation(k) && v != "" {
			refs = append(refs, model.SecretReference{
				SecretName:        v,
				Namespace:         ns,
				RefType:           string(model.RefTypeAnnotation),
				ResourceKind:      kind,
				ResourceName:      name,
				ResourceNamespace: ns,
				Key:               k,
				SourceFile:        file,
			})
		}
	}
	return refs
}

func isSecretAnnotation(key string) bool {
	return key == "checksum/secret" ||
		key == "secret.reloader.stakater.com/reload" ||
		key == "reloader.stakater.com/search" ||
		strings.HasPrefix(key, "vault.hashicorp.com/agent-inject-secret-") ||
		strings.HasPrefix(key, "external-secrets.io/") ||
		(strings.HasPrefix(key, "argocd.argoproj.io/") && strings.Contains(key, "secret"))
}

// nestedMap is a helper to safely navigate a map hierarchy.
func nestedMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	v, _ := m[key].(map[string]interface{})
	return v
}
