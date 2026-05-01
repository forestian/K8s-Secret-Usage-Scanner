package kube

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

// ScanResult holds everything collected from the live cluster.
type ScanResult struct {
	Secrets    []model.SecretInventoryItem
	References []model.SecretReference
	Resources  int
	Warnings   []string
}

// Scan queries the cluster and returns all Secret inventory and references.
// If namespace is empty, all accessible namespaces are scanned.
func Scan(ctx context.Context, client *kubernetes.Clientset, namespace string) (*ScanResult, error) {
	result := &ScanResult{}

	// Secrets
	secrets, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("could not list secrets: %v", err))
	} else {
		for _, s := range secrets.Items {
			result.Resources++
			result.Secrets = append(result.Secrets, model.SecretInventoryItem{
				Name:      s.Name,
				Namespace: s.Namespace,
				Source:    "cluster",
			})
		}
	}

	// Pods
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("could not list pods: %v", err))
	} else {
		for i := range pods.Items {
			result.Resources++
			result.References = append(result.References, refsFromPodSpec(&pods.Items[i].Spec, "Pod", pods.Items[i].Name, pods.Items[i].Namespace)...)
			result.References = append(result.References, refsFromAnnotations(pods.Items[i].Annotations, "Pod", pods.Items[i].Name, pods.Items[i].Namespace)...)
		}
	}

	// Deployments
	deployments, err := client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("could not list deployments: %v", err))
	} else {
		for i := range deployments.Items {
			result.Resources++
			result.References = append(result.References, refsFromPodTemplateSpec(&deployments.Items[i].Spec.Template, "Deployment", deployments.Items[i].Name, deployments.Items[i].Namespace)...)
			result.References = append(result.References, refsFromAnnotations(deployments.Items[i].Annotations, "Deployment", deployments.Items[i].Name, deployments.Items[i].Namespace)...)
		}
	}

	// StatefulSets
	statefulSets, err := client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("could not list statefulsets: %v", err))
	} else {
		for i := range statefulSets.Items {
			result.Resources++
			result.References = append(result.References, refsFromPodTemplateSpec(&statefulSets.Items[i].Spec.Template, "StatefulSet", statefulSets.Items[i].Name, statefulSets.Items[i].Namespace)...)
			result.References = append(result.References, refsFromAnnotations(statefulSets.Items[i].Annotations, "StatefulSet", statefulSets.Items[i].Name, statefulSets.Items[i].Namespace)...)
		}
	}

	// DaemonSets
	daemonSets, err := client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("could not list daemonsets: %v", err))
	} else {
		for i := range daemonSets.Items {
			result.Resources++
			result.References = append(result.References, refsFromPodTemplateSpec(&daemonSets.Items[i].Spec.Template, "DaemonSet", daemonSets.Items[i].Name, daemonSets.Items[i].Namespace)...)
			result.References = append(result.References, refsFromAnnotations(daemonSets.Items[i].Annotations, "DaemonSet", daemonSets.Items[i].Name, daemonSets.Items[i].Namespace)...)
		}
	}

	// ReplicaSets
	replicaSets, err := client.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("could not list replicasets: %v", err))
	} else {
		for i := range replicaSets.Items {
			result.Resources++
			result.References = append(result.References, refsFromPodTemplateSpec(&replicaSets.Items[i].Spec.Template, "ReplicaSet", replicaSets.Items[i].Name, replicaSets.Items[i].Namespace)...)
		}
	}

	// Jobs
	jobs, err := client.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("could not list jobs: %v", err))
	} else {
		for i := range jobs.Items {
			result.Resources++
			result.References = append(result.References, refsFromPodTemplateSpec(&jobs.Items[i].Spec.Template, "Job", jobs.Items[i].Name, jobs.Items[i].Namespace)...)
		}
	}

	// CronJobs
	cronJobs, err := client.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("could not list cronjobs: %v", err))
	} else {
		for i := range cronJobs.Items {
			result.Resources++
			result.References = append(result.References, refsFromPodTemplateSpec(&cronJobs.Items[i].Spec.JobTemplate.Spec.Template, "CronJob", cronJobs.Items[i].Name, cronJobs.Items[i].Namespace)...)
		}
	}

	// ServiceAccounts
	sas, err := client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("could not list serviceaccounts: %v", err))
	} else {
		for i := range sas.Items {
			result.Resources++
			for _, ref := range sas.Items[i].ImagePullSecrets {
				result.References = append(result.References, model.SecretReference{
					SecretName:        ref.Name,
					Namespace:         sas.Items[i].Namespace,
					RefType:           string(model.RefTypeServiceAccountPullSecret),
					ResourceKind:      "ServiceAccount",
					ResourceName:      sas.Items[i].Name,
					ResourceNamespace: sas.Items[i].Namespace,
				})
			}
		}
	}

	return result, nil
}

func refsFromPodTemplateSpec(t *corev1.PodTemplateSpec, kind, name, ns string) []model.SecretReference {
	refs := refsFromPodSpec(&t.Spec, kind, name, ns)
	refs = append(refs, refsFromAnnotations(t.Annotations, kind, name, ns)...)
	return refs
}

func refsFromPodSpec(spec *corev1.PodSpec, kind, name, ns string) []model.SecretReference {
	var refs []model.SecretReference

	for _, ips := range spec.ImagePullSecrets {
		refs = append(refs, model.SecretReference{
			SecretName:        ips.Name,
			Namespace:         ns,
			RefType:           string(model.RefTypeImagePullSecret),
			ResourceKind:      kind,
			ResourceName:      name,
			ResourceNamespace: ns,
		})
	}

	for _, vol := range spec.Volumes {
		if vol.Secret != nil {
			refs = append(refs, model.SecretReference{
				SecretName:        vol.Secret.SecretName,
				Namespace:         ns,
				RefType:           string(model.RefTypeVolume),
				ResourceKind:      kind,
				ResourceName:      name,
				ResourceNamespace: ns,
			})
		}
		if vol.Projected != nil {
			for _, src := range vol.Projected.Sources {
				if src.Secret != nil {
					refs = append(refs, model.SecretReference{
						SecretName:        src.Secret.Name,
						Namespace:         ns,
						RefType:           string(model.RefTypeProjectedVolume),
						ResourceKind:      kind,
						ResourceName:      name,
						ResourceNamespace: ns,
					})
				}
			}
		}
		if vol.CSI != nil && vol.CSI.NodePublishSecretRef != nil {
			refs = append(refs, model.SecretReference{
				SecretName:        vol.CSI.NodePublishSecretRef.Name,
				Namespace:         ns,
				RefType:           string(model.RefTypeCSI),
				ResourceKind:      kind,
				ResourceName:      name,
				ResourceNamespace: ns,
			})
		}
	}

	allContainers := append(spec.InitContainers, spec.Containers...) //nolint:gocritic
	for _, c := range allContainers {
		for _, env := range c.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				refs = append(refs, model.SecretReference{
					SecretName:        env.ValueFrom.SecretKeyRef.Name,
					Namespace:         ns,
					RefType:           string(model.RefTypeEnv),
					ResourceKind:      kind,
					ResourceName:      name,
					ResourceNamespace: ns,
					ContainerName:     c.Name,
					Key:               env.ValueFrom.SecretKeyRef.Key,
				})
			}
		}
		for _, ef := range c.EnvFrom {
			if ef.SecretRef != nil {
				refs = append(refs, model.SecretReference{
					SecretName:        ef.SecretRef.Name,
					Namespace:         ns,
					RefType:           string(model.RefTypeEnvFrom),
					ResourceKind:      kind,
					ResourceName:      name,
					ResourceNamespace: ns,
					ContainerName:     c.Name,
				})
			}
		}
	}

	return refs
}

func refsFromAnnotations(ann map[string]string, kind, name, ns string) []model.SecretReference {
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
			})
		}
	}
	return refs
}

func isSecretAnnotation(key string) bool {
	return key == "checksum/secret" ||
		key == "secret.reloader.stakater.com/reload" ||
		key == "reloader.stakater.com/search" ||
		len(key) > 40 && key[:40] == "vault.hashicorp.com/agent-inject-secret-" ||
		hasPrefix(key, "external-secrets.io/") ||
		(hasPrefix(key, "argocd.argoproj.io/") && contains(key, "secret"))
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
