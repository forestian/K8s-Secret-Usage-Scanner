package manifest

// KubeResource is a loosely-typed representation of any Kubernetes manifest.
// We decode into map[string]interface{} via yaml.v3 or encoding/json so we can
// handle arbitrary API versions without importing generated API types.
type KubeResource struct {
	APIVersion string                 `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                 `json:"kind"       yaml:"kind"`
	Metadata   ResourceMeta           `json:"metadata"   yaml:"metadata"`
	Raw        map[string]interface{} // full decoded document
	SourceFile string
	Line       int
}

// ResourceMeta holds the standard metadata fields we care about.
type ResourceMeta struct {
	Name        string            `json:"name"        yaml:"name"`
	Namespace   string            `json:"namespace"   yaml:"namespace"`
	Annotations map[string]string `json:"annotations" yaml:"annotations"`
}
