package model

// SecretRefType describes how a Secret is referenced.
type SecretRefType string

const (
	RefTypeEnv                      SecretRefType = "env"
	RefTypeEnvFrom                  SecretRefType = "envFrom"
	RefTypeVolume                   SecretRefType = "volume"
	RefTypeProjectedVolume          SecretRefType = "projectedVolume"
	RefTypeImagePullSecret          SecretRefType = "imagePullSecret"
	RefTypeServiceAccountPullSecret SecretRefType = "serviceAccountImagePullSecret"
	RefTypeCSI                      SecretRefType = "csi"
	RefTypeAnnotation               SecretRefType = "annotation"
	RefTypeUnknown                  SecretRefType = "unknown"
)

// SecretReference records a single usage of a Secret by a Kubernetes resource.
type SecretReference struct {
	SecretName        string `json:"secret_name"`
	Namespace         string `json:"namespace"`
	RefType           string `json:"ref_type"`
	ResourceKind      string `json:"resource_kind"`
	ResourceName      string `json:"resource_name"`
	ResourceNamespace string `json:"resource_namespace"`
	ContainerName     string `json:"container_name,omitempty"`
	Key               string `json:"key,omitempty"`
	Path              string `json:"path,omitempty"`
	SourceFile        string `json:"source_file,omitempty"`
	Line              int    `json:"line,omitempty"`
}

// SecretInventoryItem represents a known Secret.
type SecretInventoryItem struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Source     string `json:"source"`
	SourceFile string `json:"source_file,omitempty"`
	Used       bool   `json:"used"`
	RefCount   int    `json:"ref_count"`
}

// Finding is a risk-annotated observation about a Secret.
type Finding struct {
	Risk        string `json:"risk"`
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Explanation string `json:"explanation"`
	Suggestion  string `json:"suggestion"`
	SecretName  string `json:"secret_name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
}

// Summary holds aggregate counts for a ScanReport.
type Summary struct {
	TotalSecrets       int `json:"total_secrets"`
	TotalReferences    int `json:"total_references"`
	UnusedSecrets      int `json:"unused_secrets"`
	HighRiskFindings   int `json:"high_risk_findings"`
	MediumRiskFindings int `json:"medium_risk_findings"`
	LowRiskFindings    int `json:"low_risk_findings"`
}

// ScanReport is the top-level output of a scan.
type ScanReport struct {
	Mode             string                `json:"mode"`
	ScannedFiles     int                   `json:"scanned_files"`
	ScannedResources int                   `json:"scanned_resources"`
	Secrets          []SecretInventoryItem `json:"secrets"`
	References       []SecretReference     `json:"references"`
	Findings         []Finding             `json:"findings"`
	Summary          Summary               `json:"summary"`
}
