package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/analyzer"
	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/kube"
	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/manifest"
	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/report"
	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/risk"
)

var (
	flagFile          string
	flagDir           string
	flagCluster       bool
	flagNamespace     string
	flagSecret        string
	flagFormat        string
	flagOutput        string
	flagIncludeUnused bool
	flagFailOnRisk    string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Kubernetes manifests or a live cluster for Secret usage",
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&flagFile, "file", "", "Path to a single manifest file (.yaml, .yml, .json)")
	scanCmd.Flags().StringVar(&flagDir, "dir", "", "Path to a directory of manifests (scanned recursively)")
	scanCmd.Flags().BoolVar(&flagCluster, "cluster", false, "Scan a live cluster using kubeconfig")
	scanCmd.Flags().StringVar(&flagNamespace, "namespace", "", "Filter by namespace")
	scanCmd.Flags().StringVar(&flagSecret, "secret", "", "Filter results by Secret name")
	scanCmd.Flags().StringVar(&flagFormat, "format", "text", "Output format: text, json, markdown")
	scanCmd.Flags().StringVar(&flagOutput, "output", "", "Write output to file instead of stdout")
	scanCmd.Flags().BoolVar(&flagIncludeUnused, "include-unused", false, "Include findings for Secrets with no references")
	scanCmd.Flags().StringVar(&flagFailOnRisk, "fail-on-risk", "none", "Exit non-zero if findings at or above risk level exist: none, low, medium, high")
}

func runScan(cmd *cobra.Command, args []string) error {
	if err := validateFlags(); err != nil {
		return err
	}

	var (
		secrets          []model.SecretInventoryItem
		refs             []model.SecretReference
		scannedFiles     int
		scannedResources int
		mode             string
		clusterMode      bool
	)

	if flagCluster {
		mode = "cluster"
		clusterMode = true
		r, err := runClusterScan()
		if err != nil {
			return err
		}
		secrets = r.Secrets
		refs = r.References
		scannedResources = r.Resources
		for _, w := range r.Warnings {
			fmt.Fprintln(os.Stderr, "warning:", w)
		}
	} else {
		mode = "manifests"
		r, files, resources, err := runManifestScan()
		if err != nil {
			return err
		}
		secrets = r.Secrets
		refs = r.References
		scannedFiles = files
		scannedResources = resources
	}

	// Apply --secret filter
	if flagSecret != "" {
		secrets = filterSecrets(secrets, flagSecret)
		refs = filterRefs(refs, flagSecret)
	}

	// Analyze
	opts := analyzer.Options{
		IncludeUnused: flagIncludeUnused,
		ClusterMode:   clusterMode,
	}
	secrets, findings := analyzer.Analyze(secrets, refs, opts)

	// Apply namespace filter to results display
	if flagNamespace != "" {
		secrets = filterSecretsByNS(secrets, flagNamespace)
		refs = filterRefsByNS(refs, flagNamespace)
		findings = filterFindingsByNS(findings, flagNamespace)
	}

	r := &model.ScanReport{
		Mode:             mode,
		ScannedFiles:     scannedFiles,
		ScannedResources: scannedResources,
		Secrets:          secrets,
		References:       refs,
		Findings:         findings,
	}
	report.Build(r)

	if err := report.WriteToOutput(r, flagFormat, flagOutput); err != nil {
		return err
	}

	if report.ShouldFailOnRisk(r, flagFailOnRisk) {
		os.Exit(1)
	}

	return nil
}

func validateFlags() error {
	sources := 0
	if flagFile != "" {
		sources++
	}
	if flagDir != "" {
		sources++
	}
	if flagCluster {
		sources++
	}
	if sources == 0 {
		return fmt.Errorf("one of --file, --dir, or --cluster is required")
	}
	if sources > 1 {
		return fmt.Errorf("--file, --dir, and --cluster are mutually exclusive")
	}

	if flagFile != "" {
		if _, err := os.Stat(flagFile); os.IsNotExist(err) {
			return fmt.Errorf("--file does not exist: %s", flagFile)
		}
	}
	if flagDir != "" {
		if info, err := os.Stat(flagDir); os.IsNotExist(err) || !info.IsDir() {
			return fmt.Errorf("--dir does not exist or is not a directory: %s", flagDir)
		}
	}

	switch flagFormat {
	case "text", "json", "markdown":
	default:
		return fmt.Errorf("--format must be text, json, or markdown; got: %s", flagFormat)
	}

	if !risk.Valid(flagFailOnRisk) {
		return fmt.Errorf("--fail-on-risk must be none, low, medium, or high; got: %s", flagFailOnRisk)
	}

	return nil
}

func runManifestScan() (*manifest.ScanResult, int, int, error) {
	var files []string

	if flagFile != "" {
		files = []string{flagFile}
	} else {
		var err error
		files, err = manifest.WalkDir(flagDir)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("walking directory: %w", err)
		}
	}

	var resources []*manifest.KubeResource
	for _, f := range files {
		parsed, errs := manifest.ParseFile(f)
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "parse error:", e)
		}
		resources = append(resources, parsed...)
	}

	result := manifest.ScanResources(resources, flagNamespace)
	result.Files = len(files)
	return result, len(files), result.Resources, nil
}

func runClusterScan() (*kube.ScanResult, error) {
	client, err := kube.NewClient()
	if err != nil {
		return nil, fmt.Errorf("building kube client: %w", err)
	}
	return kube.Scan(context.Background(), client, flagNamespace)
}

func filterSecrets(secrets []model.SecretInventoryItem, name string) []model.SecretInventoryItem {
	var out []model.SecretInventoryItem
	for _, s := range secrets {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

func filterRefs(refs []model.SecretReference, name string) []model.SecretReference {
	var out []model.SecretReference
	for _, r := range refs {
		if r.SecretName == name {
			out = append(out, r)
		}
	}
	return out
}

func filterSecretsByNS(secrets []model.SecretInventoryItem, ns string) []model.SecretInventoryItem {
	var out []model.SecretInventoryItem
	for _, s := range secrets {
		if s.Namespace == ns {
			out = append(out, s)
		}
	}
	return out
}

func filterRefsByNS(refs []model.SecretReference, ns string) []model.SecretReference {
	var out []model.SecretReference
	for _, r := range refs {
		if r.Namespace == ns || r.ResourceNamespace == ns {
			out = append(out, r)
		}
	}
	return out
}

func filterFindingsByNS(findings []model.Finding, ns string) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if f.Namespace == ns {
			out = append(out, f)
		}
	}
	return out
}
