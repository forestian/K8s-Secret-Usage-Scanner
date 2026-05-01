package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ksecret-map",
	Short: "Scan Kubernetes manifests or a live cluster for Secret usage",
	Long: `ksecret-map scans Kubernetes manifests or a live cluster and shows
where Kubernetes Secrets are used, helping you answer:

  - Where is this Secret used?
  - Which Secrets are unused?
  - Which workloads depend on this Secret?
  - Can I safely delete or rotate this Secret?`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}
