package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the current release version. Set via ldflags at build time.
var Version = "0.1.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of ksecret-map",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ksecret-map version %s\n", Version)
	},
}
