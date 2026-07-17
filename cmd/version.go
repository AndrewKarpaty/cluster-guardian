package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags "-X ....cmd.Version=v1.2.3".
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the cluster-guardian version",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "cluster-guardian %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
