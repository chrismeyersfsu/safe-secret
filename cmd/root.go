package cmd

import (
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "safe-secret",
	Short: "Transport proxy for secret isolation",
	Long:  "Keep secrets out of user-space process memory by intercepting HTTP(S) requests at the transport layer and injecting secrets from a trusted, isolated proxy.",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ~/.config/safe-secret/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}
