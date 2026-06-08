package cmd

import (
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
	Long:  "Commands for validating, dumping, and generating configuration files",
}

func init() {
	rootCmd.AddCommand(configCmd)
}
