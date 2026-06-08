package cmd

import (
	"fmt"
	"os"

	"github.com/chrismeyersfsu/safe-secret/internal/config"
	"github.com/spf13/cobra"
)

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration",
	Long:  "Load and validate the configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return err
		}

		if err := config.Validate(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
			return err
		}

		fmt.Println("Configuration is valid")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configValidateCmd)
}
