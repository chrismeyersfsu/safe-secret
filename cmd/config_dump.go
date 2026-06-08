package cmd

import (
	"fmt"
	"os"

	"github.com/chrismeyersfsu/safe-secret/internal/config"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

var configDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump effective configuration",
	Long:  "Load and display the effective merged configuration as YAML",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return err
		}

		data, err := yaml.Marshal(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling config: %v\n", err)
			return err
		}

		fmt.Print(string(data))
		return nil
	},
}

func init() {
	configCmd.AddCommand(configDumpCmd)
}
