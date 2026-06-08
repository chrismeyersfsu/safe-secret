package cmd

import (
	"fmt"
	"os"

	"github.com/chrismeyersfsu/safe-secret/internal/config"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

var configInitOutputFile string

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate default configuration",
	Long:  "Generate a default configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Defaults()

		data, err := yaml.Marshal(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling config: %v\n", err)
			return err
		}

		if configInitOutputFile != "" {
			if err := os.WriteFile(configInitOutputFile, data, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing config file: %v\n", err)
				return err
			}
			fmt.Printf("Config written to %s\n", configInitOutputFile)
		} else {
			fmt.Print(string(data))
		}

		return nil
	},
}

func init() {
	configCmd.AddCommand(configInitCmd)
	configInitCmd.Flags().StringVarP(&configInitOutputFile, "output", "o", "", "Output file path (default: stdout)")
}
