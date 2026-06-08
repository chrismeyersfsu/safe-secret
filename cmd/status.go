package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/chrismeyersfsu/safe-secret/internal/config"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check proxy health status",
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	url := fmt.Sprintf("http://%s%s", cfg.Health.Listen, cfg.Health.Path)
	resp, err := http.Get(url)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			fmt.Println("proxy not running")
			return nil
		}
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}

	prettyJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("format JSON: %w", err)
	}

	fmt.Println(string(prettyJSON))
	return nil
}
