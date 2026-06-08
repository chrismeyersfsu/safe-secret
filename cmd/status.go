package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
	resp, err := http.Get("http://127.0.0.1:8081/healthz")
	if err != nil {
		return fmt.Errorf("GET /healthz: %w", err)
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
