package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Force immediate secret refresh",
	Long:  "Send SIGHUP to the running proxy to trigger an immediate Bitwarden refresh",
	RunE:  runReload,
}

func init() {
	rootCmd.AddCommand(reloadCmd)
}

func runReload(cmd *cobra.Command, args []string) error {
	pidBytes, err := os.ReadFile(pidFilePath())
	if err != nil {
		return fmt.Errorf("proxy not running (no PID file at %s): %w", pidFilePath(), err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		return fmt.Errorf("invalid PID file: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	if err := process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("send SIGHUP to %d: %w", pid, err)
	}

	fmt.Printf("reload signal sent to PID %d\n", pid)
	return nil
}
