package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/chrismeyersfsu/safe-secret/internal/config"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run diagnostic checks",
	RunE:  runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		fmt.Printf("✗ Config load failed: %v\n", err)
		return err
	}
	fmt.Println("✓ Config loaded")

	if err := config.Validate(cfg); err != nil {
		fmt.Printf("✗ Config validation failed: %v\n", err)
		return err
	}
	fmt.Println("✓ Config valid")

	if _, err := os.Stat(cfg.TLS.CACertPath); err != nil {
		fmt.Printf("✗ CA cert not found: %s\n", cfg.TLS.CACertPath)
	} else {
		fmt.Printf("✓ CA cert exists: %s\n", cfg.TLS.CACertPath)
	}

	if _, err := os.Stat(cfg.TLS.CAKeyPath); err != nil {
		fmt.Printf("✗ CA key not found: %s\n", cfg.TLS.CAKeyPath)
	} else {
		fmt.Printf("✓ CA key exists: %s\n", cfg.TLS.CAKeyPath)
	}

	if err := checkPortAvailable(cfg.Proxy.Listen); err != nil {
		fmt.Printf("✗ Proxy port %s unavailable: %v\n", cfg.Proxy.Listen, err)
	} else {
		fmt.Printf("✓ Proxy port %s available\n", cfg.Proxy.Listen)
	}

	if cfg.Health.Enabled {
		if err := checkPortAvailable(cfg.Health.Listen); err != nil {
			fmt.Printf("✗ Health port %s unavailable: %v\n", cfg.Health.Listen, err)
		} else {
			fmt.Printf("✓ Health port %s available\n", cfg.Health.Listen)
		}
	}

	return nil
}

func checkPortAvailable(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	listener.Close()
	return nil
}
