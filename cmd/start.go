package cmd

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/chrismeyersfsu/safe-secret/internal/audit"
	"github.com/chrismeyersfsu/safe-secret/internal/certgen"
	"github.com/chrismeyersfsu/safe-secret/internal/config"
	"github.com/chrismeyersfsu/safe-secret/internal/health"
	"github.com/chrismeyersfsu/safe-secret/internal/proxy"
	"github.com/chrismeyersfsu/safe-secret/internal/secrets"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proxy server",
	RunE:  runStart,
}

func init() {
	rootCmd.AddCommand(startCmd)
}

func runStart(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	certDir := filepath.Dir(cfg.TLS.CACertPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	caCert, err := certgen.LoadOrGenerate(cfg.TLS.CACertPath, cfg.TLS.CAKeyPath)
	if err != nil {
		return fmt.Errorf("load/generate CA: %w", err)
	}

	store := createTestStore()
	auditLogger := audit.New()

	proxyServer := proxy.NewProxyServer(store, caCert, auditLogger, cfg.Proxy.MaxIdleConnsPerHost)

	var healthServer *health.Server
	if cfg.Health.Enabled {
		healthServer = health.NewServer(cfg.Health.Listen, cfg.Health.Path, store)
		if err := healthServer.Start(); err != nil {
			return fmt.Errorf("start health server: %w", err)
		}
	}

	httpServer := &http.Server{
		Addr:    cfg.Proxy.Listen,
		Handler: proxyServer,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("proxy listening on %s", cfg.Proxy.Listen)
		errCh <- httpServer.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		log.Println("shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("proxy server error: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("proxy shutdown error: %v", err)
	}

	if healthServer != nil {
		if err := healthServer.Stop(ctx); err != nil {
			log.Printf("health shutdown error: %v", err)
		}
	}

	return nil
}

func createTestStore() *secrets.InMemoryStore {
	entries := []secrets.SecretEntry{
		{
			Name:         "GITHUB_TOKEN",
			ID:           "test-gh-id",
			Value:        []byte("ghp_test123"),
			AllowedHosts: []string{"api.github.com"},
		},
		{
			Name:         "GITLAB_TOKEN",
			ID:           "test-gl-id",
			Value:        []byte("glpat-test456"),
			AllowedHosts: []string{"gitlab.com"},
		},
	}

	store, _ := secrets.NewInMemoryStore(entries)
	return store
}
