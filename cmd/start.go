package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chrismeyersfsu/safe-secret/internal/audit"
	"github.com/chrismeyersfsu/safe-secret/internal/bitwarden"
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

	session := readBWSession()
	if session == "" {
		return fmt.Errorf("BW_SESSION required: pipe from 'bw unlock --raw' or set BW_SESSION env var")
	}

	bwClient := bitwarden.NewClient(
		cfg.Bitwarden.CLIPath,
		time.Duration(cfg.Bitwarden.CLITimeout)*time.Second,
		cfg.Bitwarden.FolderName,
		session,
	)

	ctx := context.Background()

	if err := bwClient.CheckSession(ctx); err != nil {
		return fmt.Errorf("bitwarden session invalid: %w", err)
	}

	entries, err := bwClient.LoadSecrets(ctx)
	if err != nil {
		return fmt.Errorf("initial secret load: %w", err)
	}

	store, err := secrets.NewInMemoryStore(entries)
	if err != nil {
		return fmt.Errorf("create store: %w", err)
	}
	log.Printf("loaded %d secrets from Bitwarden", store.Count())

	auditLogger := audit.New()
	proxyServer := proxy.NewProxyServer(store, caCert, auditLogger, cfg.Proxy.MaxIdleConnsPerHost)

	refreshStatus := health.NewRefreshStatus()
	refreshStatus.SetRefreshOK()

	var healthServer *health.Server
	if cfg.Health.Enabled {
		healthServer = health.NewServer(cfg.Health.Listen, cfg.Health.Path, store, refreshStatus)
		if err := healthServer.Start(); err != nil {
			return fmt.Errorf("start health server: %w", err)
		}
	}

	if err := writePIDFile(); err != nil {
		log.Printf("warning: could not write PID file: %v", err)
	}

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	defer shutdownCancel()

	triggerCh := make(chan struct{}, 1)
	go startRefreshLoop(
		shutdownCtx,
		bwClient,
		proxyServer,
		healthServer,
		refreshStatus,
		auditLogger,
		time.Duration(cfg.Bitwarden.RefreshInterval)*time.Second,
		triggerCh,
	)

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
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				log.Println("SIGHUP received, triggering refresh")
				select {
				case triggerCh <- struct{}{}:
				default:
				}
				continue
			}
			log.Println("shutdown signal received")
			goto shutdown
		case err := <-errCh:
			return fmt.Errorf("proxy server error: %w", err)
		}
	}

shutdown:
	shutdownCancel()
	removePIDFile()

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(timeoutCtx); err != nil {
		log.Printf("proxy shutdown error: %v", err)
	}

	if healthServer != nil {
		if err := healthServer.Stop(timeoutCtx); err != nil {
			log.Printf("health shutdown error: %v", err)
		}
	}

	return nil
}

func readBWSession() string {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			session := strings.TrimSpace(scanner.Text())
			if session != "" {
				return session
			}
		}
	}

	return os.Getenv("BW_SESSION")
}

func startRefreshLoop(
	ctx context.Context,
	bwClient *bitwarden.Client,
	proxyServer *proxy.ProxyServer,
	healthServer *health.Server,
	refreshStatus *health.RefreshStatus,
	auditLogger *audit.Logger,
	interval time.Duration,
	triggerCh <-chan struct{},
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var consecutiveFailures int

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-triggerCh:
		}

		entries, err := bwClient.LoadSecrets(ctx)
		if err != nil {
			consecutiveFailures++
			auditLogger.RefreshFailed(err, consecutiveFailures)
			refreshStatus.SetRefreshFailed()
			continue
		}

		newStore, err := secrets.NewInMemoryStore(entries)
		if err != nil {
			consecutiveFailures++
			auditLogger.RefreshFailed(err, consecutiveFailures)
			refreshStatus.SetRefreshFailed()
			continue
		}

		proxyServer.SwapStore(newStore)
		if healthServer != nil {
			healthServer.SwapStore(newStore)
		}

		consecutiveFailures = 0
		refreshStatus.SetRefreshOK()
		auditLogger.RefreshOK(newStore.Count())
		log.Printf("refreshed %d secrets from Bitwarden", newStore.Count())
	}
}

func pidFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/safe-secret.pid"
	}
	return filepath.Join(home, ".config", "safe-secret", "safe-secret.pid")
}

func writePIDFile() error {
	path := pidFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644)
}

func removePIDFile() {
	os.Remove(pidFilePath())
}
