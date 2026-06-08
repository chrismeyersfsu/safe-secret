package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/chrismeyersfsu/safe-secret/internal/secrets"
)

type Status struct {
	Status        string   `json:"status"`
	CachedSecrets int      `json:"cached_secrets"`
	MitmHosts     []string `json:"mitm_hosts"`
	UptimeSeconds float64  `json:"uptime_seconds"`
}

type Server struct {
	store      secrets.SecretStore
	startTime  time.Time
	server     *http.Server
	listenAddr string
	path       string
}

func NewServer(listenAddr, path string, store secrets.SecretStore) *Server {
	return &Server{
		store:      store,
		listenAddr: listenAddr,
		path:       path,
		startTime:  time.Now(),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handleHealth)

	s.server = &http.Server{
		Addr:    s.listenAddr,
		Handler: mux,
	}

	go s.server.ListenAndServe()
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	var cachedSecrets int
	var mitmHosts []string

	if s.store != nil {
		cachedSecrets = s.store.Count()
		mitmHosts = s.store.AllHosts()
	}

	response := Status{
		Status:        "healthy",
		CachedSecrets: cachedSecrets,
		MitmHosts:     mitmHosts,
		UptimeSeconds: time.Since(s.startTime).Seconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
