package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/chrismeyersfsu/safe-secret/internal/secrets"
)

type Status struct {
	Status          string   `json:"status"`
	CachedSecrets   int      `json:"cached_secrets"`
	MitmHosts       []string `json:"mitm_hosts"`
	UptimeSeconds   float64  `json:"uptime_seconds"`
	BWSession       string   `json:"bw_session"`
	LastRefresh     *string  `json:"last_refresh"`
	RefreshFailures int      `json:"refresh_failures"`
}

type RefreshStatus struct {
	mu                  sync.RWMutex
	sessionActive       bool
	lastRefresh         time.Time
	consecutiveFailures int
}

func NewRefreshStatus() *RefreshStatus {
	return &RefreshStatus{sessionActive: true}
}

func (rs *RefreshStatus) SetRefreshOK() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.lastRefresh = time.Now()
	rs.consecutiveFailures = 0
	rs.sessionActive = true
}

func (rs *RefreshStatus) SetRefreshFailed() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.consecutiveFailures++
}

func (rs *RefreshStatus) SetSessionExpired() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.sessionActive = false
}

func (rs *RefreshStatus) Get() (sessionActive bool, lastRefresh time.Time, failures int) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.sessionActive, rs.lastRefresh, rs.consecutiveFailures
}

type Server struct {
	mu            sync.RWMutex
	store         secrets.SecretStore
	refreshStatus *RefreshStatus
	startTime     time.Time
	server        *http.Server
	listenAddr    string
	path          string
}

func NewServer(listenAddr, path string, store secrets.SecretStore, refreshStatus *RefreshStatus) *Server {
	return &Server{
		store:         store,
		refreshStatus: refreshStatus,
		listenAddr:    listenAddr,
		path:          path,
		startTime:     time.Now(),
	}
}

func (s *Server) SwapStore(newStore secrets.SecretStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = newStore
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
	s.mu.RLock()
	store := s.store
	s.mu.RUnlock()

	var cachedSecrets int
	var mitmHosts []string

	if store != nil {
		cachedSecrets = store.Count()
		mitmHosts = store.AllHosts()
	}

	response := Status{
		Status:        "healthy",
		CachedSecrets: cachedSecrets,
		MitmHosts:     mitmHosts,
		UptimeSeconds: time.Since(s.startTime).Seconds(),
		BWSession:     "active",
	}

	statusCode := http.StatusOK

	if s.refreshStatus != nil {
		sessionActive, lastRefresh, failures := s.refreshStatus.Get()
		response.RefreshFailures = failures

		if !lastRefresh.IsZero() {
			ts := lastRefresh.UTC().Format(time.RFC3339)
			response.LastRefresh = &ts
		}

		if !sessionActive {
			response.BWSession = "expired"
			response.Status = "degraded"
			statusCode = http.StatusServiceUnavailable
		} else if failures > 0 {
			response.Status = "degraded"
			statusCode = http.StatusServiceUnavailable
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}
