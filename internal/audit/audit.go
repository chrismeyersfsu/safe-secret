package audit

import (
	"log/slog"
	"os"
)

type Logger struct {
	logger *slog.Logger
}

func New() *Logger {
	handler := slog.NewJSONHandler(os.Stdout, nil)
	return &Logger{
		logger: slog.New(handler),
	}
}

func (l *Logger) SecretInjected(reqID, lookup, placeholder, dstHost, dstPath, method string) {
	l.logger.Info("secret injected",
		"event", "secret_injected",
		"req_id", reqID,
		"lookup", lookup,
		"placeholder", placeholder,
		"dst_host", dstHost,
		"dst_path", dstPath,
		"method", method,
	)
}

func (l *Logger) SecretNotFound(reqID, lookup, placeholder, dstHost, dstPath, method string) {
	l.logger.Warn("secret not found",
		"event", "secret_not_found",
		"req_id", reqID,
		"lookup", lookup,
		"placeholder", placeholder,
		"dst_host", dstHost,
		"dst_path", dstPath,
		"method", method,
	)
}

func (l *Logger) HostBlocked(reqID, lookup, placeholder, dstHost, dstPath, method string) {
	l.logger.Warn("host blocked",
		"event", "host_blocked",
		"req_id", reqID,
		"lookup", lookup,
		"placeholder", placeholder,
		"dst_host", dstHost,
		"dst_path", dstPath,
		"method", method,
	)
}

func (l *Logger) ScrubHit(reqID, dstHost, dstPath, method string, scrubbedCount int) {
	l.logger.Info("scrub hit",
		"event", "scrub_hit",
		"req_id", reqID,
		"dst_host", dstHost,
		"dst_path", dstPath,
		"method", method,
		"scrubbed_count", scrubbedCount,
	)
}

func (l *Logger) ScrubSkipped(reqID, dstHost, reason string) {
	l.logger.Info("scrub skipped",
		"event", "scrub_skipped",
		"req_id", reqID,
		"dst_host", dstHost,
		"reason", reason,
	)
}

func (l *Logger) Tunnel(dstHost string) {
	l.logger.Info("tunnel established",
		"event", "tunnel",
		"dst_host", dstHost,
	)
}

func (l *Logger) RefreshOK(secretCount int) {
	l.logger.Info("refresh succeeded",
		"event", "refresh_ok",
		"secret_count", secretCount,
	)
}

func (l *Logger) RefreshFailed(err error, consecutiveFailures int) {
	logFn := l.logger.Warn
	if consecutiveFailures >= 3 {
		logFn = l.logger.Error
	}
	logFn("refresh failed",
		"event", "refresh_failed",
		"error", err.Error(),
		"consecutive_failures", consecutiveFailures,
	)
}

func (l *Logger) SessionExpired() {
	l.logger.Error("session expired",
		"event", "session_expired",
	)
}
