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
