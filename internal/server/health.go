package server

import (
	"context"
	"log/slog"
	"time"
)

const HealthLogInterval = 5 * time.Minute

// LogHealth reports local process readiness only. It does not probe payment,
// storage or other services, and frequent HTTP health probes remain silent.
func (s *Server) LogHealth(ctx context.Context) {
	ticker := time.NewTicker(HealthLogInterval)
	defer ticker.Stop()
	s.healthLogs(ctx, ticker.C)
}

func (s *Server) healthLogs(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok || ctx.Err() != nil {
				return
			}
			status := "ready"
			if s.Draining.Load() {
				status = "draining"
			}
			slog.InfoContext(ctx, "process health", "role", "server", "status", status, "active_requests", len(s.Slots), "capacity", cap(s.Slots))
		}
	}
}
