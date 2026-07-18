// Package server exposes the analyzer as a REST API and a web dashboard.
package server

import (
	"context"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/AndrewKarpaty/cluster-guardian/internal/analyzer"
	"github.com/AndrewKarpaty/cluster-guardian/internal/kube"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// Server serves the dashboard and REST API. Reports are cached briefly so a
// busy dashboard doesn't hammer the API server.
type Server struct {
	client *kube.Client
	opts   analyzer.Options
	ttl    time.Duration

	mu       sync.Mutex
	cached   *report.Report
	cachedAt time.Time
}

// New returns a Server that analyzes via client and caches reports for cacheTTL.
func New(client *kube.Client, opts analyzer.Options, cacheTTL time.Duration) *Server {
	return &Server{client: client, opts: opts, ttl: cacheTTL}
}

// Handler returns the HTTP routes for the dashboard, REST API and health probe.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /api/report", s.handleReport(report.WriteJSON, "application/json"))
	mux.HandleFunc("GET /api/report/markdown", s.handleReport(report.WriteMarkdown, "text/markdown; charset=utf-8"))
	mux.HandleFunc("GET /{$}", s.handleReport(report.WriteDashboard, "text/html; charset=utf-8"))
	return mux
}

// ListenAndServe blocks serving HTTP on addr.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("cluster-guardian dashboard listening on http://%s", addr)
	return srv.ListenAndServe()
}

func (s *Server) handleReport(render func(w io.Writer, r *report.Report) error, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r, err := s.report(req.Context(), req.URL.Query().Get("refresh") == "true")
		if err != nil {
			http.Error(w, "analysis failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if err := render(w, r); err != nil {
			log.Printf("rendering report: %v", err)
		}
	}
}

func (s *Server) report(ctx context.Context, forceRefresh bool) (*report.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !forceRefresh && s.cached != nil && time.Since(s.cachedAt) < s.ttl {
		return s.cached, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	r, err := analyzer.Run(ctx, s.client, s.opts)
	if err != nil {
		return nil, err
	}
	s.cached, s.cachedAt = r, time.Now()
	return r, nil
}
