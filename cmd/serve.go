package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/AndrewKarpaty/cluster-guardian/internal/server"
)

var (
	flagListen   string
	flagCacheTTL time.Duration
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the REST API and web dashboard",
	Long: `Starts an HTTP server exposing:

  GET /                    web dashboard (HTML report)
  GET /api/report          report as JSON (append ?refresh=true to bypass cache)
  GET /api/report/markdown report as Markdown
  GET /healthz             liveness probe`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := newKubeClient()
		if err != nil {
			return err
		}
		srv := server.New(client, analyzerOptions(), flagCacheTTL)
		return srv.ListenAndServe(flagListen)
	},
}

func init() {
	serveCmd.Flags().StringVar(&flagListen, "listen", "127.0.0.1:8080", "address to listen on")
	serveCmd.Flags().DurationVar(&flagCacheTTL, "cache-ttl", 60*time.Second, "how long to cache analysis results")
	rootCmd.AddCommand(serveCmd)
}
