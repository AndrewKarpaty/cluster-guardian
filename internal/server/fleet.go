package server

import (
	"html/template"
	"io"
	"log"
	"net/http"

	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

func (s *Server) handleFleetPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := fleetTemplate.Execute(w, s.fleet.Statuses()); err != nil {
		log.Printf("rendering fleet page: %v", err)
	}
}

func (s *Server) handleClusters(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"clusters": s.fleet.Statuses()})
}

func (s *Server) handleClusterDashboard(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	r := s.fleet.Report(name)
	if r == nil {
		http.Error(w, "unknown cluster or not scanned yet", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := report.WriteClusterDashboard(w, r, "/api/clusters/"+name, "/"); err != nil {
		log.Printf("rendering cluster dashboard: %v", err)
	}
}

func (s *Server) handleClusterReport(render func(w io.Writer, r *report.Report) error, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r := s.fleet.Report(req.PathValue("name"))
		if r == nil {
			http.Error(w, "unknown cluster or not scanned yet", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if err := render(w, r); err != nil {
			log.Printf("rendering cluster report: %v", err)
		}
	}
}

func (s *Server) handleClusterHistory(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, map[string]any{"entries": s.fleet.History(req.PathValue("name"))})
}

func (s *Server) handleClusterHistoryDiff(w http.ResponseWriter, req *http.Request) {
	d := s.fleet.Diff(req.PathValue("name"))
	if d == nil {
		d = &report.DiffResult{}
	}
	writeJSON(w, d)
}

var fleetTemplate = template.Must(template.New("fleet").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%232563EB' d='M12 1l9 3.4v7.4c0 5-3.6 8.7-9 10.7-5.4-2-9-5.7-9-10.7V4.4z'/%3E%3C/svg%3E">
<title>Cluster Guardian — Fleet</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f2f5f9; --card: #ffffff; --text: #17203a;
    --muted: rgba(23,32,58,.58); --line: rgba(23,32,58,.1);
    --accent: #2563eb;
    --ok-fg: #177a3f; --warn-fg: #8a6100; --crit-fg: #a12626;
    --shadow: 0 1px 2px rgba(15,23,42,.05), 0 4px 16px rgba(15,23,42,.06);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1117; --card: #181b23; --text: #e7eaf2;
      --muted: rgba(231,234,242,.55); --line: rgba(231,234,242,.09);
      --ok-fg: #4ade80; --warn-fg: #fbbf24; --crit-fg: #f87171;
      --shadow: 0 1px 2px rgba(0,0,0,.35);
    }
  }
  * { box-sizing: border-box; margin: 0; }
  body { font: 15px/1.55 -apple-system, "Segoe UI", Roboto, sans-serif;
         background: var(--bg); color: var(--text); padding: 2rem 1rem; }
  main { max-width: 1000px; margin: 0 auto; }
  h1 { font-size: 1.45rem; display: flex; align-items: center; gap: .6rem; margin-bottom: 1.25rem; }
  .logo { width: 34px; height: 34px; flex: none; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(270px, 1fr)); gap: 1rem; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 14px;
          padding: 1.1rem 1.25rem; box-shadow: var(--shadow); display: block;
          color: inherit; text-decoration: none; transition: border-color .15s; }
  .card:hover { border-color: var(--accent); }
  .card h2 { font-size: 1.02rem; margin-bottom: .25rem; word-break: break-all; }
  .row { display: flex; align-items: center; gap: .8rem; margin-top: .5rem; }
  .grade { font-size: 2.3rem; font-weight: 700; line-height: 1; }
  .grade.gA, .grade.gB { color: var(--ok-fg); }
  .grade.gC { color: var(--warn-fg); }
  .grade.gD { color: #c76b00; }
  .grade.gF { color: var(--crit-fg); }
  .meta { color: var(--muted); font-size: .85rem; }
  .err { color: var(--crit-fg); font-size: .85rem; word-break: break-all; margin-top: .5rem; }
  .counts { margin-left: auto; text-align: right; font-size: .85rem; color: var(--muted); }
</style>
</head>
<body>
<main>
  <h1><svg class="logo" viewBox="0 0 512 512" fill="none" aria-hidden="true"><defs><linearGradient id="lg" x1="68" y1="40" x2="444" y2="472" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#2563EB"/><stop offset="1" stop-color="#0EA5E9"/></linearGradient></defs><path d="M256 40 L444 110 V268 C444 375 366 442 256 472 C146 442 68 375 68 268 V110 Z" fill="url(#lg)"/><g stroke="#FFF" stroke-opacity=".85" stroke-width="14" stroke-linecap="round"><path d="M256 250 L256 150"/><path d="M256 250 L170 316"/><path d="M256 250 L342 316"/></g><g fill="#FFF" fill-opacity=".95"><circle cx="256" cy="142" r="24"/><circle cx="164" cy="322" r="24"/><circle cx="348" cy="322" r="24"/></g><circle cx="256" cy="250" r="42" fill="#FFF"/><path d="M238 251 L252 265 L278 235" stroke="url(#lg)" stroke-width="14" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg> Cluster Guardian — Fleet</h1>
  <div class="grid">
    {{range .}}
    <a class="card" href="/clusters/{{.Name}}">
      <h2>{{.Name}}</h2>
      <p class="meta">{{.Server}}</p>
      {{if .Summary}}
      <div class="row">
        <span class="grade g{{.Summary.Grade}}">{{.Summary.Grade}}</span>
        <span class="meta">{{.Summary.Score}}/100</span>
        <span class="counts">{{.Summary.Critical}} critical<br>{{.Summary.Warnings}} warnings</span>
      </div>
      {{end}}
      {{if .Error}}<p class="err">⚠ {{.Error}}</p>{{end}}
      {{if not .LastScan.IsZero}}<p class="meta">scanned {{.LastScan.Format "15:04:05 UTC"}}</p>{{end}}
    </a>
    {{end}}
  </div>
</main>
</body>
</html>
`))
