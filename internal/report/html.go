package report

import (
	"html/template"
	"io"
)

// WriteHTML renders a self-contained HTML report (no external assets), used
// for file export. Filtering, search and collapsible sections work offline.
func WriteHTML(w io.Writer, r *Report) error {
	return htmlTemplate.Execute(w, htmlData{Report: r})
}

// WriteDashboard renders the same report plus the live controls (auto-refresh
// and JSON/Markdown download) that need the serve-mode REST API.
func WriteDashboard(w io.Writer, r *Report) error {
	return htmlTemplate.Execute(w, htmlData{Report: r, Dashboard: true})
}

type htmlData struct {
	*Report
	Dashboard bool
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"count": func(fs []Finding, severity string) int {
		n := 0
		for _, f := range fs {
			if f.Severity.String() == severity {
				n++
			}
		}
		return n
	},
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cluster Guardian — {{.ClusterName}}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; margin: 0; }
  body { font: 15px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #f4f5f7; color: #1d2433; padding: 2rem 1rem; }
  @media (prefers-color-scheme: dark) {
    body { background: #14161c; color: #e6e8ee; }
    .card { background: #1d2028 !important; }
    .toolbar input, .toolbar select { background: #14161c; color: #e6e8ee; }
  }
  main { max-width: 880px; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin-bottom: .25rem; }
  .meta { opacity: .65; margin-bottom: 1.5rem; }
  .summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem; }
  .stat { flex: 1 1 8rem; padding: .75rem 1rem; border-radius: 10px; background: rgba(127,127,127,.12); }
  .stat b { display: block; font-size: 1.4rem; }
  .card { background: #fff; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card h2 { font-size: 1.05rem; display: inline; }
  details.card > summary { cursor: pointer; list-style: none; display: flex; align-items: center; gap: .6rem; }
  details.card > summary::-webkit-details-marker { display: none; }
  details.card > summary .counts { margin-left: auto; display: flex; gap: .35rem; align-items: center; }
  details.card > summary .chev { opacity: .45; transition: transform .15s; }
  details.card[open] > summary .chev { transform: rotate(180deg); }
  details.card[open] > summary { margin-bottom: .5rem; }
  .toolbar { display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; }
  .toolbar input[type=search] { flex: 1 1 12rem; padding: .45rem .7rem; border-radius: 8px;
                                border: 1px solid rgba(127,127,127,.35); font: inherit; }
  .toolbar select { padding: .45rem .5rem; border-radius: 8px; border: 1px solid rgba(127,127,127,.35); font: inherit; }
  .chips { display: flex; gap: .35rem; }
  .chip { font: inherit; font-size: .75rem; font-weight: 600; text-transform: uppercase; letter-spacing: .04em;
          padding: .25rem .6rem; border-radius: 99px; border: 1px solid rgba(127,127,127,.35);
          background: transparent; color: inherit; cursor: pointer; opacity: .4; }
  .chip.active { opacity: 1; }
  .chip.critical.active { background: #fadada; color: #a12626; border-color: transparent; }
  .chip.warning.active  { background: #fdeeca; color: #8a6100; border-color: transparent; }
  .chip.info.active     { background: #dcebfa; color: #1f5f9e; border-color: transparent; }
  .chip.ok.active       { background: #d9f2e2; color: #1a7f42; border-color: transparent; }
  .toggle { display: flex; gap: .35rem; align-items: center; font-size: .85rem; cursor: pointer; }
  .btn { font-size: .85rem; padding: .35rem .7rem; border-radius: 8px; text-decoration: none;
         color: inherit; border: 1px solid rgba(127,127,127,.35); }
  ul { list-style: none; }
  li { padding: .3rem 0; display: flex; gap: .6rem; align-items: baseline; }
  .badge { font-size: .7rem; font-weight: 600; text-transform: uppercase; letter-spacing: .04em;
           padding: .1rem .45rem; border-radius: 99px; white-space: nowrap; }
  .badge.ok       { background: #d9f2e2; color: #1a7f42; }
  .badge.info     { background: #dcebfa; color: #1f5f9e; }
  .badge.warning  { background: #fdeeca; color: #8a6100; }
  .badge.critical { background: #fadada; color: #a12626; }
  .hint { display: block; font-size: .85rem; opacity: .6; margin-left: 0; }
  footer { text-align: center; opacity: .5; font-size: .8rem; margin-top: 2rem; }
</style>
</head>
<body>
<main>
  <h1>🛡️ Cluster: {{.ClusterName}}</h1>
  <p class="meta">Generated {{.GeneratedAt.Format "2006-01-02 15:04 UTC"}}{{with .KubernetesVersion}} · Kubernetes {{.}}{{end}}</p>

  <div class="summary">
    <div class="stat"><b>{{.Summary.Namespaces}}</b>namespaces</div>
    <div class="stat"><b>{{.Summary.Total}}</b>findings</div>
    <div class="stat"><b>{{.Summary.Warnings}}</b>warnings</div>
    <div class="stat"><b>{{.Summary.Critical}}</b>critical</div>
  </div>

  <div class="toolbar card">
    <input id="search" type="search" placeholder="Search findings…" aria-label="Search findings">
    <div class="chips">
      <button class="chip critical active" data-sev="critical">critical</button>
      <button class="chip warning active" data-sev="warning">warning</button>
      <button class="chip info active" data-sev="info">info</button>
      <button class="chip ok active" data-sev="ok">ok</button>
    </div>
    <select id="nsfilter" aria-label="Filter by namespace">
      <option value="">All namespaces</option>
      {{range .Namespaces}}<option>{{.Name}}</option>{{end}}
    </select>
    {{if .Dashboard}}
    <label class="toggle"><input type="checkbox" id="autorefresh"> auto-refresh</label>
    <a class="btn" href="/api/report" download="report.json">JSON</a>
    <a class="btn" href="/api/report/markdown" download="report.md">Markdown</a>
    {{end}}
  </div>

  {{range .Namespaces}}{{if .Findings}}
  <details class="card" open data-ns="{{.Name}}">
    <summary><h2>📦 Namespace: {{.Name}}</h2>{{template "counts" .Findings}}</summary>
    {{template "findings" .Findings}}
  </details>
  {{end}}{{end}}

  {{range .Sections}}{{if .Findings}}
  <details class="card" open>
    <summary><h2>{{.Icon}} {{.Title}}</h2>{{template "counts" .Findings}}</summary>
    {{template "findings" .Findings}}
  </details>
  {{end}}{{end}}

  <footer>Generated by Cluster Guardian</footer>
</main>
<script>
(function () {
  var search = document.getElementById('search');
  var nsSel = document.getElementById('nsfilter');
  var chips = Array.prototype.slice.call(document.querySelectorAll('.chip'));

  function apply() {
    var q = search.value.toLowerCase();
    var ns = nsSel.value;
    var active = {};
    chips.forEach(function (c) { if (c.classList.contains('active')) active[c.dataset.sev] = true; });
    document.querySelectorAll('details.card').forEach(function (card) {
      if (ns && card.dataset.ns && card.dataset.ns !== ns) { card.style.display = 'none'; return; }
      var visible = 0;
      card.querySelectorAll('li[data-sev]').forEach(function (li) {
        var show = !!active[li.dataset.sev] && (!q || li.textContent.toLowerCase().indexOf(q) !== -1);
        li.style.display = show ? '' : 'none';
        if (show) visible++;
      });
      card.style.display = visible ? '' : 'none';
    });
  }
  search.addEventListener('input', apply);
  nsSel.addEventListener('change', apply);
  chips.forEach(function (c) {
    c.addEventListener('click', function () { c.classList.toggle('active'); apply(); });
  });

  var auto = document.getElementById('autorefresh');
  if (auto) {
    var timer = null;
    var setTimer = function (on) {
      if (timer) { clearInterval(timer); timer = null; }
      if (on) { timer = setInterval(function () { window.location = '/?refresh=true'; }, 60000); }
    };
    auto.checked = localStorage.getItem('cg-autorefresh') === '1';
    setTimer(auto.checked);
    auto.addEventListener('change', function () {
      localStorage.setItem('cg-autorefresh', auto.checked ? '1' : '0');
      setTimer(auto.checked);
    });
  }
})();
</script>
</body>
</html>
{{define "counts"}}<span class="counts">{{with count . "critical"}}<span class="badge critical">{{.}}</span>{{end}}{{with count . "warning"}}<span class="badge warning">{{.}}</span>{{end}}<span class="chev">▾</span></span>{{end}}
{{define "findings"}}<ul>
  {{range .}}
  <li data-sev="{{.Severity}}"><span class="badge {{.Severity}}">{{.Severity}}</span>
    <div>{{.Message}}{{with .Hint}}<span class="hint">{{.}}</span>{{end}}</div></li>
  {{end}}
</ul>{{end}}
`))
