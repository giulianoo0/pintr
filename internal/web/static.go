package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// Static assets: logo/favicon SVGs, the social-embed banner, and the
// self-hosted Geist font subsets (serving them first-party removes the
// render-blocking Google Fonts round-trips).

//go:embed static
var staticFS embed.FS

//go:embed static/favicon.png
var faviconPNG []byte

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Embedded assets only change with a deploy; a day of caching is safe.
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.StripPrefix("/static/", files).ServeHTTP(w, r)
	})
}

func handleFavicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconPNG)
}

const robotsTxt = `User-agent: *
Disallow: /view
Disallow: /authorize
Disallow: /dashboard
`

func handleRobots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(robotsTxt))
}
