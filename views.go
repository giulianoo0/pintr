package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"html/template"
	"log"
	"net/http"
	"net/url"
)

// All HTML lives in templates/ and is rendered with html/template, so every
// interpolated value gets contextual auto-escaping — no hand-rolled
// html.EscapeString calls to forget.

//go:embed templates/*.tmpl
var templateFS embed.FS

//go:embed templates/styles.css
var stylesCSS string

var pageTemplates = template.Must(template.New("").Funcs(template.FuncMap{
	"styles":    func() template.CSS { return template.CSS(stylesCSS) },
	"shortDate": shortDate,
}).ParseFS(templateFS, "templates/*.tmpl"))

// dashScript is the dashboard's only JavaScript: confirmation prompts for
// destructive forms (declared via data-confirm) and the live "updated Xm ago ·
// next refresh in Ym Zs" ticker on each ".fresh" element. The ticker counts
// from server-provided data-age/data-left deltas plus client-side elapsed
// time, so it isn't affected by clock skew. It is injected as a typed
// template.JS constant so its CSP hash can be computed from the same value.
const dashScript = `(function(){
  document.addEventListener('submit',function(e){
    var msg=e.target.getAttribute('data-confirm');
    if(msg&&!confirm(msg))e.preventDefault();
  });
  var start=Date.now();
  function fmt(age,left){
    var am=Math.floor(age/60);
    var updated=am<1?'updated just now':'updated '+am+'m ago';
    if(left<=0)return updated+' · refreshes on next load';
    var lm=Math.floor(left/60),ls=Math.floor(left%60);
    return updated+' · next refresh in '+lm+'m '+(ls<10?'0':'')+ls+'s';
  }
  function tick(){
    var el=(Date.now()-start)/1000;
    document.querySelectorAll('.fresh').forEach(function(n){
      var age=(+n.dataset.age)+el, left=Math.max(0,(+n.dataset.left)-el);
      n.textContent=fmt(age,left);
    });
  }
  tick();setInterval(tick,1000);
})();`

// pageCSP locks pages down to what they actually use: inline styles + Google
// Fonts, and only the dashboard script (allowed by hash — inline handlers are
// blocked, which is why forms use data-confirm instead of onsubmit).
var pageCSP = func() string {
	sum := sha256.Sum256([]byte(dashScript))
	return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; " +
		"style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; " +
		"img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
}()

func securePageHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Authenticated, user-specific pages: don't let a proxy cache them, and
	// don't let another site frame them (clickjacking on the consent page).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", pageCSP)
}

// renderTemplate executes a named page template into a buffer first, so a
// template error becomes a clean 500 instead of a half-written page.
func renderTemplate(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	securePageHeaders(w)
	_, _ = w.Write(buf.Bytes())
}

// basePage is the data every simple page needs; Nav picks the header's right
// side ("public" or "authed").
type basePage struct {
	Title string
	Nav   string
}

func publicPage(title string) basePage { return basePage{Title: title, Nav: "public"} }
func authedPage(title string) basePage { return basePage{Title: title, Nav: "authed"} }

type messagePage struct {
	basePage
	Error    string
	BackHref string
	BackText string
}

// renderMessage shows an error (or notice) with a single link back.
func renderMessage(w http.ResponseWriter, base basePage, errText, backHref, backText string) {
	renderTemplate(w, "message", messagePage{basePage: base, Error: errText, BackHref: backHref, BackText: backText})
}

type hiddenField struct {
	Name  string
	Value string
}

type consentPage struct {
	basePage
	Email  string
	CSRF   string
	Hidden []hiddenField
}

// renderConsent is the MCP OAuth consent screen (called from the authorize
// endpoint). The OAuth params are echoed as hidden fields so the POST carries
// them back.
func renderConsent(w http.ResponseWriter, session sessionInfo, query url.Values) {
	var hidden []hiddenField
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "resource", "scope"} {
		if value := query.Get(key); value != "" {
			hidden = append(hidden, hiddenField{Name: key, Value: value})
		}
	}
	renderTemplate(w, "consent", consentPage{
		basePage: authedPage("authorize"),
		Email:    session.User.Email,
		CSRF:     session.CSRF,
		Hidden:   hidden,
	})
}
