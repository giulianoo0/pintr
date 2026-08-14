package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"

	"github.com/giulianoo0/pintr/internal/mcpserver"
	"github.com/giulianoo0/pintr/internal/store"
	"github.com/giulianoo0/pintr/internal/turnstile"
)

// All HTML lives in templates/ and is rendered with html/template, so every
// interpolated value gets contextual auto-escaping — no hand-rolled
// html.EscapeString calls to forget.

//go:embed templates/*.tmpl
var templateFS embed.FS

//go:embed templates/styles.css
var stylesCSS string

// plausibleScriptURL enables the optional, privacy-friendly Plausible page
// analytics: when PINTR_PLAUSIBLE_SCRIPT is set (the full script URL from the
// Plausible snippet), every page includes the script tag plus the static init
// stub below; when unset, nothing analytics-related is served.
var plausibleScriptURL = strings.TrimSpace(os.Getenv("PINTR_PLAUSIBLE_SCRIPT"))

const plausibleInit = `window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};plausible.init()`

// publicBase is the absolute https base for social-embed URLs; set once in
// New before any page renders.
var publicBase string

// buildCommit is the git revision go build stamps into the binary; empty when
// built without vcs info (e.g. go test), in which case the footer shows only
// the version.
var buildCommit = func() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}
	return ""
}()

func commitShort() string {
	if len(buildCommit) > 7 {
		return buildCommit[:7]
	}
	return buildCommit
}

func commitURL() string {
	if buildCommit == "" {
		return ""
	}
	return "https://github.com/giulianoo0/pintr/commit/" + buildCommit
}

var pageTemplates = template.Must(template.New("").Funcs(template.FuncMap{
	"styles":           func() template.CSS { return template.CSS(stylesCSS) },
	"script":           func() template.JS { return siteScript },
	"shortDate":        shortDate,
	"plausibleScript":  func() template.URL { return template.URL(plausibleScriptURL) },
	"plausibleInit":    func() template.JS { return plausibleInit },
	"turnstileSiteKey": turnstile.SiteKey,
	"absURL":           func(path string) string { return publicBase + path },
	"version":          func() string { return mcpserver.Version },
	"commitShort":      commitShort,
	"commitURL":        commitURL,
}).ParseFS(templateFS, "templates/*.tmpl"))

// siteScript is the one script every page carries: confirmation prompts for
// destructive forms (declared via data-confirm), the sliding mobile menu
// (open on the header button, close on outside click / Escape / choosing an
// item), and the live "updated Xm ago · next refresh in Ym Zs" ticker on each
// ".fresh" element. The ticker counts from server-provided data-age/data-left
// deltas plus client-side elapsed time, so it isn't affected by clock skew.
// It is injected as a typed template.JS constant so its CSP hash can be
// computed from the same value.
const siteScript = `(function(){
  document.addEventListener('submit',function(e){
    var msg=e.target.getAttribute('data-confirm');
    if(msg&&!confirm(msg))e.preventDefault();
  });
  var btn=document.querySelector('.menu-btn'),menu=document.getElementById('site-menu');
  function closeMenu(){document.body.classList.remove('menu-open');if(btn)btn.setAttribute('aria-expanded','false');}
  if(btn&&menu){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var open=document.body.classList.toggle('menu-open');
      btn.setAttribute('aria-expanded',open?'true':'false');
    });
    document.addEventListener('click',function(e){
      if(document.body.classList.contains('menu-open')&&!menu.contains(e.target))closeMenu();
    });
    document.addEventListener('keydown',function(e){if(e.key==='Escape')closeMenu();});
    menu.addEventListener('click',function(e){
      if(e.target.closest('label,a,button'))closeMenu();
    });
  }
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
// Fonts, and only known scripts — the site script and, when configured, the
// Plausible script + its init stub and the Cloudflare Turnstile widget.
// Inline scripts are allowed by hash only, so inline handlers are blocked;
// forms use data-confirm instead of onsubmit.
var pageCSP = buildCSP("")

// buildCSP assembles the page policy. extraFormAction appends sources to
// form-action for the OAuth consent page (see consentCSP); everything else
// passes "".
func buildCSP(extraFormAction string) string {
	hash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	scriptSrc := hash(siteScript)
	// connect-src needs 'self' even though our script never fetches: tools
	// that probe the site from page context (e.g. Lighthouse downloading
	// /robots.txt via fetch) are blocked by default-src 'none' otherwise.
	connectSrc := "connect-src 'self'"
	frameSrc := ""
	if plausibleScriptURL != "" {
		if u, err := url.Parse(plausibleScriptURL); err == nil && u.Scheme == "https" {
			origin := u.Scheme + "://" + u.Host
			scriptSrc += " " + origin + " " + hash(plausibleInit)
			connectSrc += " " + origin
		}
	}
	connectSrc += "; "
	if turnstile.SiteKey() != "" {
		scriptSrc += " https://challenges.cloudflare.com"
		frameSrc = "frame-src https://challenges.cloudflare.com; "
	}
	return "default-src 'none'; script-src " + scriptSrc + "; " +
		"style-src 'unsafe-inline'; font-src 'self'; " +
		"img-src 'self' data:; " + connectSrc + frameSrc +
		"form-action 'self'" + extraFormAction + "; base-uri 'none'; frame-ancestors 'none'"
}

// consentCSP is the page policy with the MCP client's callback origin added to
// form-action. The consent form posts to /authorize, which answers with a 302
// carrying the authorization code to the client's redirect_uri — and browsers
// match form-action against the redirects that follow a form submission, not
// just its immediate action. Under a bare 'self' that redirect is dropped
// silently: the client's loopback listener never sees the code and pairing
// hangs forever (this is what broke `opencode2 mcp auth pintr`).
//
// Granting only the origin costs nothing: handleAuthorize has already checked
// redirectURI against the client's registered list before rendering, so this
// allows exactly the hop the flow is about to make.
func consentCSP(redirectURI string) string {
	target, err := url.Parse(redirectURI)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return pageCSP
	}
	return buildCSP(" " + target.Scheme + "://" + target.Host)
}

func securePageHeaders(w http.ResponseWriter, policy string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Authenticated, user-specific pages: don't let a proxy cache them, and
	// don't let another site frame them (clickjacking on the consent page).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", policy)
}

// renderTemplate executes a named page template into a buffer first, so a
// template error becomes a clean 500 instead of a half-written page.
func renderTemplate(w http.ResponseWriter, name string, data any) {
	renderTemplateCSP(w, name, data, pageCSP)
}

// renderTemplateCSP renders under a specific policy (the consent page widens
// form-action; see consentCSP).
func renderTemplateCSP(w http.ResponseWriter, name string, data any, policy string) {
	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	securePageHeaders(w, policy)
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
	Error  string
	Hidden []hiddenField
}

// RenderConsent is the MCP OAuth consent screen. It is exported for the OAuth
// provider's authorize endpoint (wired as a hook in app); the OAuth params
// are echoed as hidden fields so the POST carries them back. A non-empty
// notice re-renders the form after a failed captcha check with a fresh widget.
func RenderConsent(w http.ResponseWriter, session store.SessionInfo, query url.Values, notice string) {
	var hidden []hiddenField
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "resource", "scope"} {
		if value := query.Get(key); value != "" {
			hidden = append(hidden, hiddenField{Name: key, Value: value})
		}
	}
	renderTemplateCSP(w, "consent", consentPage{
		basePage: authedPage("authorize"),
		Email:    session.User.Email,
		CSRF:     session.CSRF,
		Error:    notice,
		Hidden:   hidden,
	}, consentCSP(query.Get("redirect_uri")))
}
