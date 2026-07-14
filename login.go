package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// The interactive browser login used in stdio mode: PKCE + a localhost
// callback server, persisting the resulting tokens to the auth file.

// The Codex OAuth client only allows these localhost callback ports.
var oauthCallbackPorts = []int{1455, 1457}

// ensureLoggedIn loads existing auth or runs the interactive browser login.
func ensureLoggedIn(ctx context.Context, store *authStore) error {
	_, err := store.load()
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	fmt.Fprintln(os.Stderr, "pintr: no saved OpenAI auth, starting browser login...")
	_, err = runLogin(ctx, store)
	return err
}

// runLogin performs the Codex browser OAuth flow (PKCE + localhost callback)
// and persists the resulting tokens.
func runLogin(ctx context.Context, store *authStore) (*storedAuth, error) {
	verifier, challenge, err := newPKCEPair()
	if err != nil {
		return nil, err
	}
	state, err := randomToken(16)
	if err != nil {
		return nil, err
	}

	listener, port, err := listenOnCallbackPort()
	if err != nil {
		return nil, err
	}
	defer listener.Close()

	redirectURI := fmt.Sprintf("http://localhost:%d%s", port, oauthRedirectPath)
	authorizeURL := buildAuthorizeURL(redirectURI, challenge, state)

	results := make(chan oauthCallback, 1)
	server := &http.Server{Handler: callbackHandler(state, results)}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	fmt.Fprintf(os.Stderr, "\nOpen this URL to sign in to OpenAI:\n\n  %s\n\n", authorizeURL)
	fmt.Fprintf(os.Stderr, "Waiting for the browser callback on http://localhost:%d%s ...\n", port, oauthRedirectPath)
	fmt.Fprintln(os.Stderr, "(on a remote machine, tunnel first: ssh -L 1455:127.0.0.1:1455 <host>)")
	openBrowser(authorizeURL)

	var code string
	select {
	case result := <-results:
		if result.err != nil {
			return nil, result.err
		}
		code = result.code
	case <-time.After(loginTimeout):
		return nil, errors.New("login timed out before the browser callback completed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	auth, err := exchangeAuthorizationCode(ctx, code, redirectURI, verifier)
	if err != nil {
		return nil, err
	}
	if err := store.save(auth); err != nil {
		return nil, fmt.Errorf("saving auth: %w", err)
	}

	store.mu.Lock()
	store.auth = auth
	store.mu.Unlock()

	fmt.Fprintf(os.Stderr, "Logged in as %s (plan: %s, account: %s)\n", orUnknown(auth.Email), orUnknown(auth.PlanType), auth.AccountID)
	return auth, nil
}

type oauthCallback struct {
	code string
	err  error
}

func callbackHandler(state string, results chan<- oauthCallback) http.Handler {
	var once sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != oauthRedirectPath {
			http.NotFound(w, r)
			return
		}

		query := r.URL.Query()
		settle := func(code string, err error, message string) {
			once.Do(func() {
				results <- oauthCallback{code: code, err: err}
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!doctype html><html><body><p>%s</p></body></html>", message)
		}

		if errParam := query.Get("error"); errParam != "" {
			settle("", fmt.Errorf("OAuth failed: %s", errParam), "Sign-in failed. You can close this window.")
			return
		}
		if query.Get("state") != state {
			settle("", errors.New("OAuth state mismatch"), "Sign-in state did not match. You can close this window.")
			return
		}
		code := query.Get("code")
		if code == "" {
			settle("", errors.New("OAuth callback did not include an authorization code"), "Sign-in did not return a code. You can close this window.")
			return
		}
		settle(code, nil, "Sign-in completed. You can close this window.")
	})
}

func listenOnCallbackPort() (net.Listener, int, error) {
	var errs []string
	for _, port := range oauthCallbackPorts {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return listener, port, nil
		}
		errs = append(errs, err.Error())
	}
	return nil, 0, fmt.Errorf("could not bind an OAuth callback port %v: %s", oauthCallbackPorts, strings.Join(errs, "; "))
}

func openBrowser(target string) {
	for _, opener := range [][]string{{"xdg-open"}, {"open"}} {
		path, err := exec.LookPath(opener[0])
		if err != nil {
			continue
		}
		if exec.Command(path, target).Start() == nil {
			return
		}
	}
}
