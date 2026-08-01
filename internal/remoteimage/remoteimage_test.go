package remoteimage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDownloadValidPNG(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\nvalid-enough-for-sniffing")
	d := newTestDownloader(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(png)),
		}, nil
	}))

	got, err := d.Download(context.Background(), "https://files.example/image.png")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, png) {
		t.Fatalf("download mismatch: %x", got)
	}
}

func TestDownloadAcceptsSupportedImageFormats(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "jpeg", body: []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00image")},
		{name: "webp", body: []byte("RIFF\x0c\x00\x00\x00WEBPVP8 image")},
		{name: "gif", body: []byte("GIF89a\x01\x00\x01\x00image")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestDownloader(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(tt.body)),
				}, nil
			}))

			got, err := d.Download(context.Background(), "https://files.example/image")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.body) {
				t.Fatalf("download mismatch: %x", got)
			}
		})
	}
}

func TestDownloadRejectsOversizeAndNonImage(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{name: "oversize", body: make([]byte, MaxBytes+1), want: "10 MiB"},
		{name: "not image", body: []byte("plain text"), want: "not a supported image"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestDownloader(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(tt.body)),
				}, nil
			}))

			_, err := d.Download(context.Background(), "https://files.example/image")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Download() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestDownloadRejectsNonOKStatus(t *testing.T) {
	d := newTestDownloader(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("missing")),
		}, nil
	}))

	_, err := d.Download(context.Background(), "https://files.example/missing.png")
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("Download() error = %v, want error containing status 404", err)
	}
}

func TestDownloadErrorsDoNotExposeSignedQuery(t *testing.T) {
	const secret = "super-secret-signature"
	d := newTestDownloader(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("upstream unavailable")
	}))

	_, err := d.Download(context.Background(), "https://files.example/image.png?sig="+secret)
	if err == nil {
		t.Fatal("Download() succeeded")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "?sig=") {
		t.Fatalf("Download() error exposed signed query: %q", err)
	}
}

func TestValidateURLRequiresPublicHTTPS(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/a.png",
		"https://user:pass@example.com/a.png",
		"https:///a.png",
		"https://localhost/a.png",
		"https://127.0.0.1/a.png",
		"https://[::1]/a.png",
		"https://[fec0::1]/a.png",
		"https://[2606:2800:220:1:248:1893:25c8:1946%25eth0]/a.png",
	} {
		if err := validateURL(raw); err == nil {
			t.Errorf("validateURL(%q) succeeded", raw)
		}
	}
}

func TestValidateURLAcceptsPublicHTTPSHost(t *testing.T) {
	if err := validateURL("https://files.example/image.png?sig=opaque"); err != nil {
		t.Fatalf("validateURL() error = %v", err)
	}
}

func TestValidateURLRejectsNonPublicIPv6Allocations(t *testing.T) {
	for _, raw := range []string{
		"https://[3fff::1]/a.png",
		"https://[5f00::1]/a.png",
	} {
		if err := validateURL(raw); err == nil {
			t.Errorf("validateURL(%q) succeeded", raw)
		}
	}
}

func TestValidateIPsRejectsPrivateDestinations(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.1",
		"127.0.0.1",
		"10.0.0.1",
		"100.64.0.1",
		"169.254.169.254",
		"192.0.2.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
		"240.0.0.1",
		"::1",
		"2001:db8::1",
		"fc00::1",
		"fec0::1",
	} {
		if err := validateIPs([]net.IPAddr{{IP: net.ParseIP(raw)}}); err == nil {
			t.Errorf("validateIPs(%s) succeeded", raw)
		}
	}
}

func TestValidateIPsAcceptsPublicDestinations(t *testing.T) {
	addrs := []net.IPAddr{
		{IP: net.ParseIP("93.184.216.34")},
		{IP: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")},
	}
	if err := validateIPs(addrs); err != nil {
		t.Fatalf("validateIPs() error = %v", err)
	}
}

func TestValidateIPsRejectsNonPublicIPv6Allocations(t *testing.T) {
	for _, raw := range []string{"3fff::1", "5f00::1"} {
		if err := validateIPs([]net.IPAddr{{IP: net.ParseIP(raw)}}); err == nil {
			t.Errorf("validateIPs(%s) succeeded", raw)
		}
	}
}

func TestProductionClientValidatesEveryRedirectTarget(t *testing.T) {
	d := New()
	for _, raw := range []string{
		"http://example.com/a.png",
		"https://user:pass@example.com/a.png",
		"https:///a.png",
		"https://localhost/a.png",
		"https://127.0.0.1/a.png",
		"https://[::1]/a.png",
		"https://[fec0::1]/a.png",
	} {
		target, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.client.CheckRedirect(&http.Request{URL: target}, nil); err == nil {
			t.Errorf("CheckRedirect(%q) succeeded", raw)
		}
	}
}

func TestProductionClientAcceptsPublicHTTPSRedirect(t *testing.T) {
	target, err := url.Parse("https://files.example/next.png")
	if err != nil {
		t.Fatal(err)
	}
	if err := New().client.CheckRedirect(&http.Request{URL: target}, nil); err != nil {
		t.Fatalf("CheckRedirect() error = %v", err)
	}
}

func TestProductionClientRejectsRedirectsToNonPublicIPv6Allocations(t *testing.T) {
	d := New()
	for _, raw := range []string{
		"https://[3fff::1]/a.png",
		"https://[5f00::1]/a.png",
	} {
		target, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.client.CheckRedirect(&http.Request{URL: target}, nil); err == nil {
			t.Errorf("CheckRedirect(%q) succeeded", raw)
		}
	}
}

func TestProductionClientLimitsRedirects(t *testing.T) {
	target, err := url.Parse("https://files.example/next.png")
	if err != nil {
		t.Fatal(err)
	}
	via := make([]*http.Request, 10)
	if err := New().client.CheckRedirect(&http.Request{URL: target}, via); err == nil {
		t.Fatal("CheckRedirect() accepted an eleventh request")
	}
}
