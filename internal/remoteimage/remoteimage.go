package remoteimage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const MaxBytes int64 = 10 << 20

var publicIPv6Prefix = netip.MustParsePrefix("2000::/3")

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fec0::/10"),
}

type Downloader struct {
	client *http.Client
}

func New() *Downloader {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 4,
		MaxConnsPerHost:     8,
		IdleConnTimeout:     30 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("invalid remote address")
			}

			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, errors.New("could not resolve remote host")
			}
			if err := validateIPs(addrs); err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
				if err == nil {
					return conn, nil
				}
			}
			return nil, errors.New("could not connect to remote host")
		},
		ForceAttemptHTTP2: true,
	}

	return &Downloader{client: &http.Client{
		Transport:     transport,
		Timeout:       30 * time.Second,
		CheckRedirect: checkRedirect,
	}}
}

func newTestDownloader(transport http.RoundTripper) *Downloader {
	return &Downloader{client: &http.Client{
		Transport:     transport,
		Timeout:       30 * time.Second,
		CheckRedirect: checkRedirect,
	}}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	req.Header.Del("Referer")
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	return validateURL(req.URL.String())
}

func (d *Downloader) Download(ctx context.Context, rawURL string) ([]byte, error) {
	if err := validateURL(rawURL); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("invalid image URL")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("image download failed: %w", ctxErr)
		}
		return nil, errors.New("image download failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("image download returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return nil, errors.New("could not read image response")
	}
	if int64(len(body)) > MaxBytes {
		return nil, errors.New("image exceeds the 10 MiB limit")
	}

	switch http.DetectContentType(body) {
	case "image/png", "image/jpeg", "image/webp", "image/gif":
		return body, nil
	default:
		return nil, errors.New("download is not a supported image")
	}
}

func validateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil {
		return errors.New("invalid image URL")
	}

	host := u.Hostname()
	if host == "" {
		return errors.New("invalid image URL")
	}
	localName := strings.TrimSuffix(strings.ToLower(host), ".")
	if localName == "localhost" || strings.HasSuffix(localName, ".localhost") {
		return errors.New("image URL must use a public destination")
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if err := validateAddrs([]netip.Addr{addr}); err != nil {
			return err
		}
	}
	return nil
}

func validateIPs(addrs []net.IPAddr) error {
	parsed := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Zone != "" {
			return errors.New("remote destination is not public")
		}
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			return errors.New("remote destination is not public")
		}
		parsed = append(parsed, ip)
	}
	return validateAddrs(parsed)
}

func validateAddrs(addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return errors.New("remote destination is not public")
	}
	for _, addr := range addrs {
		if addr.Zone() != "" {
			return errors.New("remote destination is not public")
		}
		addr = addr.Unmap()
		if addr.Is6() && !publicIPv6Prefix.Contains(addr) {
			return errors.New("remote destination is not public")
		}
		if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
			addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
			return errors.New("remote destination is not public")
		}
		for _, prefix := range nonPublicPrefixes {
			if prefix.Contains(addr) {
				return errors.New("remote destination is not public")
			}
		}
	}
	return nil
}
