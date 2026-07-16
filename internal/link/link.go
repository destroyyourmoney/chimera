// Package link builds and parses chimera:// share URIs. The format is modelled
// on VLESS-Reality links so it is familiar to operators and survives a clean
// build → parse → build round trip:
//
//	chimera://<authID>@<host>:<port>?pbk=..&sid=..&sni=..&fp=..&mode=..&tok=..#<tag>
//
// All transport-shaping parameters live in the query string; the human label is
// the URL fragment. Empty optional fields are omitted so links stay compact.
package link

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

const scheme = "chimera"

// Profile is the full set of parameters carried by a chimera:// link.
type Profile struct {
	AuthID string // optional auth UUID (URL userinfo)
	Host   string // server host or IP
	Port   string // server port
	Pbk    string // server static X25519 public key (base64url)
	Sid    string // short ID (hex), optional
	Sni    string // steal-host SNI
	Fp     string // fingerprint to mimic (e.g. chrome)
	Mode   string // transport mode: auto|quic|tcp
	Tag    string // human label
	// Token is the control-plane capability token (ROADMAP2 §1), carried so
	// a curated server's link is self-sufficient for -auth-mode
	// controlplane servers -- the same token AccountStore holds after
	// redeem/refresh. Empty for -auth-mode useracl servers/legacy BYO
	// links, which don't need one.
	Token string
}

// Build renders a Profile as a chimera:// URI.
func Build(p Profile) string {
	q := url.Values{}
	setIf(q, "pbk", p.Pbk)
	setIf(q, "sid", p.Sid)
	setIf(q, "sni", p.Sni)
	setIf(q, "fp", p.Fp)
	setIf(q, "mode", p.Mode)
	setIf(q, "tok", p.Token)

	u := url.URL{
		Scheme:   scheme,
		Host:     hostPort(p.Host, p.Port),
		RawQuery: q.Encode(),
		Fragment: p.Tag,
	}
	if p.AuthID != "" {
		u.User = url.User(p.AuthID)
	}
	return u.String()
}

// Parse decodes a chimera:// URI back into a Profile.
func Parse(uri string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return Profile{}, fmt.Errorf("parse chimera link: %w", err)
	}
	if u.Scheme != scheme {
		return Profile{}, fmt.Errorf("parse chimera link: wrong scheme %q (want %q)", u.Scheme, scheme)
	}
	host, port := splitHostPort(u.Host)
	q := u.Query()
	return Profile{
		AuthID: u.User.Username(),
		Host:   host,
		Port:   port,
		Pbk:    q.Get("pbk"),
		Sid:    q.Get("sid"),
		Sni:    q.Get("sni"),
		Fp:     q.Get("fp"),
		Mode:   q.Get("mode"),
		Token:  q.Get("tok"),
		Tag:    u.Fragment,
	}, nil
}

func setIf(q url.Values, key, val string) {
	if val != "" {
		q.Set(key, val)
	}
}

func hostPort(host, port string) string {
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func splitHostPort(hostport string) (host, port string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return hostport, ""
}
