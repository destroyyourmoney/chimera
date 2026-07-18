package link

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

const scheme = "chimera"

type Profile struct {
	AuthID string
	Host   string
	Port   string
	Pbk    string
	Sid    string
	Sni    string
	Fp     string
	Mode   string
	Tag    string

	Token string
}

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
