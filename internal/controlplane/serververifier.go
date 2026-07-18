package controlplane

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

const RevocationPollInterval = 5 * time.Second

type ServerVerifier struct {
	verifier      *Verifier
	revocationURL string
	httpClient    *http.Client

	revoked atomic.Pointer[map[string]struct{}]
	etag    atomic.Int64
}

func NewServerVerifier(pubKeys []ed25519.PublicKey, controlPlaneBaseURL string) *ServerVerifier {
	empty := map[string]struct{}{}
	v := &ServerVerifier{
		verifier:      NewVerifier(pubKeys...),
		revocationURL: controlPlaneBaseURL + "/v1/revocations",
		httpClient:    &http.Client{Timeout: 10 * time.Second},
	}
	v.revoked.Store(&empty)
	return v
}

func (v *ServerVerifier) VerifyToken(token string, shortIDHex string) bool {
	payload, err := v.verifier.Verify(token)
	if err != nil {
		return false
	}
	if payload.ShortIDHex != shortIDHex {
		return false
	}
	revoked := v.revoked.Load()
	if revoked != nil {
		if _, ok := (*revoked)[shortIDHex]; ok {
			return false
		}
	}
	return true
}

func (v *ServerVerifier) Watch(done <-chan struct{}) {
	t := time.NewTicker(RevocationPollInterval)
	defer t.Stop()
	v.poll()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			v.poll()
		}
	}
}

func (v *ServerVerifier) poll() {
	url := fmt.Sprintf("%s?since=%d", v.revocationURL, v.etag.Load())
	resp, err := v.httpClient.Get(url)
	if err != nil {
		slog.Debug("controlplane: revocation poll failed", "err", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		slog.Debug("controlplane: revocation poll failed", "status", resp.StatusCode, "err", err)
		return
	}

	var parsed struct {
		Revocations []RevocationEntry `json:"revocations"`
		Etag        int64             `json:"etag"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		slog.Debug("controlplane: revocation poll: bad response", "err", err)
		return
	}
	if len(parsed.Revocations) == 0 {
		v.etag.Store(parsed.Etag)
		return
	}

	prev := v.revoked.Load()
	next := make(map[string]struct{}, len(*prev)+len(parsed.Revocations))
	for k := range *prev {
		next[k] = struct{}{}
	}
	for _, e := range parsed.Revocations {
		next[e.ShortIDHex] = struct{}{}
	}
	v.revoked.Store(&next)
	v.etag.Store(parsed.Etag)
}
