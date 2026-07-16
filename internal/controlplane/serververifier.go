// ServerVerifier is the data-plane side of ROADMAP2 §1.3/§1.4: it lets a
// carrier server implement carrier.TokenVerifier by checking a token's
// Ed25519 signature/expiry locally (no network call, no disk read on the
// hot path) plus a revocation cache refreshed on the same 5-second poll
// cadence useracl.Store.Watch already uses for its own file -- just against
// the control-plane's public GET /v1/revocations?since= instead of a local
// YAML file.
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

// RevocationPollInterval matches useracl.PollInterval -- see package doc.
const RevocationPollInterval = 5 * time.Second

// ServerVerifier implements carrier.TokenVerifier. Construct with
// NewServerVerifier and call Watch in a goroutine to keep the revocation
// cache warm; VerifyToken works (against a possibly-stale cache) even
// before the first successful poll, defaulting to "nothing revoked yet".
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

// VerifyToken implements carrier.TokenVerifier: signature + expiry +
// shortID match + not on the (cached) revocation list. Pure in-memory
// check, safe to call per-connection.
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

// Watch polls the control-plane's revocation feed every
// RevocationPollInterval until done is closed, same lifecycle contract as
// useracl.Store.Watch.
func (v *ServerVerifier) Watch(done <-chan struct{}) {
	t := time.NewTicker(RevocationPollInterval)
	defer t.Stop()
	v.poll() // prime the cache immediately rather than waiting a full tick
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
