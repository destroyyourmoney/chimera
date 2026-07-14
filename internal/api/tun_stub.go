//go:build !(chimera_netstack && (linux || darwin))

package api

import (
	"context"
	"errors"
)

// ConnectTUN is unavailable in this build. FD-based TUN adoption is supported on
// linux/darwin with -tags chimera_netstack. Windows CLI TUN uses a named Wintun
// device via `chimera tun`, not fd adoption. Use RunSOCKS as the TUN-less fallback.
func (s *Session) ConnectTUN(_ context.Context, _, _ int) error {
	return errors.New("api: fd-based TUN support not built for this target (use RunSOCKS, or chimera tun on supported desktop builds)")
}
