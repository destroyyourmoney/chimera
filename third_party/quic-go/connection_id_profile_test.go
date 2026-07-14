package quic

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGenerateConnectionIDForInitialWithProfile guards Chrome's fixed 8-byte
// initial DCID guess: real Chrome always uses an 8-byte destination
// connection ID in its first Initial packet, while stock quic-go randomizes
// this length between 8 and 20 bytes (which would itself be a distinguishing
// signal for the chrome-h3 fingerprint profile). Every other profile,
// including the default empty one, must keep the stock randomized behavior.
func TestGenerateConnectionIDForInitialWithProfile(t *testing.T) {
	for range 20 {
		connID, err := generateConnectionIDForInitialWithProfile("chrome-h3")
		require.NoError(t, err)
		require.Equal(t, chromeH3InitialDestConnIDLen, connID.Len())
	}

	sawDifferentLength := false
	for range 50 {
		connID, err := generateConnectionIDForInitialWithProfile("")
		require.NoError(t, err)
		require.GreaterOrEqual(t, connID.Len(), 8)
		require.LessOrEqual(t, connID.Len(), 20)
		if connID.Len() != chromeH3InitialDestConnIDLen {
			sawDifferentLength = true
		}
	}
	require.True(t, sawDifferentLength, "expected the default profile to keep randomizing DCID length")
}
