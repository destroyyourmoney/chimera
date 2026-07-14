//go:build chimera_quic

package main

// Importing the quic package for its init() registers the QUIC carrier into the
// transport registry (carrier.QUIC*). Only compiled with -tags chimera_quic, so
// the default binary never links quic-go.
import _ "chimera/internal/quic"
