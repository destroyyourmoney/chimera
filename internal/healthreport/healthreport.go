// Package healthreport pings a set of endpoints concurrently and reports
// latency/error per endpoint. It exists as its own package (rather than
// inline in cmd/chimera) so the collection/ordering/fastest-pick logic is
// unit-testable without a real network dial -- cmd/chimera's healthCmd
// supplies the real carrier.Ping as the ping func and only owns printing.
package healthreport

import "time"

// Result is one endpoint's outcome. RTTMs is only meaningful when OK.
type Result struct {
	Server string `json:"server"`
	OK     bool   `json:"ok"`
	RTTMs  int64  `json:"rtt_ms,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Run pings every host concurrently via ping and returns results in the same
// order as hosts (not completion order), so callers can zip results back
// against their input list.
func Run(hosts []string, ping func(host string) error) []Result {
	type indexed struct {
		i int
		r Result
	}
	ch := make(chan indexed, len(hosts))
	for i, h := range hosts {
		i, h := i, h
		go func() {
			start := time.Now()
			err := ping(h)
			r := Result{Server: h}
			if err != nil {
				r.Error = err.Error()
			} else {
				r.OK = true
				r.RTTMs = time.Since(start).Milliseconds()
			}
			ch <- indexed{i: i, r: r}
		}()
	}
	out := make([]Result, len(hosts))
	for range hosts {
		x := <-ch
		out[x.i] = x.r
	}
	return out
}

// Fastest returns the OK result with the lowest RTT, and false if none of
// the results are OK.
func Fastest(results []Result) (Result, bool) {
	var best Result
	found := false
	for _, r := range results {
		if !r.OK {
			continue
		}
		if !found || r.RTTMs < best.RTTMs {
			best = r
			found = true
		}
	}
	return best, found
}
