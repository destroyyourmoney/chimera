package healthreport

import "time"

type Result struct {
	Server string `json:"server"`
	OK     bool   `json:"ok"`
	RTTMs  int64  `json:"rtt_ms,omitempty"`
	Error  string `json:"error,omitempty"`
}

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
