// Command chimera is a single binary providing the CHIMERA server, SOCKS5
// inbound proxy, client PoC, key generation, and share-link tooling.
//
//	chimera keygen
//	chimera link   -host H -port P -pbk K [-sid S -sni N -fp chrome -mode auto -tag name -id uuid]
//	chimera server -listen :443 -steal-host www.microsoft.com:443 -priv K [-sid a,b]
//	chimera proxy  -server H:P -pbk K [-listen 127.0.0.1:1080 -sni N -sid S]
//	chimera client -server H:P -pbk K [-sni N -sid S]
//	chimera health -server H:P -pbk K [-sni N -sid S -transport auto]
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"chimera/internal/admin"
	"chimera/internal/carrier"
	"chimera/internal/client"
	"chimera/internal/config"
	"chimera/internal/endpoint"
	"chimera/internal/healthreport"
	"chimera/internal/keys"
	"chimera/internal/link"
	"chimera/internal/provision"
	"chimera/internal/qr"
	"chimera/internal/server"
	"chimera/internal/socks"
	"chimera/internal/subscription"
	"chimera/internal/telemetry"
	"chimera/internal/useracl"
	"chimera/internal/winnet"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		keygenCmd()
	case "link":
		linkCmd(os.Args[2:])
	case "qr":
		qrCmd(os.Args[2:])
	case "server":
		serverCmd(os.Args[2:])
	case "proxy":
		proxyCmd(os.Args[2:])
	case "connect":
		connectCmd(os.Args[2:])
	case "tun":
		tunCmd(os.Args[2:])
	case "client":
		clientCmd(os.Args[2:])
	case "health":
		healthCmd(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `chimera <command>

  keygen   generate an X25519 server keypair
  link     build a chimera:// share link from server parameters
  qr       render a chimera:// link as a terminal QR code
  server   run the stealth TCP carrier (auth + tunnel egress + transparent fallback)
  proxy    run a local SOCKS5 inbound that tunnels through a CHIMERA server
  connect  run a SOCKS5 inbound straight from a chimera:// link (scan QR → paste → go)
  tun      run a full-tunnel TUN device via the userspace netstack (-tags chimera_netstack)
  client   run the client PoC (handshake + PING)
  health   show endpoint health dashboard (ping latency, status)

Run "chimera <command> -h" for command flags.
`)
}

func keygenCmd() {
	priv, pub, err := keys.GenerateX25519()
	must(err)
	fmt.Printf("private (server, keep secret): %s\n", priv)
	fmt.Printf("public  (share in link)      : %s\n", pub)
}

func linkCmd(args []string) {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	host := fs.String("host", "", "server host or IP (required)")
	port := fs.String("port", "443", "server port")
	pbk := fs.String("pbk", "", "server public key, base64url (required)")
	sid := fs.String("sid", "", "short ID (hex)")
	sni := fs.String("sni", "www.microsoft.com", "steal-host SNI")
	fp := fs.String("fp", "chrome", "fingerprint to mimic")
	mode := fs.String("mode", "auto", "transport mode: auto|quic|tcp")
	tag := fs.String("tag", "", "human label")
	id := fs.String("id", "", "auth UUID")
	withQR := fs.Bool("qr", false, "also render the link as a terminal QR code")
	_ = fs.Parse(args)
	if *host == "" || *pbk == "" {
		fs.Usage()
		os.Exit(2)
	}
	uri := link.Build(link.Profile{
		AuthID: *id, Host: *host, Port: *port, Pbk: *pbk,
		Sid: *sid, Sni: *sni, Fp: *fp, Mode: *mode, Tag: *tag,
	})
	fmt.Println(uri)
	if *withQR {
		must(qr.Render(os.Stdout, uri))
	}
}

// qrCmd renders a chimera:// link as a terminal QR code. The link is taken from
// the first argument, or read from stdin if no argument is given.
func qrCmd(args []string) {
	var uri string
	if len(args) > 0 && args[0] != "" {
		uri = strings.TrimSpace(args[0])
	} else {
		b, err := io.ReadAll(os.Stdin)
		must(err)
		uri = strings.TrimSpace(string(b))
	}
	if uri == "" {
		fmt.Fprintln(os.Stderr, "usage: chimera qr <chimera://...>  (or pipe the link on stdin)")
		os.Exit(2)
	}
	must(qr.Render(os.Stdout, uri))
}

func serverCmd(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgFile := fs.String("config", "", "path to YAML config file (flags override file values)")
	listen := fs.String("listen", "", "listen address (default :443)")
	steal := fs.String("steal-host", "", "real TLS host to impersonate, host:port")
	priv := fs.String("priv", "", "server private key, base64url")
	sid := fs.String("sid", "", "allowed short IDs, comma-separated hex (empty = any)")
	transport := fs.String("transport", "", "carrier transport: tcp|quic (default tcp)")
	rate := fs.Float64("rate", 0, "per-IP auth attempts/sec (0 = use default)")
	burst := fs.Float64("burst", 0, "per-IP auth burst (0 = use default)")
	bw := fs.Float64("bw", 0, "QUIC ElasticCC Brutal target bandwidth in Mbps (0 = adaptive estimation)")
	usersFile := fs.String("users-file", "", "path to a dynamic users YAML file (add/revoke sids without a restart via -admin-listen); overrides -sid/short_ids when set")
	adminListen := fs.String("admin-listen", "", "address for the users admin HTTP API, e.g. 127.0.0.1:8901 (requires -users-file; empty = disabled)")
	adminToken := fs.String("admin-token", "", "bearer token for -admin-listen (empty = generate one and print it once at startup)")
	verbose := fs.Bool("v", false, "verbose (debug) logging")
	_ = fs.Parse(args)

	// Build effective config: file defaults, then CLI overrides.
	var cfg serverEffectiveCfg
	cfg.listen = ":443"
	cfg.transport = "tcp"
	cfg.rate = server.DefaultAuthRate
	cfg.burst = server.DefaultAuthBurst

	if *cfgFile != "" {
		fc, err := config.LoadServer(*cfgFile)
		if err != nil {
			log.Fatalf("server: %v", err)
		}
		if fc.Listen != "" {
			cfg.listen = fc.Listen
		}
		if fc.StealHost != "" {
			cfg.steal = fc.StealHost
		}
		if fc.PrivB64 != "" {
			cfg.priv = fc.PrivB64
		}
		cfg.ids = fc.ShortIDs
		if fc.Transport != "" {
			cfg.transport = fc.Transport
		}
		if fc.Verbose {
			cfg.verbose = true
		}
		if fc.RateLimit.Rate > 0 {
			cfg.rate = fc.RateLimit.Rate
		}
		if fc.RateLimit.Burst > 0 {
			cfg.burst = fc.RateLimit.Burst
		}
	}

	// CLI flags override file values (non-zero/non-empty = explicitly set).
	if *listen != "" {
		cfg.listen = *listen
	}
	if *steal != "" {
		cfg.steal = *steal
	}
	if *priv != "" {
		cfg.priv = *priv
	}
	if *sid != "" {
		cfg.ids = strings.Split(*sid, ",")
	}
	if *transport != "" {
		cfg.transport = *transport
	}
	if *verbose {
		cfg.verbose = true
	}
	if *rate > 0 {
		cfg.rate = *rate
	}
	if *burst > 0 {
		cfg.burst = *burst
	}

	if cfg.priv == "" || (cfg.transport == "tcp" && cfg.steal == "") {
		fs.Usage()
		os.Exit(2)
	}
	setupLogger(cfg.verbose)

	ctx, stop := signalContext()
	defer stop()

	var allowlist carrier.Allowlist
	if *usersFile != "" {
		allowlist = setupUserACL(ctx, *usersFile, *adminListen, *adminToken, cfg.ids)
	}

	if cfg.transport == "quic" || cfg.transport == "quic-rudp" {
		// quic-rudp shares the QUIC carrier listener; it only adds a new command
		// (CmdConnectRUDP) the server already handles, so the same serve path runs.
		if carrier.QUICServe == nil {
			log.Fatal("quic transport requested but binary built without QUIC support (rebuild with -tags chimera_quic)")
		}
		must(carrier.QUICServe(ctx, carrier.QUICServerConfig{
			Listen: cfg.listen, PrivB64: cfg.priv, StealHost: cfg.steal, ShortIDs: cfg.ids,
			BandwidthBps: uint64(*bw * 125000), // Mbps → bytes/s (1 Mbps = 125000 B/s)
			Allowlist:    allowlist,
		}))
		return
	}
	must(server.Run(ctx, server.Config{
		Listen: cfg.listen, StealHost: cfg.steal, PrivB64: cfg.priv, ShortIDs: cfg.ids,
		AuthRate: cfg.rate, AuthBurst: cfg.burst,
		Allowlist: allowlist,
	}))
}

// setupUserACL loads the dynamic users file, seeds it from the legacy -sid
// list if it's empty (so turning this on never locks out existing clients),
// starts its background poll loop (picks up changes made by the admin API in
// a sibling process, e.g. the QUIC carrier when only the TCP carrier runs
// -admin-listen), and — if requested — starts the admin HTTP API itself.
func setupUserACL(ctx context.Context, usersFile, adminListen, adminToken string, staticIDs []string) *useracl.Store {
	store, err := useracl.Load(usersFile)
	if err != nil {
		log.Fatalf("server: -users-file: %v", err)
	}
	if len(staticIDs) > 0 {
		seed := make([]useracl.User, len(staticIDs))
		for i, id := range staticIDs {
			seed[i] = useracl.User{SID: id, Label: "default"}
		}
		if err := store.SeedIfEmpty(seed); err != nil {
			log.Fatalf("server: seed -users-file from -sid: %v", err)
		}
	}
	go store.Watch(ctx.Done())

	if adminListen != "" {
		token := adminToken
		if token == "" {
			buf := make([]byte, 16)
			if _, err := rand.Read(buf); err != nil {
				log.Fatalf("server: generate admin token: %v", err)
			}
			token = hex.EncodeToString(buf)
			slog.Warn("admin api: no -admin-token given, generated one for this run — save it, it will not be shown again", "token", token)
		}
		if !admin.LoopbackOnly(adminListen) {
			slog.Warn("admin api: -admin-listen is not loopback-only; make sure it's firewalled or reached only via an SSH tunnel", "listen", adminListen)
		}
		go func() {
			if err := admin.Serve(ctx, adminListen, token, store); err != nil {
				slog.Error("admin api stopped", "err", err)
			}
		}()
	}
	return store
}

type serverEffectiveCfg struct {
	listen, steal, priv, transport string
	ids                            []string
	verbose                        bool
	rate, burst                    float64
}

func proxyCmd(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	cfgFile := fs.String("config", "", "path to YAML config file; fp: field is hot-reloaded every 30s")
	subFile := fs.String("sub", "", "path to subscription file (overrides -server/-pbk if given)")
	subKey := fs.String("sub-key", "", "hex HMAC-SHA256 key for subscription signature verification (empty = unsigned)")
	srv := fs.String("server", "", "CHIMERA server host:port (comma-separated for failover)")
	pbk := fs.String("pbk", "", "server public key, base64url")
	listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	sni := fs.String("sni", "www.microsoft.com", "steal-host SNI")
	sid := fs.String("sid", "", "short ID (hex)")
	transport := fs.String("transport", "auto", "carrier transport: auto|tcp|quic (auto races QUIC+TCP; quic needs -tags chimera_quic)")
	fp := fs.String("fp", "", "TLS fingerprint: chrome (default), chrome131, chrome120, firefox, safari, ios, edge")
	provCmd := fs.String("provision-cmd", "", "shell command that prints a chimera subscription to provision fresh endpoints when the pool burns (auto-rotation)")
	bw := fs.Float64("bw", 0, "QUIC ElasticCC Brutal target bandwidth in Mbps (0 = adaptive estimation)")
	shape := fs.Bool("shape", false, "shape bulk QUIC writes into H3-video bursts (stealth; caps throughput)")
	verbose := fs.Bool("v", false, "verbose (debug) logging")
	_ = fs.Parse(args)
	if *subFile == "" && (*srv == "" || *pbk == "") {
		fs.Usage()
		os.Exit(2)
	}
	setupLogger(*verbose)

	// If a config file is given, seed the fingerprint from it.
	if *cfgFile != "" {
		if fc, err := config.LoadServer(*cfgFile); err == nil && fc.Fp != "" && *fp == "" {
			*fp = fc.Fp
		}
	}

	var cfgs []carrier.Config

	// Subscription file overrides -server/-pbk when given.
	if *subFile != "" {
		var key []byte
		if *subKey != "" {
			var err error
			if key, err = hexDecode(*subKey); err != nil {
				log.Fatalf("proxy: invalid -sub-key: %v", err)
			}
		}
		loaded, err := subscription.Load(*subFile, key)
		if err != nil {
			log.Fatalf("proxy: load subscription: %v", err)
		}
		cfgs = loaded
	} else {
		for _, host := range strings.Split(*srv, ",") {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			cfgs = append(cfgs, carrier.Config{Server: host, PubB64: *pbk, SNI: *sni, ShortIDHex: *sid, Transport: *transport, Fp: *fp, BandwidthBps: uint64(*bw * 125000), Shaping: *shape})
		}
	}
	if len(cfgs) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	ctx, stop := signalContext()
	defer stop()

	// mode=auto: race QUIC+TCP per dial (demote/promote by health scoring).
	// Other transports: plain pool with serial failover.
	var (
		dialer  endpoint.Dialer
		pool    *endpoint.Pool
		mutator provision.PoolMutator
	)
	if *transport == "auto" {
		auto := endpoint.NewAutoPool(cfgs)
		dialer = auto
		pool = auto.Pool()
		mutator = auto
	} else {
		p := endpoint.NewPool(cfgs)
		dialer = p
		pool = p
		mutator = p
	}

	// Hot-reload fingerprint/profile from config file. The uTLS build also has
	// a process-level updater for TCP handshakes; updating pool configs makes
	// future QUIC/TCP dials pick up cfg.Fp without restarting.
	if *cfgFile != "" {
		go config.Watch(ctx, *cfgFile, func(fc *config.ServerConfig) {
			if fc.Fp == "" {
				return
			}
			if carrier.FingerprintUpdater != nil {
				carrier.FingerprintUpdater(fc.Fp)
			}
			pool.SetFingerprint(fc.Fp)
		})
	}

	// Optional auto-provisioning: turn the burned-endpoint signal into fresh endpoints.
	var prov provision.Provisioner
	if *provCmd != "" {
		key, _ := hexDecode(*subKey) // reuse -sub-key to verify a signed provision subscription
		prov = provision.ShellCommandProvisioner(*provCmd, key)
	}

	// Background telemetry: logs health snapshots every 30s, warns when rotation needed,
	// and auto-provisions replacements when a provisioner is configured.
	mon := telemetry.NewMonitor(pool, telemetry.DefaultConfig())
	mon.OnRotationNeeded(func(burned []telemetry.BurnedEndpoint) {
		servers := make([]string, len(burned))
		for i, b := range burned {
			servers[i] = b.Server
			slog.Warn("endpoint burned", "server", b.Server, "fails", b.Fails)
		}
		if prov == nil {
			return
		}
		if err := provision.Rotate(ctx, mutator, prov, servers); err != nil {
			slog.Warn("auto-provision failed", "err", err)
			return
		}
		slog.Info("auto-provisioned replacement endpoints", "burned", len(servers))
	})
	go mon.Run(ctx)

	must(socks.Serve(ctx, *listen, dialer))
}

// connectCmd starts a SOCKS5 inbound directly from a single chimera:// link — the
// "scanned a QR, paste the URI, connect" convenience over `proxy -server -pbk …`.
func connectCmd(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	verbose := fs.Bool("v", false, "verbose (debug) logging")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) < 1 || strings.TrimSpace(rest[0]) == "" {
		fmt.Fprintln(os.Stderr, "usage: chimera connect [-listen addr] <chimera://...>")
		os.Exit(2)
	}
	setupLogger(*verbose)

	p, err := link.Parse(strings.TrimSpace(rest[0]))
	if err != nil {
		log.Fatalf("connect: invalid chimera:// link: %v", err)
	}
	cfg := carrier.Config{
		Server: p.Host + ":" + p.Port, PubB64: p.Pbk, SNI: p.Sni,
		ShortIDHex: p.Sid, Transport: p.Mode, Fp: p.Fp,
	}
	if cfg.Transport == "" {
		cfg.Transport = "auto"
	}
	if cfg.SNI == "" {
		cfg.SNI = "www.microsoft.com"
	}

	ctx, stop := signalContext()
	defer stop()
	var dialer endpoint.Dialer
	if cfg.Transport == "auto" {
		dialer = endpoint.NewAutoPool([]carrier.Config{cfg})
	} else {
		dialer = endpoint.NewPool([]carrier.Config{cfg})
	}
	slog.Info("connect", "server", cfg.Server, "transport", cfg.Transport, "listen", *listen)
	must(socks.Serve(ctx, *listen, dialer))
}

// tunCmd runs a full-tunnel TUN device routed through the carrier via the
// userspace netstack. The data path itself is compiled only with -tags
// chimera_netstack (see tun_on.go / tun_off.go); without it this reports a clear
// error. Creating the TUN device requires privileges (root / utun).
func tunCmd(args []string) {
	fs := flag.NewFlagSet("tun", flag.ExitOnError)
	srv := fs.String("server", "", "CHIMERA server host:port (comma-separated for failover)")
	pbk := fs.String("pbk", "", "server public key, base64url")
	sni := fs.String("sni", "www.microsoft.com", "steal-host SNI")
	sid := fs.String("sid", "", "short ID (hex)")
	transport := fs.String("transport", "auto", "carrier transport: auto|tcp|quic")
	dev := fs.String("dev", "", "TUN device name (empty = OS-assigned, e.g. utunN)")
	mtu := fs.Int("mtu", 1400, "TUN MTU")
	fp := fs.String("fp", "", "TLS fingerprint: chrome (default), firefox, safari, ios, edge")
	bw := fs.Float64("bw", 0, "QUIC ElasticCC Brutal target bandwidth in Mbps (0 = adaptive estimation)")
	setupOS := fs.Bool("setup-os", false, "configure OS full-tunnel routes/DNS for the TUN device (Windows; requires admin)")
	setupDryRun := fs.Bool("setup-dry-run", false, "print the OS setup plan and exit without creating the TUN device")
	setupElevate := fs.Bool("setup-elevate", false, "re-run this tun command through the Windows UAC prompt")
	setupRestore := fs.Bool("setup-restore", false, "restore OS routes/DNS for the TUN device and exit")
	setupCheck := fs.Bool("setup-check", false, "check OS routes/DNS for the TUN device and exit")
	setupKeep := fs.Bool("setup-keep", false, "leave OS routes/DNS in place on clean exit (fail-closed; restore manually)")
	setupFirewall := fs.Bool("setup-firewall", false, "install Windows Firewall DNS leak guard with OS setup")
	setupKillswitch := fs.Bool("setup-killswitch", false, "block ALL outbound traffic except the TUN device, loopback, and the resolved endpoints (full killswitch, not just DNS)")
	tunAddr := fs.String("tun-addr", winnet.DefaultAddressCIDR, "TUN IPv4 address/prefix for OS setup")
	dns := fs.String("dns", "1.1.1.1,8.8.8.8", "comma-separated DNS servers for OS setup")
	statusFile := fs.String("status-file", "", "periodically write JSON tunnel stats (state/bytesUp/bytesDown/server/transport) to this path; empty disables")
	verbose := fs.Bool("v", false, "verbose (debug) logging")
	_ = fs.Parse(args)
	setupLogger(*verbose)

	ctx, stop := signalContext()
	defer stop()

	setupBase := winnet.Config{
		InterfaceAlias: *dev,
		AddressCIDR:    *tunAddr,
		DNS:            strings.Split(*dns, ","),
		Endpoints:      splitServerList(*srv),
		Firewall:       *setupFirewall,
		Killswitch:     *setupKillswitch,
	}
	if *setupElevate {
		relaunchArgs := append([]string{"tun"}, args...)
		must(winnet.Elevate(ctx, os.Args[0], relaunchArgs, *setupDryRun, os.Stdout))
		return
	}
	if *setupRestore {
		must(winnet.Restore(ctx, setupBase, *setupDryRun, os.Stdout))
		return
	}
	if *setupCheck {
		must(winnet.Check(ctx, setupBase, *setupDryRun, os.Stdout))
		return
	}
	if *setupDryRun {
		must(winnet.Apply(ctx, setupBase, true, os.Stdout))
		return
	}

	if *srv == "" || *pbk == "" {
		fs.Usage()
		os.Exit(2)
	}

	var cfgs []carrier.Config
	for _, host := range strings.Split(*srv, ",") {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		cfgs = append(cfgs, carrier.Config{Server: host, PubB64: *pbk, SNI: *sni, ShortIDHex: *sid, Transport: *transport, Fp: *fp, BandwidthBps: uint64(*bw * 125000)})
	}
	if len(cfgs) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	setup := winnet.Config{
		InterfaceAlias: *dev,
		AddressCIDR:    *tunAddr,
		DNS:            strings.Split(*dns, ","),
		Endpoints:      serversFromConfigs(cfgs),
		Firewall:       *setupFirewall,
		Killswitch:     *setupKillswitch,
	}

	var dialer endpoint.Dialer
	if *transport == "auto" {
		dialer = endpoint.NewAutoPool(cfgs)
	} else {
		dialer = endpoint.NewPool(cfgs)
	}
	var setupPtr *winnet.Config
	if *setupOS {
		setupPtr = &setup
	}
	if err := runTUN(ctx, dialer, *dev, *mtu, setupPtr, *setupKeep, *statusFile, *srv, *transport); err != nil {
		log.Fatalf("tun: %v", err)
	}
}

func serversFromConfigs(cfgs []carrier.Config) []string {
	out := make([]string, 0, len(cfgs))
	for _, cfg := range cfgs {
		out = append(out, cfg.Server)
	}
	return out
}

func splitServerList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

// healthCmd pings each server endpoint and prints a one-shot health dashboard.
func healthCmd(args []string) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	srv := fs.String("server", "", "CHIMERA server host:port (required; comma-separated for multiple)")
	pbk := fs.String("pbk", "", "server public key, base64url (required)")
	sni := fs.String("sni", "www.microsoft.com", "steal-host SNI")
	sid := fs.String("sid", "", "short ID (hex)")
	transport := fs.String("transport", "tcp", "carrier transport to probe: tcp|quic")
	asJSON := fs.Bool("json", false, "print machine-readable JSON instead of the table (for UI callers)")
	_ = fs.Parse(args)
	if *srv == "" || *pbk == "" {
		fs.Usage()
		os.Exit(2)
	}

	var hosts []string
	for _, h := range strings.Split(*srv, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}

	results := healthreport.Run(hosts, func(h string) error {
		cfg := carrier.Config{Server: h, PubB64: *pbk, SNI: *sni, ShortIDHex: *sid, Transport: *transport}
		return carrier.Ping(cfg)
	})

	healthy := 0
	for _, r := range results {
		if r.OK {
			healthy++
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(results); err != nil {
			log.Fatalf("health: encode json: %v", err)
		}
		if healthy == 0 {
			os.Exit(1)
		}
		return
	}

	fmt.Printf("%-32s  %-8s  %s\n", "SERVER", "STATUS", "RTT / ERROR")
	fmt.Printf("%-32s  %-8s  %s\n", strings.Repeat("-", 32), "--------", strings.Repeat("-", 32))
	for _, r := range results {
		if r.OK {
			fmt.Printf("%-32s  %-8s  %s\n", r.Server, "OK", time.Duration(r.RTTMs)*time.Millisecond)
		} else {
			fmt.Printf("%-32s  %-8s  %s\n", r.Server, "FAIL", r.Error)
		}
	}
	fmt.Printf("\n%d/%d endpoints healthy\n", healthy, len(hosts))
	if healthy == 0 {
		os.Exit(1)
	}
}

// signalContext returns a context cancelled on SIGINT/SIGTERM for graceful shutdown.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// setupLogger installs a text slog handler. Long-running roles call it with the
// verbose flag; one-shot commands fall back to the default once at startup.
func setupLogger(verbose ...bool) {
	level := slog.LevelInfo
	if len(verbose) > 0 && verbose[0] {
		level = slog.LevelDebug
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

func clientCmd(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	srv := fs.String("server", "", "server host:port (required)")
	pbk := fs.String("pbk", "", "server public key, base64url (required)")
	sni := fs.String("sni", "www.microsoft.com", "steal-host SNI")
	sid := fs.String("sid", "", "short ID (hex)")
	transport := fs.String("transport", "tcp", "carrier transport: tcp|quic (quic needs -tags chimera_quic)")
	fp := fs.String("fp", "", "TLS fingerprint: chrome (default), chrome131, chrome120, firefox, safari, ios, edge")
	_ = fs.Parse(args)
	if *srv == "" || *pbk == "" {
		fs.Usage()
		os.Exit(2)
	}
	must(client.Run(client.Config{Server: *srv, PubB64: *pbk, SNI: *sni, ShortIDHex: *sid, Transport: *transport, Fp: *fp}))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
