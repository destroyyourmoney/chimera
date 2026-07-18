package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"chimera/internal/controlplane"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		keygenCmd(os.Args[2:])
	case "serve":
		serveCmd(os.Args[2:])
	case "gencert":
		gencertCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: chimera-control keygen -out FILE")
	fmt.Fprintln(os.Stderr, "       chimera-control gencert -out FILE -host HOST_OR_IP [-days 3650]")
	fmt.Fprintln(os.Stderr, "       chimera-control serve -db FILE -signing-key FILE -listen ADDR -admin-listen ADDR -admin-token TOKEN [-tls-cert FILE -tls-key FILE] [-mirrors host1,host2]")
}

func gencertCmd(args []string) {
	fs := flag.NewFlagSet("gencert", flag.ExitOnError)
	out := fs.String("out", "control", "output basename: writes FILE.crt and FILE.key")
	host := fs.String("host", "", "IP address or DNS name the cert covers (required, e.g. the -listen public address)")
	days := fs.Int("days", 3650, "certificate validity in days")
	fs.Parse(args)

	if *host == "" {
		fmt.Fprintln(os.Stderr, "gencert: -host is required")
		os.Exit(2)
	}
	pin, err := controlplane.GenerateSelfSignedCert(*out+".crt", *out+".key", *host, *days)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gencert:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s.crt and %s.key\n", *out, *out)
	fmt.Printf("SHA-256 cert pin (embed in the client's kMirrorCertPins for this host): %s\n", pin)
	fmt.Println("this is self-signed -- clients must pin the SPKI hash above, not rely on a public CA")
}

func keygenCmd(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "control.key", "private key output path (public key written to FILE.pub)")
	fs.Parse(args)

	pub, priv, err := controlplane.GenerateKeypair()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	if err := controlplane.SavePrivateKey(*out, priv); err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	if err := controlplane.SavePublicKey(*out+".pub", pub); err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote private key to %s (keep secret) and public key to %s.pub\n", *out, *out)
}

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPath := fs.String("db", "control.db", "SQLite database path")
	signingKeyPath := fs.String("signing-key", "", "path to the current Ed25519 signing private key (required)")

	prevPubKeysFlag := fs.String("previous-pubkeys", "", "comma-separated hex Ed25519 public keys still accepted (rotation grace window)")
	listen := fs.String("listen", ":8443", "public API listen address")
	adminListen := fs.String("admin-listen", "127.0.0.1:8444", "admin API listen address (loopback-only recommended)")
	adminToken := fs.String("admin-token", "", "bearer token for the admin API (required)")
	mirrorsFlag := fs.String("mirrors", "", "comma-separated mirror addresses served at /v1/mirrors (ROADMAP2 §0.1 п.5)")
	tlsCert := fs.String("tls-cert", "", "PEM certificate for the public API; serves plain HTTP if unset (redeem/refresh/catalog then travel unencrypted)")
	tlsKey := fs.String("tls-key", "", "PEM private key matching -tls-cert")
	fs.Parse(args)

	if *signingKeyPath == "" || *adminToken == "" {
		usage()
		os.Exit(2)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Fprintln(os.Stderr, "serve: -tls-cert and -tls-key must be set together")
		os.Exit(2)
	}

	priv, err := controlplane.LoadPrivateKey(*signingKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
	pubKeys := []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}
	if *prevPubKeysFlag != "" {
		for _, hexKey := range strings.Split(*prevPubKeysFlag, ",") {
			pub, err := controlplane.ParsePublicKeyHex(strings.TrimSpace(hexKey))
			if err != nil {
				fmt.Fprintln(os.Stderr, "serve: previous-pubkeys:", err)
				os.Exit(1)
			}
			pubKeys = append(pubKeys, pub)
		}
	}

	db, err := controlplane.OpenDB(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
	defer db.Close()

	accounts := controlplane.NewAccountStore(db)
	catalog := controlplane.NewCatalogStore(db)
	revocations := controlplane.NewRevocationStore(db)
	signer := controlplane.NewSigner(priv)
	verifier := controlplane.NewVerifier(pubKeys...)

	var mirrors []string
	if *mirrorsFlag != "" {
		for _, m := range strings.Split(*mirrorsFlag, ",") {
			if m = strings.TrimSpace(m); m != "" {
				mirrors = append(mirrors, m)
			}
		}
	}

	api := controlplane.NewAPI(accounts, catalog, revocations, signer, verifier, mirrors)
	adminMux, err := controlplane.NewAdminMux(*adminToken, accounts, catalog, revocations)
	if err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	publicSrv := &http.Server{Addr: *listen, Handler: api.Mux()}
	adminSrv := &http.Server{Addr: *adminListen, Handler: adminMux}

	errCh := make(chan error, 2)
	go func() {
		if *tlsCert != "" {
			slog.Info("chimera-control: public API listening (tls)", "addr", *listen)
			errCh <- publicSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
			return
		}
		slog.Warn("chimera-control: public API listening WITHOUT TLS -- account_number/device_pubkey/token travel in the clear; set -tls-cert/-tls-key", "addr", *listen)
		errCh <- publicSrv.ListenAndServe()
	}()
	go func() {
		slog.Info("chimera-control: admin API listening", "addr", *adminListen)
		errCh <- adminSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("chimera-control: server error", "err", err)
		}
	}
	_ = publicSrv.Close()
	_ = adminSrv.Close()
}
