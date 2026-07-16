// Command chimera-control runs the account/catalog control-plane
// (ROADMAP2 §0): the public API (redeem/refresh/catalog/revocations/mirrors)
// and the loopback-only admin API that chimera-control-cli talks to.
// It is the only process with database access -- data-plane servers and
// clients only ever call its HTTP APIs or verify its signed tokens locally.
//
//	chimera-control keygen -out control.key
//	chimera-control serve -db control.db -signing-key control.key -listen :8443 -admin-listen 127.0.0.1:8444 -admin-token TOKEN
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
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: chimera-control keygen -out FILE")
	fmt.Fprintln(os.Stderr, "       chimera-control serve -db FILE -signing-key FILE -listen ADDR -admin-listen ADDR -admin-token TOKEN [-mirrors host1,host2]")
}

// keygenCmd generates a fresh Ed25519 signing keypair (ROADMAP2 §0.1 п.4).
// The private key file is a deploy secret; the public key is what gets
// distributed to data-plane servers (-controlplane-pubkey) and baked into
// client builds.
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
	// prevSigningPubKeys accepts hex-encoded public keys still honored for
	// verification during a rotation grace window (ROADMAP2 §0.1 п.4) --
	// tokens signed by the outgoing key keep verifying until it's retired.
	prevPubKeysFlag := fs.String("previous-pubkeys", "", "comma-separated hex Ed25519 public keys still accepted (rotation grace window)")
	listen := fs.String("listen", ":8443", "public API listen address")
	adminListen := fs.String("admin-listen", "127.0.0.1:8444", "admin API listen address (loopback-only recommended)")
	adminToken := fs.String("admin-token", "", "bearer token for the admin API (required)")
	mirrorsFlag := fs.String("mirrors", "", "comma-separated mirror addresses served at /v1/mirrors (ROADMAP2 §0.1 п.5)")
	fs.Parse(args)

	if *signingKeyPath == "" || *adminToken == "" {
		usage()
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
		slog.Info("chimera-control: public API listening", "addr", *listen)
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
