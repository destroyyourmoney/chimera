//go:build windows

package main

import (
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sys/windows/svc"

	"chimera/internal/nethelper"
)

func main() {
	if len(os.Args) > 1 {
		var err error
		switch os.Args[1] {
		case "install":
			err = installService()
		case "uninstall":
			err = uninstallService()
		case "status":
			err = printStatus()
		default:
			fmt.Fprintf(os.Stderr, "chimera-helper: unknown subcommand %q (want install|uninstall|status)\n", os.Args[1])
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "chimera-helper: %v\n", err)
			os.Exit(1)
		}
		return
	}

	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "chimera-helper: determine session type: %v\n", err)
		os.Exit(1)
	}
	if !isService {
		fmt.Fprintln(os.Stderr, "chimera-helper: run with install|uninstall|status, or let the Service Control Manager start it")
		os.Exit(2)
	}

	setupServiceLogging()

	token, err := loadOrCreateToken()
	if err != nil {
		slog.Error("chimera-helper: load token", "err", err)
		os.Exit(1)
	}

	server := &nethelper.Server{Token: token, Runner: &procRunner{}}
	if err := svc.Run(serviceName, &chimeraService{server: server}); err != nil {
		slog.Error("chimera-helper: service run failed", "err", err)
		os.Exit(1)
	}
}

func loadOrCreateToken() (string, error) {
	if tok, err := nethelper.ReadToken(); err == nil && tok != "" {
		return tok, nil
	}
	tok, err := nethelper.GenerateToken()
	if err != nil {
		return "", err
	}
	if err := nethelper.WriteToken(tok); err != nil {
		return "", err
	}
	return tok, nil
}
