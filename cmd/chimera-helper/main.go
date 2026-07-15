//go:build windows

// Command chimera-helper is a persistent Windows service that owns the
// elevated half of CHIMERA's full-tunnel networking (TUN device, routes,
// DNS, Windows Firewall rules -- see internal/winnet), so the unprivileged
// Flutter tray app never has to trigger a UAC prompt on every Connect.
//
// It runs as LocalSystem once installed, listening on a loopback-only TCP
// socket (internal/nethelper) authenticated by a shared-secret token file
// under %ProgramData%\chimera\ (see internal/nethelper's doc comments for
// why loopback+token instead of a named pipe, and why %ProgramData% instead
// of a per-user directory). Actual tunnel setup/teardown is done by
// spawning `chimera.exe tun ...` as a child process -- since the service is
// already SYSTEM, that child inherits full privilege with no further
// elevation, and this reuses 100% of the already-tested CLI/internal/winnet
// logic instead of reimplementing it here.
//
// Subcommands (all require an elevated/admin caller; the Flutter app
// triggers `install` through one UAC prompt via Start-Process -Verb RunAs,
// mirroring the pattern network_protection.dart already uses for
// `chimera.exe tun -setup-elevate`):
//
//	chimera-helper.exe install    register + start the service (Automatic start)
//	chimera-helper.exe uninstall  stop + remove the service, delete the token
//	chimera-helper.exe status     print running/stopped/not-installed and exit
//
// With no subcommand, and only when actually launched by the Service
// Control Manager, it runs as the service itself (svc.Run in service_windows.go).
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

// loadOrCreateToken reads the shared secret written at install time. If
// missing (e.g. the service was registered by hand rather than through
// `install`), it mints and persists a fresh one so the service can still
// come up -- the tray app just won't have a matching token until it's told
// to re-run `install` (surfaced as an auth failure, not a crash).
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
