// Command chimera-control-cli is the operator's terminal-only interface to
// the control-plane's admin API (ROADMAP2 §2). Deliberately CLI-only, not a
// GUI or a mode of the Flutter client -- see ROADMAP2 §2's reasoning: this
// is where account keys and the server catalog get managed, and that's a
// smaller attack surface kept off any binary distributed to end users.
//
//	chimera-control-cli account create -expires 2027-01-01T00:00:00Z -device-limit 5
//	chimera-control-cli account revoke -number 7K2M-9PQR-4TZS-XW3H
//	chimera-control-cli catalog add -host vps.example.com -port 443 -pubkey B64KEY -sni www.microsoft.com -country Sweden -city Stockholm
//	chimera-control-cli catalog remove -id 3
//	chimera-control-cli catalog list
//	chimera-control-cli revoke -sid a1b2c3d4
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

var (
	globalAddr string
	globalTok  string
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// Global flags (-admin-addr/-admin-token) may appear before or after the
	// subcommand; scan for and strip them so the same flag set works either
	// way, e.g. both `cli -admin-addr X account create` and
	// `cli account create -admin-addr X`.
	args := extractGlobalFlags(os.Args[1:])
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	if globalAddr == "" {
		globalAddr = envOr("CHIMERA_CONTROL_ADMIN_ADDR", "http://127.0.0.1:8444")
	}
	if globalTok == "" {
		globalTok = os.Getenv("CHIMERA_CONTROL_ADMIN_TOKEN")
	}
	if globalTok == "" {
		fmt.Fprintln(os.Stderr, "error: admin token required (-admin-token or CHIMERA_CONTROL_ADMIN_TOKEN)")
		os.Exit(2)
	}

	switch args[0] {
	case "account":
		accountCmd(args[1:])
	case "catalog":
		catalogCmd(args[1:])
	case "revoke":
		revokeCmd(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: chimera-control-cli [-admin-addr URL] [-admin-token TOKEN] <account|catalog|revoke> ...")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// extractGlobalFlags pulls -admin-addr/-admin-token out of argv (wherever
// they appear) into globalAddr/globalTok and returns the remaining
// positional args unchanged.
func extractGlobalFlags(argv []string) []string {
	var out []string
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "-admin-addr", "--admin-addr":
			if i+1 < len(argv) {
				globalAddr = argv[i+1]
				i++
			}
		case "-admin-token", "--admin-token":
			if i+1 < len(argv) {
				globalTok = argv[i+1]
				i++
			}
		default:
			out = append(out, argv[i])
		}
	}
	return out
}

func adminRequest(method, path string, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, globalAddr+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+globalTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, err
}

func mustOK(body []byte, status int, err error) []byte {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if status >= 300 {
		fmt.Fprintf(os.Stderr, "error: server returned %d: %s\n", status, string(body))
		os.Exit(1)
	}
	return body
}

func accountCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: chimera-control-cli account <create|revoke> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("account create", flag.ExitOnError)
		expires := fs.String("expires", "", "RFC3339 expiry, e.g. 2027-01-01T00:00:00Z (required)")
		deviceLimit := fs.Int("device-limit", 5, "max devices for this account")
		fs.Parse(args[1:])
		if *expires == "" {
			fmt.Fprintln(os.Stderr, "error: -expires is required")
			os.Exit(2)
		}
		body := mustOK(adminRequest("POST", "/v1/admin/accounts", map[string]any{
			"expires_at":   *expires,
			"device_limit": *deviceLimit,
		}))
		var resp struct {
			AccountNumber string `json:"account_number"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			fmt.Fprintln(os.Stderr, "error: unexpected response:", string(body))
			os.Exit(1)
		}
		fmt.Println("account number (shown once, store it now):", resp.AccountNumber)
	case "revoke":
		fs := flag.NewFlagSet("account revoke", flag.ExitOnError)
		number := fs.String("number", "", "account number to revoke (required)")
		fs.Parse(args[1:])
		if *number == "" {
			fmt.Fprintln(os.Stderr, "error: -number is required")
			os.Exit(2)
		}
		mustOK(adminRequest("POST", "/v1/admin/accounts/revoke", map[string]any{"account_number": *number}))
		fmt.Println("revoked")
	default:
		fmt.Fprintln(os.Stderr, "usage: chimera-control-cli account <create|revoke> ...")
		os.Exit(2)
	}
}

func catalogCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: chimera-control-cli catalog <add|remove|list> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("catalog add", flag.ExitOnError)
		host := fs.String("host", "", "server host/IP (required)")
		port := fs.Int("port", 443, "server port")
		pubkey := fs.String("pubkey", "", "server static X25519 public key, base64url (required)")
		sni := fs.String("sni", "", "steal-host SNI (required)")
		fp := fs.String("fp", "", "fingerprint profile name")
		country := fs.String("country", "", "country (required)")
		city := fs.String("city", "", "city (required)")
		fs.Parse(args[1:])
		if *host == "" || *pubkey == "" || *sni == "" || *country == "" || *city == "" {
			fmt.Fprintln(os.Stderr, "error: -host, -pubkey, -sni, -country, -city are required")
			os.Exit(2)
		}
		body := mustOK(adminRequest("POST", "/v1/admin/servers", map[string]any{
			"host": *host, "port": *port, "pubkey": *pubkey, "sni": *sni,
			"fp": *fp, "country": *country, "city": *city,
		}))
		fmt.Println(string(body))
	case "remove":
		fs := flag.NewFlagSet("catalog remove", flag.ExitOnError)
		id := fs.Int64("id", 0, "server id (required)")
		fs.Parse(args[1:])
		if *id == 0 {
			fmt.Fprintln(os.Stderr, "error: -id is required")
			os.Exit(2)
		}
		mustOK(adminRequest("DELETE", fmt.Sprintf("/v1/admin/servers/%d", *id), nil))
		fmt.Println("removed")
	case "list":
		body := mustOK(adminRequest("GET", "/v1/admin/servers", nil))
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, body, "", "  "); err == nil {
			fmt.Println(pretty.String())
		} else {
			fmt.Println(string(body))
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: chimera-control-cli catalog <add|remove|list> ...")
		os.Exit(2)
	}
}

func revokeCmd(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	sid := fs.String("sid", "", "hex short ID to revoke immediately (required)")
	fs.Parse(args)
	if *sid == "" {
		fmt.Fprintln(os.Stderr, "error: -sid is required")
		os.Exit(2)
	}
	mustOK(adminRequest("POST", "/v1/admin/revocations", map[string]any{"short_id_hex": *sid}))
	fmt.Println("revoked")
}
