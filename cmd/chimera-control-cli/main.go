package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
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
		fmt.Fprintln(os.Stderr, "usage: chimera-control-cli account <create|status|revoke|remove-devices> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("account status", flag.ExitOnError)
		number := fs.String("number", "", "account number to check (required)")
		fs.Parse(args[1:])
		if *number == "" {
			fmt.Fprintln(os.Stderr, "error: -number is required")
			os.Exit(2)
		}
		body := mustOK(adminRequest("POST", "/v1/admin/accounts/status", map[string]any{"account_number": *number}))
		var resp struct {
			Status      string `json:"status"`
			ExpiresAt   int64  `json:"expires_at"`
			DeviceCount int    `json:"device_count"`
			DeviceLimit int    `json:"device_limit"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			fmt.Fprintln(os.Stderr, "error: unexpected response:", string(body))
			os.Exit(1)
		}
		fmt.Printf(
			"status: %s\nexpires_at: %s\ndevices: %d/%d\n",
			resp.Status,
			time.Unix(resp.ExpiresAt, 0).UTC().Format(time.RFC3339),
			resp.DeviceCount, resp.DeviceLimit,
		)
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
	case "remove-devices":
		fs := flag.NewFlagSet("account remove-devices", flag.ExitOnError)
		number := fs.String("number", "", "account number to clear devices from (required)")
		fs.Parse(args[1:])
		if *number == "" {
			fmt.Fprintln(os.Stderr, "error: -number is required")
			os.Exit(2)
		}
		body := mustOK(adminRequest("POST", "/v1/admin/accounts/devices/reset", map[string]any{"account_number": *number}))
		var resp struct {
			RemovedCount int      `json:"removed_count"`
			ShortIDs     []string `json:"short_ids"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			fmt.Fprintln(os.Stderr, "error: unexpected response:", string(body))
			os.Exit(1)
		}
		fmt.Printf("removed %d device(s), revoked short IDs: %v\n", resp.RemovedCount, resp.ShortIDs)
	default:
		fmt.Fprintln(os.Stderr, "usage: chimera-control-cli account <create|status|revoke|remove-devices> ...")
		os.Exit(2)
	}
}

func catalogCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: chimera-control-cli catalog <add|remove|list|add-listener|remove-listener> ...")
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
	case "add-listener":
		fs := flag.NewFlagSet("catalog add-listener", flag.ExitOnError)
		serverID := fs.Int64("server-id", 0, "catalog server id (required)")
		transport := fs.String("transport", "", "reality|quic|ss|dot (required)")
		port := fs.Int("port", 0, "listener port (required)")
		fs.Parse(args[1:])
		if *serverID == 0 || *transport == "" || *port == 0 {
			fmt.Fprintln(os.Stderr, "error: -server-id, -transport, -port are required")
			os.Exit(2)
		}
		mustOK(adminRequest("POST", fmt.Sprintf("/v1/admin/servers/%d/listeners", *serverID), map[string]any{
			"transport": *transport, "port": *port,
		}))
		fmt.Println("listener added")
	case "remove-listener":
		fs := flag.NewFlagSet("catalog remove-listener", flag.ExitOnError)
		serverID := fs.Int64("server-id", 0, "catalog server id (required)")
		transport := fs.String("transport", "", "reality|quic|ss|dot (required)")
		fs.Parse(args[1:])
		if *serverID == 0 || *transport == "" {
			fmt.Fprintln(os.Stderr, "error: -server-id and -transport are required")
			os.Exit(2)
		}
		mustOK(adminRequest("DELETE", fmt.Sprintf("/v1/admin/servers/%d/listeners/%s", *serverID, *transport), nil))
		fmt.Println("listener removed")
	default:
		fmt.Fprintln(os.Stderr, "usage: chimera-control-cli catalog <add|remove|list|add-listener|remove-listener> ...")
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
