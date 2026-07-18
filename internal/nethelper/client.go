package nethelper

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

func Call(req Request, timeout time.Duration) (Response, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", Port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return Response{}, fmt.Errorf("nethelper: dial %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return Response{}, fmt.Errorf("nethelper: encode request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("nethelper: decode response: %w", err)
	}
	return resp, nil
}
