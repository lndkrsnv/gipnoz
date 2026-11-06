package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
)

const (
	socks5Version    = 0x05
	authNone         = 0x00
	cmdConnect       = 0x01
	atypIPv4         = 0x01
	atypDomain       = 0x03
	atypIPv6         = 0x04
	repSuccess       = 0x00
	repUnsupported   = 0x07
	repUnsupportedAt = 0x08
)

func ServeSOCKS5(lis net.Listener, handler func(conn net.Conn, targetAddr string)) error {
	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			slog.Warn("socks5 accept error", "err", err)
			continue
		}
		go func() {
			targetAddr, err := socks5Handshake(conn)
			if err != nil {
				slog.Debug("socks5 handshake failed", "err", err)
				conn.Close()
				return
			}
			handler(conn, targetAddr)
		}()
	}
}

func socks5Handshake(conn net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read greeting header: %w", err)
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("unsupported socks version: %d", header[0])
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read auth methods: %w", err)
	}
	if _, err := conn.Write([]byte{socks5Version, authNone}); err != nil {
		return "", fmt.Errorf("write auth reply: %w", err)
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", fmt.Errorf("read connect request: %w", err)
	}
	if req[1] != cmdConnect {
		if err := sendReply(conn, repUnsupported); err != nil {
			return "", err
		}
		return "", fmt.Errorf("unsupported command: %d", req[1])
	}

	host, err := readHost(conn, req[3])
	if err != nil {
		if replyErr := sendReply(conn, repUnsupportedAt); replyErr != nil {
			return "", replyErr
		}
		return "", err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	if err := sendReply(conn, repSuccess); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readHost(conn net.Conn, addrType byte) (string, error) {
	switch addrType {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read ipv4 address: %w", err)
		}
		return net.IP(addr).String(), nil
	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read ipv6 address: %w", err)
		}
		return net.IP(addr).String(), nil
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		return string(domain), nil
	default:
		return "", fmt.Errorf("unsupported address type: %d", addrType)
	}
}

func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{socks5Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("write reply: %w", err)
	}
	return nil
}
