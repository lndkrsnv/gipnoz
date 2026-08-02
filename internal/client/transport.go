package client

import (
	"context"
	stdtls "crypto/tls"
	"fmt"
	"net"

	tls "github.com/refraction-networking/utls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "gipnoz/internal/proto"
)

func DialServer(address, sni, fingerprint string, insecureMode bool) (pb.TunnelClient, *grpc.ClientConn, error) {
	var opts []grpc.DialOption
	if insecureMode {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(newUTLSCredentials(sni, fingerprint)))
	}
	if sni != "" {
		opts = append(opts, grpc.WithAuthority(sni))
	}
	opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{Control: protectControl}).DialContext(ctx, "tcp", addr)
	}))

	conn, err := grpc.NewClient("passthrough:///"+address, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("grpc dial: %w", err)
	}
	return pb.NewTunnelClient(conn), conn, nil
}

type utlsCredentials struct {
	sni         string
	clientHello *tls.ClientHelloID
}

func newUTLSCredentials(sni, fingerprint string) *utlsCredentials {
	return &utlsCredentials{
		sni:         sni,
		clientHello: resolveFingerprint(fingerprint),
	}
}

func (c *utlsCredentials) ClientHandshake(ctx context.Context, _ string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	cfg := &tls.Config{
		ServerName: c.sni,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	conn := tls.UClient(rawConn, cfg, *c.clientHello)

	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("utls handshake: %w", err)
	}

	state := conn.ConnectionState()
	tlsInfo := credentials.TLSInfo{State: stdtls.ConnectionState{
		Version:                    state.Version,
		HandshakeComplete:          state.HandshakeComplete,
		CipherSuite:                state.CipherSuite,
		NegotiatedProtocol:         state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: state.NegotiatedProtocolIsMutual,
		ServerName:                 state.ServerName,
		PeerCertificates:           state.PeerCertificates,
		VerifiedChains:             state.VerifiedChains,
		OCSPResponse:               state.OCSPResponse,
		TLSUnique:                  state.TLSUnique,
	}}
	return conn, tlsInfo, nil
}

func (c *utlsCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("utls credentials: server handshake not supported")
}

func (c *utlsCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

func (c *utlsCredentials) Clone() credentials.TransportCredentials {
	return &utlsCredentials{sni: c.sni, clientHello: c.clientHello}
}

func (c *utlsCredentials) OverrideServerName(name string) error {
	c.sni = name
	return nil
}

func resolveFingerprint(name string) *tls.ClientHelloID {
	switch name {
	case "firefox":
		return &tls.HelloFirefox_Auto
	default:
		return &tls.HelloChrome_Auto
	}
}
