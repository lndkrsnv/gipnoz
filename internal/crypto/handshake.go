package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	TimestampToleranceSeconds = 30

	GoodbyeTarget = "gipnoz:goodbye"

	ephemeralPubLen = 32
	SessionIDLen    = 16

	ClientHelloFixedLen = ephemeralPubLen + ed25519.PublicKeySize + 8 + SessionIDLen + ed25519.SignatureSize
	ServerHelloLen      = ephemeralPubLen + ed25519.SignatureSize

	clientHelloDomain = "gipnoz-client-hello-v2"
	serverHelloDomain = "gipnoz-server-hello-v2"
	sessionInfoC2S    = "gipnoz-session-c2s-v1"
	sessionInfoS2C    = "gipnoz-session-s2c-v1"
)

type ClientHello struct {
	EphPub    []byte
	IDPub     ed25519.PublicKey
	SessionID []byte
	Sig       []byte
	Target    string
	Payload   []byte
}

func BuildClientHello(id ed25519.PrivateKey, target string, sessionID []byte) (payload []byte, eph *ecdh.PrivateKey, err error) {
	return BuildClientHelloAt(id, time.Now(), target, sessionID)
}

func BuildClientHelloAt(id ed25519.PrivateKey, ts time.Time, target string, sessionID []byte) (payload []byte, eph *ecdh.PrivateKey, err error) {
	if len(sessionID) != SessionIDLen {
		return nil, nil, fmt.Errorf("session id must be %d bytes, got %d", SessionIDLen, len(sessionID))
	}

	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(ts.Unix()))

	eph, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	ephPub := eph.PublicKey().Bytes()
	idPub := id.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(id, clientHelloSigningInput(ephPub, idPub, tsBytes, sessionID, target))

	payload = make([]byte, 0, ClientHelloFixedLen+len(target))
	payload = append(payload, ephPub...)
	payload = append(payload, idPub...)
	payload = append(payload, tsBytes...)
	payload = append(payload, sessionID...)
	payload = append(payload, sig...)
	payload = append(payload, target...)
	return payload, eph, nil
}

func ParseClientHello(payload []byte, clients map[string]ed25519.PublicKey) (*ClientHello, error) {
	if len(payload) <= ClientHelloFixedLen {
		return nil, fmt.Errorf("client hello too short: %d bytes", len(payload))
	}
	ephPub := payload[:ephemeralPubLen]
	idPub := ed25519.PublicKey(payload[ephemeralPubLen : ephemeralPubLen+ed25519.PublicKeySize])
	tsBytes := payload[ephemeralPubLen+ed25519.PublicKeySize : ephemeralPubLen+ed25519.PublicKeySize+8]
	sessionID := payload[ephemeralPubLen+ed25519.PublicKeySize+8 : ephemeralPubLen+ed25519.PublicKeySize+8+SessionIDLen]
	sig := payload[ClientHelloFixedLen-ed25519.SignatureSize : ClientHelloFixedLen]
	target := string(payload[ClientHelloFixedLen:])

	if _, ok := clients[string(idPub)]; !ok {
		return nil, fmt.Errorf("unknown client key")
	}
	if err := checkTimestamp(tsBytes); err != nil {
		return nil, err
	}
	if !ed25519.Verify(idPub, clientHelloSigningInput(ephPub, idPub, tsBytes, sessionID, target), sig) {
		return nil, fmt.Errorf("invalid signature")
	}

	return &ClientHello{
		EphPub:    ephPub,
		IDPub:     idPub,
		SessionID: sessionID,
		Sig:       sig,
		Target:    target,
		Payload:   payload,
	}, nil
}

func clientHelloSigningInput(ephPub, idPub, tsBytes, sessionID []byte, target string) []byte {
	msg := make([]byte, 0, len(clientHelloDomain)+ClientHelloFixedLen+len(target))
	msg = append(msg, clientHelloDomain...)
	msg = append(msg, ephPub...)
	msg = append(msg, idPub...)
	msg = append(msg, tsBytes...)
	msg = append(msg, sessionID...)
	msg = append(msg, target...)
	return msg
}

func checkTimestamp(tsBytes []byte) error {
	ts := int64(binary.BigEndian.Uint64(tsBytes))
	diff := time.Now().Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > TimestampToleranceSeconds {
		return fmt.Errorf("timestamp out of window (delta %ds)", diff)
	}
	return nil
}

func BuildServerHello(host ed25519.PrivateKey, clientHelloPayload []byte) (payload []byte, eph *ecdh.PrivateKey, err error) {
	eph, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	ephPub := eph.PublicKey().Bytes()
	sig := ed25519.Sign(host, serverHelloSigningInput(clientHelloPayload, ephPub))

	payload = make([]byte, 0, ServerHelloLen)
	payload = append(payload, ephPub...)
	payload = append(payload, sig...)
	return payload, eph, nil
}

func ParseServerHello(payload, clientHelloPayload []byte, serverPub ed25519.PublicKey) (ephPub []byte, err error) {
	if len(payload) != ServerHelloLen {
		return nil, fmt.Errorf("server hello wrong length: %d bytes", len(payload))
	}
	ephPub = payload[:ephemeralPubLen]
	sig := payload[ephemeralPubLen:]
	if !ed25519.Verify(serverPub, serverHelloSigningInput(clientHelloPayload, ephPub), sig) {
		return nil, fmt.Errorf("invalid server signature")
	}
	return ephPub, nil
}

func serverHelloSigningInput(clientHelloPayload, ephPub []byte) []byte {
	msg := make([]byte, 0, len(serverHelloDomain)+len(clientHelloPayload)+ephemeralPubLen)
	msg = append(msg, serverHelloDomain...)
	msg = append(msg, clientHelloPayload...)
	msg = append(msg, ephPub...)
	return msg
}

func DeriveSessionKeys(eph *ecdh.PrivateKey, peerEphPub, clientHelloPayload, serverHelloPayload []byte) (c2s, s2c []byte, err error) {
	pub, err := ecdh.X25519().NewPublicKey(peerEphPub)
	if err != nil {
		return nil, nil, fmt.Errorf("parse peer ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdh: %w", err)
	}

	transcript := sha256.New()
	transcript.Write(clientHelloPayload)
	transcript.Write(serverHelloPayload)
	salt := transcript.Sum(nil)

	c2s, err = deriveSessionKey(shared, salt, sessionInfoC2S)
	if err != nil {
		return nil, nil, err
	}
	s2c, err = deriveSessionKey(shared, salt, sessionInfoS2C)
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

func deriveSessionKey(shared, salt []byte, info string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte(info)), key); err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	return key, nil
}
