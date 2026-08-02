package server

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"gipnoz/internal/crypto"
	pb "gipnoz/internal/proto"
)

func relay(stream pb.Tunnel_ConnectServer, conn net.Conn, decCipher, encCipher *crypto.Cipher, padMin, padMax int, idleTimeout time.Duration, onClientClosed func()) {
	var wg sync.WaitGroup
	wg.Add(2)

	targetDead := make(chan struct{})

	go func() {
		defer wg.Done()
		defer onClientClosed()
		streamToConn(stream, conn, decCipher, idleTimeout)
	}()

	go func() {
		defer wg.Done()
		defer close(targetDead)
		connToStream(stream, conn, encCipher, padMin, padMax, idleTimeout)
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-targetDead:
	}
}

func streamToConn(stream pb.Tunnel_ConnectServer, conn net.Conn, cipher *crypto.Cipher, idleTimeout time.Duration) {
	defer closeWrite(conn)
	for {
		chunk, err := stream.Recv()
		if err != nil {
			if err != io.EOF {
				slog.Debug("stream recv error", "err", err)
			}
			return
		}
		plaintext, err := cipher.Decrypt(chunk.Payload)
		if err != nil {
			slog.Warn("decrypt error", "err", err)
			return
		}
		conn.SetDeadline(time.Now().Add(idleTimeout))
		if _, err := conn.Write(plaintext); err != nil {
			slog.Debug("conn write error", "err", err)
			return
		}
	}
}

func connToStream(stream pb.Tunnel_ConnectServer, conn net.Conn, cipher *crypto.Cipher, padMin, padMax int, idleTimeout time.Duration) {
	defer conn.Close()
	buf := make([]byte, 32*1024)
	for {
		conn.SetDeadline(time.Now().Add(idleTimeout))
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := sendChunk(stream, cipher, buf[:n], padMin, padMax); sendErr != nil {
				slog.Debug("stream send error", "err", sendErr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				slog.Debug("conn read error", "err", err)
			}
			return
		}
	}
}

func sendChunk(stream pb.Tunnel_ConnectServer, cipher *crypto.Cipher, data []byte, padMin, padMax int) error {
	encrypted, err := cipher.Encrypt(data)
	if err != nil {
		return err
	}
	padding, err := crypto.GeneratePadding(padMin, padMax)
	if err != nil {
		return err
	}
	return stream.Send(&pb.Chunk{Payload: encrypted, Padding: padding})
}

func closeWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}
