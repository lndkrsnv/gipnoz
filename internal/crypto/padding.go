package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

func GeneratePadding(minSize, maxSize int) ([]byte, error) {
	if minSize < 0 || maxSize < minSize {
		return nil, fmt.Errorf("invalid padding range [%d, %d]", minSize, maxSize)
	}
	if minSize == maxSize {
		return randomBytes(minSize)
	}

	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, fmt.Errorf("generate padding length: %w", err)
	}
	size := minSize + int(binary.LittleEndian.Uint64(buf[:])%uint64(maxSize-minSize+1))
	return randomBytes(size)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	return b, nil
}
