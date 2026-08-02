package client

import (
	"fmt"
	"sync/atomic"
	"syscall"
)

type protectorHolder struct {
	fn func(fd uintptr) bool
}

var protector atomic.Value

func SetProtector(fn func(fd uintptr) bool) {
	protector.Store(protectorHolder{fn: fn})
}

func currentProtector() func(fd uintptr) bool {
	holder, ok := protector.Load().(protectorHolder)
	if !ok {
		return nil
	}
	return holder.fn
}

func protectControl(_, _ string, raw syscall.RawConn) error {
	fn := currentProtector()
	if fn == nil {
		return nil
	}
	var protectErr error
	if err := raw.Control(func(fd uintptr) {
		if !fn(fd) {
			protectErr = fmt.Errorf("socket protect failed")
		}
	}); err != nil {
		return fmt.Errorf("raw conn control: %w", err)
	}
	return protectErr
}
