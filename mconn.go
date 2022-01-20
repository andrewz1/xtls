package xtls

import (
	"io"
	"net"
	"sync"
	"time"
)

type multiConn struct {
	sync.RWMutex
	cn     net.Conn
	mr     io.Reader
	closed bool
}

func (m *multiConn) Read(p []byte) (int, error) {
	m.RLock()
	defer m.RUnlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.mr.Read(p)
}

func (m *multiConn) Write(p []byte) (int, error) {
	m.RLock()
	defer m.RUnlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.cn.Write(p)
}

func (m *multiConn) Close() error {
	m.Lock()
	defer m.Unlock()
	if m.closed {
		return io.ErrClosedPipe
	}
	m.closed = true
	return m.cn.Close()
}

func (m *multiConn) LocalAddr() net.Addr {
	m.RLock()
	defer m.RUnlock()
	if m.closed {
		return nil
	}
	return m.cn.LocalAddr()
}

func (m *multiConn) RemoteAddr() net.Addr {
	m.RLock()
	defer m.RUnlock()
	if m.closed {
		return nil
	}
	return m.cn.RemoteAddr()
}

func (m *multiConn) SetDeadline(t time.Time) error {
	m.RLock()
	defer m.RUnlock()
	if m.closed {
		return io.ErrClosedPipe
	}
	return m.cn.SetDeadline(t)
}

func (m *multiConn) SetReadDeadline(t time.Time) error {
	m.RLock()
	defer m.RUnlock()
	if m.closed {
		return io.ErrClosedPipe
	}
	return m.cn.SetReadDeadline(t)
}

func (m *multiConn) SetWriteDeadline(t time.Time) error {
	m.RLock()
	defer m.RUnlock()
	if m.closed {
		return io.ErrClosedPipe
	}
	return m.cn.SetWriteDeadline(t)
}
