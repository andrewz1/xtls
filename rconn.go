package xtls

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"
)

type roConn struct {
	sync.Mutex
	cn     net.Conn
	buf    []byte
	closed bool
}

func newRoConn(cn net.Conn) *roConn {
	return &roConn{cn: cn}
}

func (c *roConn) Read(p []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := c.cn.Read(p)
	if err == nil && n > 0 {
		c.buf = append(c.buf, p[:n]...)
	}
	return n, err
}

func (c *roConn) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (c *roConn) Close() error {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	c.closed = true
	return nil
}

func (c *roConn) LocalAddr() net.Addr {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return nil
	}
	return c.cn.LocalAddr()
}

func (c *roConn) RemoteAddr() net.Addr {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return nil
	}
	return c.cn.RemoteAddr()
}

func (c *roConn) SetDeadline(t time.Time) error {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	return c.cn.SetDeadline(t)
}

func (c *roConn) SetReadDeadline(t time.Time) error {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	return c.cn.SetReadDeadline(t)
}

func (c *roConn) SetWriteDeadline(t time.Time) error {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return io.ErrClosedPipe
	}
	return c.cn.SetWriteDeadline(t)
}

func (c *roConn) multiConn() *multiConn {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return &multiConn{
		cn: c.cn,
		mr: io.MultiReader(bytes.NewReader(c.buf), c.cn),
	}
}
