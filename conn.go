package xtls

import (
	"bytes"
	"io"
	"net"
)

type roConn struct {
	net.Conn
	buf []byte
}

type multiConn struct {
	net.Conn
	mr io.Reader
}

func newRoConn(cn net.Conn) *roConn {
	return &roConn{Conn: cn}
}

func (c *roConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == nil && n > 0 {
		c.buf = append(c.buf, p[:n]...)
	}
	return n, err
}

func (c *roConn) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (c *roConn) Close() error {
	return nil
}

func (c *roConn) multiConn() *multiConn {
	return &multiConn{
		Conn: c.Conn,
		mr:   io.MultiReader(bytes.NewReader(c.buf), c.Conn),
	}
}

func (m *multiConn) Read(p []byte) (int, error) {
	return m.mr.Read(p)
}
