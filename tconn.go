package xtls

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/andrewz1/xbuf"
	"github.com/andrewz1/xnet"
)

const (
	bufLen              = 2048
	hdrLen              = 5
	recordTypeHandshake = 22
	typeClientHello     = 1
	randLen             = 32
	sniExtNum           = 0
	sniHostType         = 0
	rdTmo               = 3 * time.Second
	rdTry               = 10
)

var (
	retErr = fmt.Errorf("handshake error")
)

type AuthChecker interface {
	IsAuth(finOnly bool) bool
}

type TConn struct {
	net.Conn           // original connection
	rd       io.Reader // multireader for reread hello message
	sni      string    // connection SNI
}

func (c *TConn) Read(p []byte) (int, error) {
	return c.rd.Read(p)
}

func (c *TConn) GetSNI() string {
	if c == nil {
		return ""
	}
	return c.sni
}

func (c *TConn) resolveSNI(ctx context.Context, r *net.Resolver) (net.IP, error) {
	ips, err := r.LookupIP(ctx, "ip4", c.sni)
	if err != nil {
		return nil, err
	}
	l := len(ips)
	if l == 0 {
		return nil, fmt.Errorf("host %s not found", c.sni)
	}
	return ips[int(time.Now().UnixNano())%l], nil
}

func (c *TConn) dialSNI(r *net.Resolver) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if r == nil {
		r = net.DefaultResolver
	}
	ip, err := c.resolveSNI(ctx, r)
	if err != nil {
		return nil, err
	}
	ta := &net.TCPAddr{IP: ip, Port: 443}
	return xnet.DialTCPContext(ctx, "tcp", nil, ta)
}

func (c *TConn) ProxySNI(tmo time.Duration, r *net.Resolver, ac AuthChecker) error {
	cc, err := c.dialSNI(r)
	if err != nil {
		c.Close()
		return err
	}
	return Pipe(c, cc, tmo, ac)
}

type hConn struct { // hello read helper
	cn   net.Conn // original connection
	rb   *xbuf.RB // data parse buffer
	buf  []byte   // data read buffer
	mLen int      // hello message len
}

func (c *hConn) readTmo(n int) (int, error) { // read with timeout
	defer c.cn.SetReadDeadline(time.Time{})
	c.cn.SetReadDeadline(time.Now().Add(rdTmo))
	nn, err := c.cn.Read(c.buf[:n])
	if err != nil {
		return 0, err
	}
	c.rb.Append(c.buf[:nn])
	return nn, nil
}

func (c *hConn) needLen() int {
	need := c.mLen - c.rb.Len()
	switch {
	case need <= 0:
		return 0
	case need > bufLen:
		return bufLen
	default:
		return need
	}
}

func (c *hConn) skipToExt() error {
	if c.rb.MustGetU8() != typeClientHello { // check is this client hello
		return retErr
	}
	if ln := int(c.rb.MustGetU24()); ln != c.rb.Left() { // second msg len
		return retErr
	}
	if c.rb.MustGetU16() < 0x300 { // second tls version
		return retErr
	}
	if !c.rb.Skip(randLen) { // rand bytes
		return retErr
	}
	if !c.rb.SkipL8() { // session id
		return retErr
	}
	if !c.rb.SkipL16() { // cipher suites
		return retErr
	}
	if !c.rb.SkipL8() { // compression methods
		return retErr
	}
	return nil
}

func (c *hConn) findSNI() (string, error) {
	ext, ok := c.rb.GetNestedL16() // get tls extensions to buf
	if !ok {
		return "", retErr
	}
	sniExt := findSNIExt(ext)
	if sniExt == nil {
		return "", retErr
	}
	sniList, ok := sniExt.GetNestedL16() // get sni list to buf
	if !ok {
		return "", retErr
	}
	sniHost := findSNIHost(sniList)
	if sniHost == nil {
		return "", retErr
	}
	return FixDomain(sniHost.String()), nil
}

func findSNIExt(ext *xbuf.RB) *xbuf.RB {
	var found bool
	for ext.Left() > 0 {
		if eNum, ok := ext.GetU16(); !ok {
			return nil
		} else if eNum == sniExtNum {
			found = true
			break
		}
		if !ext.SkipL16() {
			return nil
		}
	}
	if !found {
		return nil
	}
	if sniExt, ok := ext.GetNestedL16(); ok {
		return sniExt
	}
	return nil
}

func findSNIHost(sniList *xbuf.RB) *xbuf.RB {
	var found bool
	for sniList.Left() > 0 {
		if hType, ok := sniList.GetU8(); !ok {
			return nil
		} else if hType == sniHostType {
			found = true
			break
		}
		if !sniList.SkipL16() {
			return nil
		}
	}
	if !found {
		return nil
	}
	if sniHost, ok := sniList.GetNestedL16(); ok {
		return sniHost
	}
	return nil
}

func getHConn(cn net.Conn) (cc *hConn, err error) {
	c := &hConn{
		cn:  cn,
		rb:  xbuf.GetRB(nil),
		buf: make([]byte, bufLen),
	}
	defer func() {
		if err != nil {
			xbuf.PutRB(c.rb)
		}
	}()
	var n int
	if n, err = c.readTmo(hdrLen); err != nil {
		return
	}
	if n != hdrLen {
		err = retErr
		return
	}
	/* SSL 2.0 compatible Client Hello
	 * High bit of first byte (length) and content type is Client Hello
	 * See RFC5246 Appendix E.2
	 */
	if (c.buf[0]&0x80) != 0 && c.buf[2] == 1 {
		err = retErr
		return
	}
	// tls content type
	if c.rb.MustGetU8() != recordTypeHandshake {
		err = retErr
		return
	}
	// tls version
	if c.rb.MustGetU16() < 0x300 { // sslv3
		err = retErr
		return
	}
	c.mLen = int(c.rb.MustGetU16()) + hdrLen // full msg size
	var need int
	for i := 0; i < rdTry; i++ {
		if need = c.needLen(); need == 0 {
			break
		}
		if _, err = c.readTmo(need); err != nil {
			return
		}
	}
	if need != 0 {
		err = retErr
		return
	}
	cc = c
	return
}

func putHConn(c *hConn) {
	if c == nil {
		return
	}
	xbuf.PutRB(c.rb)
}

func ReadHello(cn net.Conn) (*TConn, error) {
	c, err := getHConn(cn)
	if err != nil {
		return nil, err
	}
	defer putHConn(c)
	if err = c.skipToExt(); err != nil {
		return nil, err
	}
	var sni string
	if sni, err = c.findSNI(); err != nil {
		return nil, err
	}
	rd := bytes.NewReader(c.rb.GetBuf(c.mLen))
	return &TConn{
		Conn: cn,
		rd:   io.MultiReader(rd, cn),
		sni:  sni,
	}, nil
}
