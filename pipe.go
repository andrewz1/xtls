package xtls

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/andrewz1/xnet"
)

type pipeOne struct {
	src net.Conn
	dst net.Conn
	tmo time.Duration
	wg  *sync.WaitGroup
	ec  chan error
}

func (p *pipeOne) pipe() {
	defer func() {
		p.src.Close()
		p.dst.Close()
		p.wg.Done()
	}()
	buf := make([]byte, 2048)
	for {
		p.src.SetReadDeadline(time.Now().Add(p.tmo))
		n, err := p.src.Read(buf)
		if err != nil {
			p.ec <- err
			break
		}
		p.dst.SetWriteDeadline(time.Now().Add(p.tmo))
		s := 0
		for s < n {
			nn, err := p.dst.Write(buf[s:n])
			if err != nil {
				p.ec <- err
				break
			}
			s += nn
		}
	}
}

func Pipe(inner, outer net.Conn, tmo time.Duration) error {
	ec := make(chan error, 3)
	var wg sync.WaitGroup
	wg.Add(2)
	p1 := pipeOne{
		src: inner,
		dst: outer,
		tmo: tmo,
		wg:  &wg,
		ec:  ec,
	}
	go p1.pipe()
	p2 := pipeOne{
		src: outer,
		dst: inner,
		tmo: tmo,
		wg:  &wg,
		ec:  ec,
	}
	go p2.pipe()
	err := <-ec
	wg.Wait()
	close(ec)
	return err
}

func net2ip(network string) string {
	l := len(network)
	if l == 0 {
		return "ip"
	}
	switch network[l-1] {
	case '4':
		return "ip4"
	case '6':
		return "ip6"
	default:
		return "ip"
	}
}

func resolveIP(ctx context.Context, network, sni string, r *net.Resolver) (net.IP, error) {
	ips, err := r.LookupIP(ctx, network, sni)
	if err != nil {
		return nil, err
	}
	l := len(ips)
	if l == 0 {
		return nil, fmt.Errorf("host %s not found", sni)
	}
	n := int(time.Now().UnixNano()) % l
	return ips[n], nil
}

func DialSNI(network, sni string, r *net.Resolver) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if r == nil {
		r = net.DefaultResolver
	}
	ip, err := resolveIP(ctx, net2ip(network), sni, r)
	if err != nil {
		return nil, err
	}
	ta := &net.TCPAddr{IP: ip, Port: 443}
	return xnet.DialTCPContext(ctx, network, nil, ta)
}

func detectNet(cn net.Conn) (string, error) {
	ips, _, err := net.SplitHostPort(cn.RemoteAddr().String())
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(ips)
	if len(ip) == 0 {
		return "", fmt.Errorf("invalid IP: %s", ips)
	}
	if len(ip.To4()) == net.IPv4len {
		return "tcp4", nil
	}
	return "tcp6", nil
}

func ProxySNI(cn net.Conn, sni string, tmo time.Duration, r *net.Resolver) error {
	network, err := detectNet(cn)
	if err != nil {
		return err
	}
	cn2, err := DialSNI(network, sni, r)
	if err != nil {
		return err
	}
	return Pipe(cn, cn2, tmo)
}
