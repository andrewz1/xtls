package xtls

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andrewz1/xnet"
)

func connMain(t *testing.T, cn net.Conn) {
	tc, err := ReadHello(cn)
	if err != nil {
		cn.Close()
		t.Fatal(err)
	}
	t.Log(tc.ProxySNI(time.Second*10, nil))
}

func TestProxySNI(t *testing.T) {
	ln, err := xnet.Listen("tcp", ":8443")
	if err != nil {
		t.Fatal(err)
	}
	for {
		cn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go connMain(t, cn)
	}
}

// proxy dns
type pdns struct {
	ua  []string // dns addresses
	cnt uint32   // ip counter
}

// dial func
func (p *pdns) dial(ctx context.Context, nn, _ string) (net.Conn, error) {
	n := int(atomic.AddUint32(&p.cnt, 1))
	n %= len(p.ua)
	ra := p.ua[n]
	if _, _, err := net.SplitHostPort(ra); err != nil {
		ra += ":53"
	}
	return xnet.DialContext(ctx, nn, ra)
}

// create proxy resolver
func newResolver(dns []string) (*net.Resolver, error) {
	if len(dns) == 0 {
		return nil, fmt.Errorf("no dns IP set")
	}
	p := &pdns{ua: append([]string{}, dns...)}
	return &net.Resolver{Dial: p.dial}, nil
}

var (
	srvs = []string{"1.1.1.1", "1.0.0.1"}
)

func lookup(dns *net.Resolver, host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	return dns.LookupIP(ctx, "ip4", host)
}

func TestResolver(t *testing.T) {
	dns, err := newResolver(srvs)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := lookup(dns, "www.google.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range ip {
		t.Logf("%v", v)
	}
}
