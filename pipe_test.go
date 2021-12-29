package xtls

import (
	"net"
	"testing"
	"time"

	"github.com/andrewz1/xnet"
)

func proxySNI(cn net.Conn) (net.Conn, error) {
	ccn, sni, err := PeekSNI(cn)
	if err != nil {
		return cn, err
	}
	return ccn, ProxySNI(ccn, sni, 10*time.Second, nil)
}

func TestProxySNI(t *testing.T) {
	ln, err := xnet.Listen("tcp", ":8443")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for {
		cn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			ccn, err := proxySNI(cn)
			t.Log(err)
			ccn.Close()
		}()
	}
}
