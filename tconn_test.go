package xtls

import (
	"testing"

	"github.com/andrewz1/xnet"
)

func TestReadHello(t *testing.T) {
	ln, err := xnet.Listen("tcp", ":8443")
	if err != nil {
		t.Fatal(err)
	}
	for {
		cn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		tc, err := ReadHello(cn)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("sni: %s", tc.sni)
		tc.Close()
	}
}
