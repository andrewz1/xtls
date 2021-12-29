package xtls

import (
	"testing"

	"github.com/andrewz1/xnet"
)

func TestPeekSNI(t *testing.T) {
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
		ccn, sni, err := PeekSNI(cn)
		if err != nil {
			t.Log(err)
		} else {
			t.Log(sni)
		}
		ccn.Close()
	}
}
