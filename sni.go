package xtls

import (
	"crypto/tls"
	"net"
	"strings"
	"time"
)

type sniPeeker struct {
	sni string
}

func FixDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(d), ".")
}

func FixDomains(d []string) []string {
	if len(d) == 0 {
		return nil
	}
	dd := make([]string, 0, len(d))
	for _, v := range d {
		dd = append(dd, FixDomain(v))
	}
	return dd
}

func (p *sniPeeker) peekSNI(info *tls.ClientHelloInfo) (*tls.Config, error) {
	p.sni = FixDomain(info.ServerName)
	return nil, nil // this always give error!
}

func (p *sniPeeker) ok() bool {
	return len(p.sni) > 0
}

func PeekSNI(cn net.Conn) (net.Conn, string, error) {
	cn.SetDeadline(time.Now().Add(5 * time.Second))
	defer cn.SetDeadline(time.Time{})
	ro := newRoConn(cn)
	pk := &sniPeeker{}
	cfg := &tls.Config{
		GetConfigForClient: pk.peekSNI,
	}
	if err := tls.Server(ro, cfg).Handshake(); !pk.ok() {
		return cn, "", err
	}
	return ro.multiConn(), pk.sni, nil
}
