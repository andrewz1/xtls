package xtls

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	pipeBuf = 2048
)

type pipeOne struct {
	src net.Conn
	dst net.Conn
	tmo time.Duration
	wg  *sync.WaitGroup
	ec  chan error
	ac  AuthChecker
}

func (p *pipeOne) rdTmo() {
	p.src.SetReadDeadline(time.Now().Add(p.tmo))
}

func (p *pipeOne) wrTmo() {
	p.dst.SetWriteDeadline(time.Now().Add(p.tmo))
}

func (p *pipeOne) read(b []byte) (int, error) {
	if !p.ac.IsAuth(false) {
		return 0, fmt.Errorf("session timeout")
	}
	p.rdTmo()
	return p.src.Read(b)
}

func (p *pipeOne) write(b []byte) error {
	if !p.ac.IsAuth(false) {
		return fmt.Errorf("session timeout")
	}
	p.wrTmo()
	s := 0
	for s < len(b) {
		n, err := p.dst.Write(b[s:])
		if err != nil {
			return err
		}
		s += n
	}
	return nil
}

func (p *pipeOne) pipe() {
	defer p.wg.Done()
	buf := make([]byte, pipeBuf)
	for {
		n, err := p.read(buf)
		if err != nil {
			p.ec <- err
			break
		}
		if err = p.write(buf[:n]); err != nil {
			p.ec <- err
			break
		}
	}
}

func Pipe(inner, outer net.Conn, tmo time.Duration, ac AuthChecker) error {
	ec := make(chan error, 3)
	var wg sync.WaitGroup
	wg.Add(2)
	p1 := pipeOne{
		src: inner,
		dst: outer,
		tmo: tmo,
		wg:  &wg,
		ec:  ec,
		ac:  ac,
	}
	p2 := pipeOne{
		src: outer,
		dst: inner,
		tmo: tmo,
		wg:  &wg,
		ec:  ec,
		ac:  ac,
	}
	go p1.pipe()
	go p2.pipe()
	err := <-ec
	wg.Wait()
	close(ec)
	return err
}
