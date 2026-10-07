package httplisten

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const peekTimeout = 5 * time.Second

// Serve слушает addr и на одном порту принимает и TLS, и обычный HTTP.
// HTTP нужен reverse proxy, который завершает TLS у себя и присылает X-Forwarded-Proto.
func Serve(addr string, handler http.Handler, certFile, keyFile string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	var cert *tls.Certificate
	if certFile != "" {
		if st, statErr := os.Stat(certFile); statErr == nil && !st.IsDir() {
			pair, loadErr := tls.LoadX509KeyPair(certFile, keyFile)
			if loadErr != nil {
				ln.Close()
				return loadErr
			}
			cert = &pair
		}
	}
	return serve(ln, handler, cert)
}

func serve(ln net.Listener, handler http.Handler, cert *tls.Certificate) error {
	defer ln.Close()
	if cert == nil {
		return (&http.Server{Handler: handler}).Serve(ln)
	}

	plain := newChanListener(ln.Addr())
	secured := newChanListener(ln.Addr())
	defer plain.close()
	defer secured.close()

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	errCh := make(chan error, 2)
	go func() {
		errCh <- (&http.Server{Handler: handler}).Serve(plain)
	}()
	go func() {
		errCh <- (&http.Server{Handler: handler, TLSConfig: tlsCfg}).Serve(tls.NewListener(secured, tlsCfg))
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go dispatch(conn, plain, secured)
	}
}

func dispatch(conn net.Conn, plain, secured *chanListener) {
	wrapped, clientTLS, err := classify(conn)
	if err != nil {
		conn.Close()
		return
	}
	if clientTLS {
		secured.add(wrapped)
		return
	}
	plain.add(wrapped)
}

func classify(conn net.Conn) (net.Conn, bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(peekTimeout)); err != nil {
		return nil, false, err
	}
	reader := bufio.NewReader(conn)
	header, err := reader.Peek(3)
	if err != nil {
		return nil, false, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, false, err
	}
	return &bufferedConn{Conn: conn, r: reader}, isTLSClientHello(header), nil
}

func isTLSClientHello(header []byte) bool {
	return len(header) >= 3 && header[0] == 0x16 && header[1] == 0x03
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{
		addr: addr,
		ch:   make(chan net.Conn, 128),
		done: make(chan struct{}),
	}
}

func (l *chanListener) add(conn net.Conn) {
	select {
	case <-l.done:
		conn.Close()
	case l.ch <- conn:
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case conn, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (l *chanListener) Close() error {
	l.close()
	return nil
}

func (l *chanListener) close() {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}
