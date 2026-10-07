package httplisten

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeAcceptsHTTPAndHTTPS(t *testing.T) {
	cert := testCertificate(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("X-Proto", "tls")
		} else {
			w.Header().Set("X-Proto", r.Header.Get("X-Forwarded-Proto"))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	go func() {
		_ = serve(ln, handler, &cert)
	}()
	t.Cleanup(func() { _ = ln.Close() })

	base := ln.Addr().String()

	plain, err := http.Get("http://" + base + "/")
	if err != nil {
		t.Fatal(err)
	}
	plain.Body.Close()
	if plain.StatusCode != http.StatusNoContent {
		t.Fatalf("plain status %d", plain.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, "http://"+base+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	proxied, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	proxied.Body.Close()
	if proxied.Header.Get("X-Proto") != "https" {
		t.Fatalf("forwarded proto header was not visible: %q", proxied.Header.Get("X-Proto"))
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	secure, err := client.Get("https://" + base + "/")
	if err != nil {
		t.Fatal(err)
	}
	secure.Body.Close()
	if secure.Header.Get("X-Proto") != "tls" {
		t.Fatalf("https connection was not treated as TLS: %q", secure.Header.Get("X-Proto"))
	}
}

func TestIsTLSClientHello(t *testing.T) {
	t.Parallel()
	if !isTLSClientHello([]byte{0x16, 0x03, 0x01}) {
		t.Fatal("tls 1.0 record must be detected")
	}
	if isTLSClientHello([]byte("GET")) {
		t.Fatal("http request must not be detected as tls")
	}
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
