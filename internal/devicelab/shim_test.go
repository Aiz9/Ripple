package devicelab

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// clientHelloBytes produces a genuine TLS ClientHello carrying serverName.
func clientHelloBytes(t *testing.T, serverName string) []byte {
	t.Helper()
	pr, pw := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, 16384)
		n, _ := pr.Read(b)
		got <- append([]byte(nil), b[:n]...)
		pr.Close()
	}()
	tc := tls.Client(pw, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	_ = tc.Handshake() // errors once the pipe closes — we only need the ClientHello
	select {
	case ch := <-got:
		return ch
	case <-time.After(3 * time.Second):
		t.Fatal("no ClientHello captured")
		return nil
	}
}

func TestPeekSNI(t *testing.T) {
	ch := clientHelloBytes(t, "api.example.com")
	sni, err := peekSNI(bufio.NewReaderSize(bytes.NewReader(ch), 16384))
	if err != nil {
		t.Fatalf("peekSNI: %v", err)
	}
	if sni != "api.example.com" {
		t.Fatalf("sni=%q, want api.example.com", sni)
	}
}

func TestPeekHTTPHost(t *testing.T) {
	req := "GET /webbackend/v2/initial/data HTTP/1.1\r\nHost: bankxp.example.com\r\nAccept: */*\r\n\r\n"
	host, err := peekHTTPHost(bufio.NewReaderSize(strings.NewReader(req), 4096))
	if err != nil || host != "bankxp.example.com" {
		t.Fatalf("host=%q err=%v", host, err)
	}
}

// TestShimConvertsTLSToConnect verifies the core behaviour: a NAT-redirected TLS
// connection (no CONNECT) is turned into a CONNECT to the right host against the
// explicit proxy, and the client's ClientHello is replayed through.
func TestShimConvertsTLSToConnect(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	gotTarget := make(chan string, 1)
	gotHello := make(chan []byte, 1)
	go func() {
		c, err := proxyLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		line, _ := br.ReadString('\n')
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			gotTarget <- parts[1]
		} else {
			gotTarget <- ""
		}
		for {
			l, e := br.ReadString('\n')
			if e != nil || l == "\r\n" || l == "\n" {
				break
			}
		}
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		// The next bytes should be the replayed ClientHello.
		hdr := make([]byte, 5)
		if _, e := io.ReadFull(br, hdr); e == nil {
			body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
			io.ReadFull(br, body)
			gotHello <- append(hdr, body...)
		} else {
			gotHello <- nil
		}
	}()

	shim, err := NewTransparentShim("127.0.0.1:0", proxyLn.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	go shim.Serve()
	defer shim.Close()

	hello := clientHelloBytes(t, "target.example.com")
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", shim.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}

	select {
	case tgt := <-gotTarget:
		if tgt != "target.example.com:443" {
			t.Fatalf("CONNECT target=%q, want target.example.com:443", tgt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shim did not issue CONNECT")
	}
	select {
	case replayed := <-gotHello:
		sni, _ := peekSNI(bufio.NewReaderSize(bytes.NewReader(replayed), 16384))
		if sni != "target.example.com" {
			t.Fatalf("replayed ClientHello SNI=%q — the app's handshake was not forwarded intact", sni)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ClientHello was not replayed to the proxy")
	}
}
