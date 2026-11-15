package devicelab

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// TransparentShim accepts NAT-redirected connections (no CONNECT line) from a
// proxy-unaware app, recovers the intended host from the TLS SNI (HTTPS) or the
// Host header (HTTP), and forwards the connection to an explicit MITM proxy
// (go-mitmproxy) as a CONNECT tunnel. The app's own bytes — including the peeked
// ClientHello — are replayed to the proxy, so all of the engine's existing
// interception, CA handling and recording applies to traffic from apps that
// ignore the system HTTP proxy (Flutter being the important case).
type TransparentShim struct {
	proxyAddr string
	ln        net.Listener
	logf      func(string, ...any)
	wg        sync.WaitGroup
}

// NewTransparentShim listens on listenAddr and will tunnel to the explicit MITM
// proxy at proxyAddr (e.g. "127.0.0.1:8798").
func NewTransparentShim(listenAddr, proxyAddr string, logf func(string, ...any)) (*TransparentShim, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &TransparentShim{proxyAddr: proxyAddr, ln: ln, logf: logf}, nil
}

func (s *TransparentShim) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Serve accepts connections until Close. Run it in a goroutine.
func (s *TransparentShim) Serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.handle(c) }()
	}
}

func (s *TransparentShim) Close() error {
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *TransparentShim) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReaderSize(client, 16384)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	var target string
	if first[0] == 0x16 { // TLS handshake record
		sni, perr := peekSNI(br)
		if perr != nil || sni == "" {
			s.logf("shim: could not read SNI: %v", perr)
			return
		}
		target = net.JoinHostPort(sni, "443")
	} else {
		host, perr := peekHTTPHost(br)
		if perr != nil || host == "" {
			return
		}
		if !strings.Contains(host, ":") {
			host = net.JoinHostPort(host, "80")
		}
		target = host
	}
	_ = client.SetReadDeadline(time.Time{})

	up, err := net.DialTimeout("tcp", s.proxyAddr, 10*time.Second)
	if err != nil {
		s.logf("shim: dial proxy %s: %v", s.proxyAddr, err)
		return
	}
	defer up.Close()
	if _, err := fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return
	}
	pr := bufio.NewReader(up)
	status, err := pr.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200") {
		s.logf("shim: proxy CONNECT to %s failed: %q", target, strings.TrimSpace(status))
		return
	}
	for { // drain the rest of the CONNECT response headers
		line, lerr := pr.ReadString('\n')
		if lerr != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	// Relay. br/pr are buffered readers so the peeked ClientHello and any proxy
	// bytes already read are included.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, pr); done <- struct{}{} }()
	<-done
}

// peekSNI reads (without consuming) the TLS ClientHello buffered in br and returns
// the server_name. The bytes remain in br so the handshake can be replayed to the
// upstream MITM proxy unchanged.
func peekSNI(br *bufio.Reader) (string, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return "", err
	}
	if hdr[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake record")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 42 || recLen > 16384 {
		return "", fmt.Errorf("implausible record length %d", recLen)
	}
	buf, err := br.Peek(5 + recLen)
	if err != nil {
		return "", err
	}
	return parseSNI(buf[5 : 5+recLen])
}

// parseSNI extracts the SNI host from a ClientHello handshake body.
func parseSNI(b []byte) (string, error) {
	// handshake: type(1) len(3) version(2) random(32) then variable fields.
	if len(b) < 38 || b[0] != 0x01 {
		return "", fmt.Errorf("not a ClientHello")
	}
	p := 38
	read1 := func() (int, bool) {
		if p >= len(b) {
			return 0, false
		}
		v := int(b[p])
		p++
		return v, true
	}
	read2 := func() (int, bool) {
		if p+1 >= len(b) {
			return 0, false
		}
		v := int(b[p])<<8 | int(b[p+1])
		p += 2
		return v, true
	}
	// session_id
	n, ok := read1()
	if !ok {
		return "", io.ErrUnexpectedEOF
	}
	p += n
	// cipher_suites
	n, ok = read2()
	if !ok {
		return "", io.ErrUnexpectedEOF
	}
	p += n
	// compression_methods
	n, ok = read1()
	if !ok {
		return "", io.ErrUnexpectedEOF
	}
	p += n
	// extensions
	if _, ok = read2(); !ok {
		return "", io.ErrUnexpectedEOF
	}
	for p+4 <= len(b) {
		etype := int(b[p])<<8 | int(b[p+1])
		elen := int(b[p+2])<<8 | int(b[p+3])
		p += 4
		if p+elen > len(b) {
			break
		}
		if etype == 0x0000 { // server_name
			ext := b[p : p+elen]
			// server_name_list(2) then name_type(1) name_len(2) name
			if len(ext) < 5 || ext[2] != 0x00 {
				return "", fmt.Errorf("malformed SNI extension")
			}
			nameLen := int(ext[3])<<8 | int(ext[4])
			if 5+nameLen > len(ext) {
				return "", fmt.Errorf("malformed SNI name")
			}
			return string(ext[5 : 5+nameLen]), nil
		}
		p += elen
	}
	return "", fmt.Errorf("no SNI extension")
}

// peekHTTPHost reads (without consuming) an HTTP/1.x request head buffered in br
// and returns the Host header value.
func peekHTTPHost(br *bufio.Reader) (string, error) {
	// Peek a growing window until the header terminator or a sane cap.
	for _, n := range []int{512, 2048, 8192} {
		buf, err := br.Peek(n)
		if len(buf) == 0 {
			return "", err
		}
		s := string(buf)
		end := strings.Index(s, "\r\n\r\n")
		if end < 0 && err == nil && len(buf) == n {
			continue // need more
		}
		head := s
		if end >= 0 {
			head = s[:end]
		}
		for _, line := range strings.Split(head, "\r\n") {
			if len(line) > 5 && strings.EqualFold(line[:5], "host:") {
				return strings.TrimSpace(line[5:]), nil
			}
		}
		return "", fmt.Errorf("no Host header")
	}
	return "", fmt.Errorf("no Host header within cap")
}
