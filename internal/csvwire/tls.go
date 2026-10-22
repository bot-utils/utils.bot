package csvwire

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"pdfservice/internal/jsonwire"
	"time"
)

// Bootstrap is an ephemeral per-run transport identity, not an AWS credential.
// It may enter only the transport container through one approved Secrets ref.
type Bootstrap struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	ClientCA    string `json:"client_ca"`
	PeerSHA256  string `json:"peer_sha256"`
}

func (Bootstrap) String() string   { return "CSV transport identity [redacted]" }
func (Bootstrap) GoString() string { return "CSV transport identity [redacted]" }
func ServerTLS(raw []byte, now time.Time) (*tls.Config, error) {
	var b Bootstrap
	if jsonwire.Decode(raw, &b, 4096) != nil || !digest(b.PeerSHA256) {
		return nil, ErrWire
	}
	cert, e := tls.X509KeyPair([]byte(b.Certificate), []byte(b.PrivateKey))
	if e != nil || len(cert.Certificate) != 1 {
		return nil, ErrWire
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil || !now.Before(leaf.NotAfter) || leaf.NotAfter.After(now.Add(20*time.Minute)) || now.Before(leaf.NotBefore) {
		return nil, ErrWire
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(b.ClientCA)) {
		return nil, ErrWire
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{Protocol}, SessionTicketsDisabled: true, VerifyConnection: func(s tls.ConnectionState) error {
		if s.NegotiatedProtocol != Protocol || len(s.PeerCertificates) != 1 {
			return ErrWire
		}
		h := sha256.Sum256(s.PeerCertificates[0].Raw)
		if hex.EncodeToString(h[:]) != b.PeerSHA256 {
			return ErrWire
		}
		return nil
	}}, nil
}

// ServeOne handles exactly one authenticated session. No listener or peer
// address is logged; one bad/uncertain attempt consumes this worker too.
func ServeOne(ctx context.Context, ln net.Listener, config *tls.Config, input io.WriteCloser, output io.Reader) error {
	defer ln.Close()
	defer input.Close()
	if config == nil || config.ClientAuth != tls.RequireAndVerifyClientCert || config.MinVersion != tls.VersionTLS13 {
		return ErrWire
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-done:
		}
	}()
	conn, e := ln.Accept()
	if e != nil {
		return ErrWire
	}
	defer conn.Close()
	_ = ln.Close()
	c := tls.Server(conn, config)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	if e = c.HandshakeContext(ctx); e != nil {
		return ErrWire
	}
	// The parser's ready marker is produced only after all kernel restrictions.
	var ready [4]byte
	for {
		n, err := io.ReadFull(output, ready[:])
		if n == 0 && err == io.EOF {
			select {
			case <-ctx.Done():
				return ErrWorker
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		if err != nil || string(ready[:]) != "RDY1" {
			return ErrWorker
		}
		break
	}
	n, e := io.Copy(input, io.LimitReader(c, 2*MaxInput+MaxHeader+5))
	ce := input.Close()
	if e != nil || ce != nil || n > 2*MaxInput+MaxHeader+4 {
		return ErrWire
	}
	n, e = io.Copy(c, io.LimitReader(output, MaxOutput+MaxHeader+5))
	if e != nil || n > MaxOutput+MaxHeader+4 {
		return ErrWire
	}
	if e = c.CloseWrite(); e != nil {
		return ErrWire
	}
	return nil
}

// Exchange accepts an already authenticated connection created for the original
// ECS-observed private endpoint. It cannot select URLs, AWS keys or a new peer.
func Exchange(ctx context.Context, c *tls.Conn, q Request, inputs map[string]io.Reader, sink io.Writer) (Result, error) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if c.HandshakeContext(ctx) != nil || c.ConnectionState().NegotiatedProtocol != Protocol {
		return Result{}, ErrWire
	}
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	if WriteRequest(c, q, inputs) != nil || c.CloseWrite() != nil {
		return Result{}, ErrWire
	}
	return ReadResult(c, sink)
}

// ClientTLS verifies the per-job server certificate, normal CA validation and
// exact leaf pin. No server-selected origin, system roots or insecure mode.
func ClientTLS(b Bootstrap, now time.Time) (*tls.Config, error) {
	cert, e := tls.X509KeyPair([]byte(b.Certificate), []byte(b.PrivateKey))
	if e != nil || len(cert.Certificate) != 1 || !digest(b.PeerSHA256) {
		return nil, ErrWire
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.NotAfter.After(now.Add(20*time.Minute)) {
		return nil, ErrWire
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(b.ClientCA)) {
		return nil, ErrWire
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "csv-worker", Certificates: []tls.Certificate{cert}, NextProtos: []string{Protocol}, SessionTicketsDisabled: true, VerifyConnection: func(s tls.ConnectionState) error {
		if s.NegotiatedProtocol != Protocol || len(s.PeerCertificates) != 1 || len(s.VerifiedChains) == 0 {
			return ErrWire
		}
		h := sha256.Sum256(s.PeerCertificates[0].Raw)
		if hex.EncodeToString(h[:]) != b.PeerSHA256 {
			return ErrWire
		}
		return nil
	}}, nil
}
