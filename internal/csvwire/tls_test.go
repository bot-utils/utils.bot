package csvwire

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func identities(t *testing.T) ([]byte, *tls.Config) { return identitiesVersion(t, 0) }
func identitiesVersion(t *testing.T, version int) ([]byte, *tls.Config) {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-job"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	makeCert := func(client bool) ([]byte, []byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		c := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: []string{"csv-worker"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if client {
			c.SerialNumber = big.NewInt(3)
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		v, e := x509.CreateCertificate(rand.Reader, c, ca, &k.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		key, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}), v
	}
	server, key, serverDER := makeCert(false)
	client, ck, clientDER := makeCert(true)
	raw, _ := json.Marshal(Bootstrap{Version: version, Certificate: string(server), PrivateKey: string(key), ClientCA: string(caPEM), PeerSHA256: hash(clientDER)})
	if len(raw) > 4096 {
		t.Fatal("SSM standard parameter bound")
	}
	clientConfig, e := ClientTLS(Bootstrap{Version: version, Certificate: string(client), PrivateKey: string(ck), ClientCA: string(caPEM), PeerSHA256: hash(serverDER)}, now)
	if e != nil {
		t.Fatal(e)
	}
	return raw, clientConfig
}
func TestOneJobMTLSFramedSession(t *testing.T) {
	raw, client := identities(t)
	cfg, e := ServerTLS(raw, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	in, writer := io.Pipe()
	reader, out := io.Pipe()
	defer in.Close()
	defer writer.Close()
	defer reader.Close()
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	worker := make(chan error, 1)
	go func() { _, _ = out.Write([]byte("RDY1")); e := Process(in, out); out.Close(); worker <- e }()
	server := make(chan error, 1)
	go func() { server <- ServeOne(ctx, ln, cfg, writer, reader) }()
	conn, e := net.Dial("tcp4", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	q, inputs := fixture(t, "transform", `{"column":"v","op":"upper"}`, map[string]string{"file": "id,v\n1,hello\n"})
	var sink bytes.Buffer
	m, e := Exchange(ctx, tls.Client(conn, client), q, inputs, &sink)
	if e != nil || m.LogicalSHA256 != hash([]byte("id,v\n1,HELLO\n")) {
		t.Fatal("mTLS framing", e)
	}
	if e = <-server; e != nil {
		t.Fatal(e)
	}
	if e = <-worker; e != nil {
		t.Fatal(e)
	}
}
func TestWrongJobCertificateIsRejectedBeforeInput(t *testing.T) {
	raw, _ := identities(t)
	_, wrong := identities(t)
	cfg, _ := ServerTLS(raw, time.Now())
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln.Close()
	in, writer := io.Pipe()
	reader, out := io.Pipe()
	defer in.Close()
	defer writer.Close()
	defer reader.Close()
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeOne(ctx, ln, cfg, writer, reader) }()
	conn, e := net.Dial("tcp4", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	c := tls.Client(conn, wrong)
	defer c.Close()
	if e = c.HandshakeContext(ctx); e == nil {
		t.Fatal("other job trusted")
	}
	if e = <-done; e == nil {
		t.Fatal("wrong peer accepted")
	}
}

func TestOneJobStreamingMTLSSession(t *testing.T) {
	raw, client := identitiesVersion(t, 2)
	cfg, e := ServerTLS(raw, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	in, writer := io.Pipe()
	reader, out := io.Pipe()
	defer in.Close()
	defer writer.Close()
	defer reader.Close()
	defer out.Close()
	spool, e := os.CreateTemp(t.TempDir(), "spool")
	if e != nil {
		t.Fatal(e)
	}
	defer spool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	worker, server := make(chan error, 1), make(chan error, 1)
	go func() { _, _ = out.Write([]byte("RDY2")); e := ProcessStream(in, out, spool); out.Close(); worker <- e }()
	go func() { server <- ServeOne(ctx, ln, cfg, writer, reader) }()
	conn, e := net.Dial("tcp4", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	q, inputs := fixture(t, "transform", `{"column":"v","op":"upper"}`, map[string]string{"file": "id,v\n1,hello\n"})
	q.Version = 2
	var sink bytes.Buffer
	m, e := Exchange(ctx, tls.Client(conn, client), q, inputs, &sink)
	if e != nil || m.Version != 2 || m.LogicalSHA256 != hash([]byte("id,v\n1,HELLO\n")) || VerifyStreamResult(m, bytes.NewReader(sink.Bytes())) != nil {
		t.Fatal("streaming mTLS", e)
	}
	if e = <-server; e != nil {
		t.Fatal(e)
	}
	if e = <-worker; e != nil {
		t.Fatal(e)
	}
}
