package certsync

import (
	"crypto/tls"
	"io"
	"testing"
)

func TestMutualTLS(t *testing.T) {
	t.Parallel()

	certPem, keyPem, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate certs: %v", err)
	}

	serverConfig, err := GetServerTLSConfig(certPem, keyPem)
	if err != nil {
		t.Fatalf("failed to get server tls config: %v", err)
	}

	clientConfig, err := GetClientTLSConfig(certPem, keyPem)
	if err != nil {
		t.Fatalf("failed to get client tls config: %v", err)
	}

	lis, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("failed to start tls listener: %v", err)
	}
	defer lis.Close()

	go func() {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err == nil {
			_, _ = conn.Write(append(buf, []byte("-reply")...))
		}
	}()

	conn, err := tls.Dial("tcp", lis.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("failed to connect client: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("failed to send bytes: %v", err)
	}

	reply := make([]byte, 11)
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("failed to read reply: %v", err)
	}

	if string(reply) != "hello-reply" {
		t.Errorf("expected reply hello-reply, got %s", string(reply))
	}
}
