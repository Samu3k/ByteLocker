package mailer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
)

const testAppPassword = "abcdefghijklmnop" // Public fixture, not a real credential.

type capturedMail struct{ authentication, from, to, data string }

func simulatedGmail(t *testing.T, mode string) (*Gmail, <-chan capturedMail) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Simulated SMTP test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: gmailHost}, DNSNames: []string{gmailHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if mode == "wrong-host" {
		template.DNSNames = []string{"other.example.com"}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	// Exercise real TLS and SMTP over an in-memory connection, so antivirus
	// interception of local TCP cannot substitute this fixture's certificate.
	clientPipe, serverPipe := net.Pipe()
	t.Cleanup(func() { clientPipe.Close(); serverPipe.Close() })
	result := make(chan capturedMail, 1)
	go func() {
		var captured capturedMail
		defer func() { result <- captured }()
		connection := tls.Server(serverPipe, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
		defer serverPipe.Close()
		connection.SetDeadline(time.Now().Add(3 * time.Second))
		if err := connection.Handshake(); err != nil {
			return
		}
		if mode == "hang" {
			io.Copy(io.Discard, connection)
			return
		}
		fmt.Fprint(connection, "220 simulated Gmail\r\n")
		reader := bufio.NewReader(connection)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			switch {
			case strings.HasPrefix(line, "EHLO "):
				if mode == "no-auth" {
					fmt.Fprint(connection, "250 simulated Gmail\r\n")
				} else {
					fmt.Fprint(connection, "250-simulated Gmail\r\n250 AUTH PLAIN\r\n")
				}
			case strings.HasPrefix(line, "AUTH PLAIN "):
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
				if err != nil {
					return
				}
				captured.authentication = string(decoded)
				if mode == "reject-auth" {
					fmt.Fprint(connection, "535 private SMTP diagnostic\r\n")
				} else {
					fmt.Fprint(connection, "235 authenticated\r\n")
				}
			case strings.HasPrefix(line, "MAIL FROM:"):
				captured.from = line
				fmt.Fprint(connection, "250 sender accepted\r\n")
			case strings.HasPrefix(line, "RCPT TO:"):
				captured.to = line
				if mode == "reject-recipient" {
					fmt.Fprint(connection, "550 private recipient diagnostic\r\n")
				} else {
					fmt.Fprint(connection, "250 recipient accepted\r\n")
				}
			case line == "DATA":
				fmt.Fprint(connection, "354 send message\r\n")
				data, err := io.ReadAll(textproto.NewReader(reader).DotReader())
				if err != nil {
					return
				}
				captured.data = string(data)
				if mode == "reject-data" {
					fmt.Fprint(connection, "451 private delivery diagnostic\r\n")
				} else {
					fmt.Fprint(connection, "250 accepted\r\n")
				}
				if mode == "drop-after-acceptance" {
					return
				}
			case line == "QUIT":
				fmt.Fprint(connection, "221 goodbye\r\n")
				return
			default:
				fmt.Fprint(connection, "500 unsupported command\r\n")
			}
		}
	}()
	g, err := NewGmail("sender@example.com", testAppPassword)
	if err != nil {
		t.Fatal(err)
	}
	// Test-only private injection. Production always uses system trust roots
	// and smtp.gmail.com:465; the public constructor exposes no override.
	g.connect = func(ctx context.Context) (net.Conn, error) {
		pool := roots
		if mode == "untrusted" {
			pool = x509.NewCertPool()
		}
		connection := tls.Client(clientPipe, &tls.Config{ServerName: gmailHost, RootCAs: pool, MinVersion: tls.VersionTLS12})
		if err := connection.HandshakeContext(ctx); err != nil {
			clientPipe.Close()
			return nil, err
		}
		return connection, nil
	}
	return g, result
}

func emailFixture(t *testing.T) (protocol.Email, auth.EmailCode) {
	t.Helper()
	to, err := protocol.ParseEmail("recipient@example.com")
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.ParseEmailCode("00001234")
	if err != nil {
		t.Fatal(err)
	}
	return to, code
}

func TestGmailDelivery(t *testing.T) {
	for _, mode := range []string{"success", "drop-after-acceptance"} {
		t.Run(mode, func(t *testing.T) {
			g, result := simulatedGmail(t, mode)
			to, code := emailFixture(t)
			if err := g.SendVerification(context.Background(), to, code, time.Now().Add(10*time.Minute)); err != nil {
				captured := <-result
				t.Fatalf("%v (auth=%t, sender=%t, recipient=%t, data=%t)", err, captured.authentication != "", captured.from != "", captured.to != "", captured.data != "")
			}
			captured := <-result
			if captured.authentication != "\x00sender@example.com\x00"+testAppPassword || captured.from != "MAIL FROM:<sender@example.com>" || captured.to != "RCPT TO:<recipient@example.com>" {
				t.Fatal("SMTP envelope/authentication differs")
			}
			message, err := mail.ReadMessage(strings.NewReader(captured.data))
			if err != nil {
				t.Fatal(err)
			}
			if message.Header.Get("Content-Transfer-Encoding") != "base64" || message.Header.Get("Message-ID") == "" {
				t.Fatal("invalid mail headers")
			}
			body, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, message.Body))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(body, []byte("00001234")) || bytes.Contains(body, []byte(testAppPassword)) {
				t.Fatal("wrong message content")
			}
		})
	}
}

func TestGmailFailures(t *testing.T) {
	for _, mode := range []string{"reject-auth", "reject-recipient", "reject-data", "untrusted", "wrong-host", "no-auth"} {
		t.Run(mode, func(t *testing.T) {
			g, result := simulatedGmail(t, mode)
			to, code := emailFixture(t)
			err := g.SendVerification(context.Background(), to, code, time.Now().Add(time.Minute))
			if !errors.Is(err, ErrDeliveryUnavailable) || strings.Contains(err.Error(), "private") {
				t.Fatal("failure not protected")
			}
			captured := <-result
			if (mode == "untrusted" || mode == "wrong-host" || mode == "no-auth") && captured.authentication != "" {
				t.Fatal("credential sent to untrusted server")
			}
		})
	}
	g, result := simulatedGmail(t, "hang")
	to, code := emailFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := g.SendVerification(ctx, to, code, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("hanging SMTP succeeded")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation did not interrupt SMTP")
	}
	<-result
}

func TestGmailConfigurationAndRedaction(t *testing.T) {
	g, err := NewGmail("sender@example.com", "abcd efgh ijkl mnop\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%#v", "%s", "%x"} {
		if fmt.Sprintf(format, g) != "[REDACTED]" {
			t.Fatal("configuration leaked")
		}
	}
	encoded, err := json.Marshal(g)
	if err != nil || string(encoded) != `"[REDACTED]"` {
		t.Fatal("JSON leaked configuration")
	}
	for _, input := range []struct{ user, password string }{{"bad", testAppPassword}, {"sender@example.com", ""}, {"sender@example.com", "abcdefghijklmn\top"}, {"sender@example.com", strings.Repeat("x", 17)}} {
		if _, err := NewGmail(input.user, input.password); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("invalid configuration accepted")
		}
	}
	passwordPath := filepath.Join(t.TempDir(), "smtp-secret")
	if err := os.WriteFile(passwordPath, []byte(testAppPassword), 0600); err != nil {
		t.Fatal(err)
	}
	lookup := func(name string) string {
		if name == "PM_SMTP_USERNAME" {
			return "sender@example.com"
		}
		if name == "PM_SMTP_APP_PASSWORD_FILE" {
			return passwordPath
		}
		return ""
	}
	if _, err := GmailFromEnvironment(lookup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwordPath, bytes.Repeat([]byte("x"), 257), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := GmailFromEnvironment(lookup); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("oversized credential file accepted")
	}
	if _, err := GmailFromEnvironment(nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("missing configuration accepted")
	}
	to, code := emailFixture(t)
	g.connect = func(context.Context) (net.Conn, error) { t.Fatal("invalid input reached network"); return nil, nil }
	for _, input := range []struct {
		to      protocol.Email
		code    auth.EmailCode
		expires time.Time
	}{{protocol.Email{}, code, time.Now().Add(time.Minute)}, {to, auth.EmailCode{}, time.Now().Add(time.Minute)}, {to, code, time.Now().Add(-time.Second)}} {
		if err := g.SendVerification(context.Background(), input.to, input.code, input.expires); !errors.Is(err, ErrInvalidMessage) {
			t.Fatal("invalid message accepted")
		}
	}
}
