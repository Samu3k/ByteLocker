// Package mailer delivers verification messages. It neither activates accounts
// nor manages code lifetimes, attempts, outbox retries or registration state.
package mailer

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
)

const gmailHost = "smtp.gmail.com"

var (
	ErrInvalidConfiguration = errors.New("mailer: invalid Gmail configuration")
	ErrInvalidMessage       = errors.New("mailer: invalid verification message")
	ErrDeliveryUnavailable  = errors.New("mailer: SMTP delivery unavailable")
)

type Gmail struct {
	username protocol.Email
	password string
	connect  func(context.Context) (net.Conn, error)
	now      func() time.Time
}

// NewGmail configures a sender without opening a connection or sending email.
// Only implicit TLS on Gmail's port 465 is used. There is no plaintext fallback
// and no option to disable certificate or hostname verification.
func NewGmail(username, appPassword string) (*Gmail, error) {
	email, err := protocol.ParseEmail(username)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	password := strings.ReplaceAll(strings.TrimSpace(appPassword), " ", "")
	if len(password) != 16 {
		return nil, ErrInvalidConfiguration
	}
	for i := range password {
		if password[i] < 33 || password[i] > 126 {
			return nil, ErrInvalidConfiguration
		}
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{ServerName: gmailHost, MinVersion: tls.VersionTLS12},
	}
	return &Gmail{username: email, password: password, now: time.Now, connect: func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", gmailHost+":465")
	}}, nil
}

// GmailFromEnvironment reads a local password file. The password itself is not
// accepted as a command argument and is never included in errors or logging.
// File permissions/ACLs must restrict access to the service account.
func GmailFromEnvironment(lookup func(string) string) (*Gmail, error) {
	if lookup == nil {
		return nil, ErrInvalidConfiguration
	}
	username := lookup("PM_SMTP_USERNAME")
	path := lookup("PM_SMTP_APP_PASSWORD_FILE")
	if path == "" {
		return nil, ErrInvalidConfiguration
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrInvalidConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(data) > 256 {
		return nil, ErrInvalidConfiguration
	}
	defer clear(data)
	return NewGmail(username, string(data))
}

// SendVerification returns success when Gmail accepts the DATA command. This
// does not promise inbox delivery. Failure after acceptance (for example QUIT)
// is not reported as an undelivered message, which could cause duplicate retries.
// The future outbox worker, not an HTTP handler, must call this method.
func (g *Gmail) SendVerification(ctx context.Context, to protocol.Email, code auth.EmailCode, expires time.Time) error {
	if g == nil {
		return ErrInvalidConfiguration
	}
	message, err := g.message(to, code, expires)
	if err != nil {
		return err
	}
	defer clear(message)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ctx, expireCancel := context.WithDeadline(ctx, expires)
	defer expireCancel()
	connection, err := g.connect(ctx)
	if err != nil {
		return deliveryError(ctx)
	}
	defer connection.Close()
	secured, ok := connection.(*tls.Conn)
	if !ok {
		return ErrDeliveryUnavailable
	}
	state := secured.ConnectionState()
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 || state.ServerName != gmailHost || state.Version < tls.VersionTLS12 {
		return ErrDeliveryUnavailable
	}
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return ErrDeliveryUnavailable
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	client, err := smtp.NewClient(connection, gmailHost)
	if err != nil {
		return deliveryError(ctx)
	}
	defer client.Close()
	if supported, mechanisms := client.Extension("AUTH"); !supported || !strings.Contains(" "+mechanisms+" ", " PLAIN ") {
		return ErrDeliveryUnavailable
	}
	if err := client.Auth(smtp.PlainAuth("", g.username.String(), g.password, gmailHost)); err != nil {
		return deliveryError(ctx)
	}
	if err := client.Mail(g.username.String()); err != nil {
		return deliveryError(ctx)
	}
	if err := client.Rcpt(to.String()); err != nil {
		return deliveryError(ctx)
	}
	if !expires.After(g.now()) {
		return ErrInvalidMessage
	}
	writer, err := client.Data()
	if err != nil {
		return deliveryError(ctx)
	}
	written, err := writer.Write(message)
	if err != nil || written != len(message) {
		return deliveryError(ctx)
	}
	if err := writer.Close(); err != nil {
		return deliveryError(ctx)
	}
	_ = client.Quit()
	return nil
}

func deliveryError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrDeliveryUnavailable
}

func (g *Gmail) message(to protocol.Email, code auth.EmailCode, expires time.Time) ([]byte, error) {
	now := g.now().UTC()
	if !to.Valid() || !expires.After(now) {
		return nil, ErrInvalidMessage
	}
	if _, err := protocol.NewTimestamp(expires); err != nil {
		return nil, ErrInvalidMessage
	}
	value, err := code.DeliveryValue()
	if err != nil {
		return nil, ErrInvalidMessage
	}
	var id [16]byte
	rand.Read(id[:])
	_, domain, _ := strings.Cut(g.username.String(), "@")
	body := fmt.Sprintf("Il codice per verificare il tuo account Password Manager e': %s\n\nScade il %s UTC.\n\nSe non hai richiesto la registrazione, ignora questo messaggio.\n", value, expires.UTC().Format("02/01/2006 15:04:05"))
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	var message strings.Builder
	fmt.Fprintf(&message, "From: Password Manager <%s>\r\nTo: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nSubject: Verifica il tuo account Password Manager\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n", g.username.String(), to.String(), now.Format(time.RFC1123Z), base64.RawURLEncoding.EncodeToString(id[:]), domain)
	for len(encoded) > 76 {
		message.WriteString(encoded[:76])
		message.WriteString("\r\n")
		encoded = encoded[76:]
	}
	message.WriteString(encoded)
	message.WriteString("\r\n")
	return []byte(message.String()), nil
}

func (g Gmail) String() string                    { return "[REDACTED]" }
func (g Gmail) GoString() string                  { return "[REDACTED]" }
func (g Gmail) Format(state fmt.State, verb rune) { _, _ = io.WriteString(state, "[REDACTED]") }
func (g Gmail) LogValue() slog.Value              { return slog.StringValue("[REDACTED]") }
func (g Gmail) MarshalJSON() ([]byte, error)      { return []byte(`"[REDACTED]"`), nil }
