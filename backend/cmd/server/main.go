package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/emailworker"
	"passwordmanager/internal/httpapi"
	"passwordmanager/internal/mailer"
	"passwordmanager/internal/operationalkeys"
	"passwordmanager/internal/storage"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	return runWithEnvironment(ctx, args, output, os.Getenv)
}

func runWithEnvironment(ctx context.Context, args []string, output io.Writer, lookup func(string) string) error {
	output = &lockedWriter{writer: output}
	flags := flag.NewFlagSet("passwordmanager", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("data-dir", "./data", "Persistent local data directory")
	secretsDirectory := flags.String("secrets-dir", "", "Protected keys directory; defaults to data-dir/secrets")
	apiAddress := flags.String("api-address", "127.0.0.1:8080", "API listener")
	healthAddress := flags.String("health-address", "127.0.0.1:8081", "Internal loopback health listener")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(output, "Usage: go run ./cmd/server [-data-dir ./data] [-secrets-dir path] [-api-address 127.0.0.1:8080] [-health-address 127.0.0.1:8081]")
			return nil
		}
		return errors.New("server: invalid command arguments")
	}
	if flags.NArg() != 0 || !validAddress(*apiAddress, false) || !validAddress(*healthAddress, true) {
		return errors.New("server: invalid listener configuration")
	}
	store, err := storage.Open(ctx, *directory)
	if err != nil {
		return err
	}
	defer store.Close()
	if *secretsDirectory == "" {
		*secretsDirectory = filepath.Join(*directory, "secrets")
	}
	bound, err := store.HasOperationalKeys(ctx)
	if err != nil {
		return err
	}
	keys, err := operationalkeys.LoadOrCreate(ctx, *secretsDirectory, store.Instance().ServerID, !bound)
	if err != nil {
		return err
	}
	if err := store.BindOperationalKeys(ctx, keys.Fingerprint()); err != nil {
		return err
	}
	queue, err := storage.NewEmailQueue(store, keys.EmailMAC(), keys.EmailEncryption(), keys.EmailQuota())
	if err != nil {
		return err
	}
	var sender *mailer.Gmail
	if lookup != nil && (lookup("PM_SMTP_USERNAME") != "" || lookup("PM_SMTP_APP_PASSWORD_FILE") != "") {
		sender, err = mailer.GmailFromEnvironment(lookup)
		if err != nil {
			return errors.New("server: invalid email configuration")
		}
	}
	var registrationAPI []*storage.Registrations
	engine := auth.NewEngine()
	sessions, err := storage.NewSessions(store, engine, keys.Prelogin(), keys.EmailQuota())
	if err != nil {
		return errors.New("server: invalid authentication configuration")
	}
	if sender != nil {
		registrations, err := storage.NewRegistrations(store, queue, engine)
		if err != nil {
			return errors.New("server: invalid registration configuration")
		}
		registrationAPI = append(registrationAPI, registrations)
	}
	api, err := httpapi.New(store.Instance().ServerID, store.Ping, registrationAPI...)
	if err != nil {
		return errors.New("server: invalid API configuration")
	}
	if err := api.EnableAuthentication(sessions); err != nil {
		return errors.New("server: invalid authentication configuration")
	}
	if err := api.EnableAdminPanel(store); err != nil {
		return err
	}
	listen := net.ListenConfig{}
	public, err := listen.Listen(ctx, "tcp", *apiAddress)
	if err != nil {
		return errors.New("server: API listener unavailable")
	}
	defer public.Close()
	internal, err := listen.Listen(ctx, "tcp", *healthAddress)
	if err != nil {
		return errors.New("server: health listener unavailable")
	}
	defer internal.Close()
	servers := []*http.Server{newHTTPServer(api.PublicHandler()), newHTTPServer(api.InternalHandler())}
	failures := make(chan error, 2)
	go func() { failures <- servers[0].Serve(public) }()
	go func() { failures <- servers[1].Serve(internal) }()
	fmt.Fprintf(output, "Development server running. API: http://%s/api/v1/config\nInternal health: http://%s/healthz\nLogin, sessions and encrypted vault API enabled. Client applications are not yet available.\n", public.Addr(), internal.Addr())
	workerCtx, stopWorker := context.WithCancel(ctx)
	defer stopWorker()
	workerDone := make(chan error, 1)
	if sender != nil {
		fmt.Fprintln(output, "Email dispatcher enabled. Registration API enabled; Gmail credentials are checked on delivery.")
		go func() {
			workerDone <- emailworker.Run(workerCtx, queue, sender, func() {
				fmt.Fprintln(output, "Email dispatcher encountered an error; pending delivery remains bounded by queue policy.")
			})
		}()
	} else {
		fmt.Fprintln(output, "Email dispatcher disabled: Gmail is not configured.")
		workerDone <- nil
	}
	var serveError error
	select {
	case <-ctx.Done():
	case serveError = <-failures:
	}
	stopWorker()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
		}
	}
	select {
	case err := <-workerDone:
		if err != nil {
			return errors.New("server: email dispatcher stopped unexpectedly")
		}
	case <-time.After(6 * time.Second):
		return errors.New("server: email dispatcher shutdown timed out")
	}
	if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
		return errors.New("server: HTTP service stopped unexpectedly")
	}
	return nil
}

type lockedWriter struct {
	sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(data []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	return w.writer.Write(data)
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}

func validAddress(address string, loopbackOnly bool) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && (!loopbackOnly || ip.IsLoopback())
}
