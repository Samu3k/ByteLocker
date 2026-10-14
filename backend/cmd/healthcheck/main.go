// Command healthcheck probes only the internal loopback readiness endpoint.
package main

import (
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	client := &http.Client{
		Timeout:       3 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Get("http://127.0.0.1:8081/healthz")
	if err != nil {
		os.Exit(1)
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if err != nil || response.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
