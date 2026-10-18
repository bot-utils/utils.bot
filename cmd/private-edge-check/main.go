// private-edge-check is a temporary validation-image entrypoint. It makes only
// fixed, harmless requests to our private service from Fargate's independent
// network, then execs the unchanged production supervisor. It is not copied
// into the production runtime image.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

type check struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	Status     int    `json:"status"`
	CloudFront bool   `json:"cloudfront"`
	Expected   bool   `json:"expected"`
	Failure    string `json:"failure,omitempty"`
}

func main() {
	server := flag.Bool("run-server", false, "exec production supervisor after successful private-access checks")
	flag.Parse()
	networkTargets, valid := privateNetworkTargets(os.Getenv("RESOURCE_URL"))
	if !valid {
		os.Exit(1)
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	checks := []check{}
	success := true
	for _, tc := range []struct{ url, method string }{{"https://utils.bot/", "GET"}, {"https://utils.bot/health", "GET"}, {"https://utils.bot/v1/pdf/text", "POST"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, tc.method, tc.url, nil)
		req.Header.Set("Content-Type", "application/pdf")
		response, err := client.Do(req)
		c := check{URL: tc.url, Method: tc.method}
		if err != nil {
			c.Failure = "transport_error"
		} else {
			data, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
			_ = response.Body.Close()
			c.Status = response.StatusCode
			c.CloudFront = response.Header.Get("X-Amz-Cf-Id") != ""
			c.Expected = c.Status == 403 && c.CloudFront && strings.Contains(string(data), "not_public")
		}
		cancel()
		success = success && c.Expected
		checks = append(checks, c)
	}
	for _, target := range networkTargets {
		// Resolve first so a failed DNS lookup is not mistaken for a firewall block.
		parsed, _ := url.Parse(target)
		dnsCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, dnsErr := net.DefaultResolver.LookupHost(dnsCtx, parsed.Hostname())
		cancel()
		origin := check{URL: target, Method: "GET"}
		if dnsErr == nil && len(ips) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			req, _ := http.NewRequestWithContext(ctx, "GET", origin.URL, nil)
			response, err := client.Do(req)
			if response != nil {
				origin.Status = response.StatusCode
				_ = response.Body.Close()
			}
			if err != nil {
				if n, ok := err.(net.Error); ok && n.Timeout() {
					origin.Expected = true
					origin.Failure = "network_timeout_after_successful_dns"
				}
			}
			cancel()
		}
		success = success && origin.Expected
		checks = append(checks, origin)
	}
	report, _ := json.Marshal(map[string]any{"event": "private_edge_check", "independentVantage": "AWS Fargate us-east-2", "checks": checks, "passed": success})
	fmt.Println(string(report))
	if !success {
		os.Exit(1)
	}
	if *server {
		if err := syscall.Exec("/app/server", []string{"server"}, os.Environ()); err != nil {
			os.Exit(1)
		}
	}
}

func privateNetworkTargets(resource string) ([]string, bool) {
	switch resource {
	case "https://utils.bot/v1/pdf/text":
		return []string{"https://origin.utils.bot/health"}, true
	case "https://api.utils.bot/v1/pdf/text":
		return []string{"https://origin.utils.bot:8443/health", "https://api.utils.bot/v1/pdf/text"}, true
	default:
		return nil, false
	}
}
