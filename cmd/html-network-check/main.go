// Temporary independent-network check. Never accepts caller destinations or
// payment data, and is never included in an ordinary application deployment.
package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	lambda.Start(func(ctx context.Context) (map[string]any, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.utils.bot/v1/html/markdown", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			return map[string]any{"passed": false, "code": "transport_failure"}, nil
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		slog.Info("independent_network_check", "passed", resp.StatusCode == 404, "status", resp.StatusCode)
		return map[string]any{"passed": resp.StatusCode == 404, "status": resp.StatusCode}, nil
	})
}
