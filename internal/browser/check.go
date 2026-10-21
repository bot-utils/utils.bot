package browser

import (
	"context"
	"os"
	"strings"
)

// Check renders only an in-memory synthetic page; it never contacts a website.
// The expected element is absent from the source and requires JavaScript.
func Check(ctx context.Context, launcher, executable string) error {
	dir, err := os.MkdirTemp("", "browser-check-")
	if err != nil {
		return ErrBrowser
	}
	defer os.RemoveAll(dir)
	s, err := Start(ctx, launcher, executable, dir)
	if err != nil {
		return err
	}
	defer s.Close()
	return CheckSession(ctx, s)
}

// CheckSession exercises synthetic JavaScript only, in a throwaway context.
func CheckSession(ctx context.Context, s *Session) error {
	rendered, err := Render(ctx, s, "https://fixture.example/", func(_ context.Context, r Request) (Response, error) {
		if r.Method != "GET" || r.URL != "https://fixture.example/" {
			return Response{}, ErrBrowser
		}
		return Response{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: []byte(`<p id="proof"></p><script>document.getElementById('proof').textContent='renderer-'+'ready'</script>`)}, nil
	})
	if err != nil || !strings.Contains(rendered.HTML, `<p id="proof">renderer-ready</p>`) {
		return ErrBrowser
	}
	return nil
}
