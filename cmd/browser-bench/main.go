// Local, synthetic-only benchmark. It never submits payment or fetches a URL.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"pdfservice/internal/browser"
	"pdfservice/internal/htmlrender"
	"strings"
	"syscall"
	"time"
)

func main() {
	probe := flag.Bool("socket-probe", false, "test the native launcher socket boundary")
	count := flag.Int("n", 10, "fresh browser jobs per fixture")
	flag.Parse()
	if *probe {
		for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
			fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
			if err != syscall.EPERM {
				if fd >= 0 {
					syscall.Close(fd)
				}
				fmt.Fprintln(os.Stderr, "Internet socket boundary failed")
				os.Exit(1)
			}
		}
		fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			os.Exit(1)
		}
		syscall.Close(fd)
		fmt.Println("IPv4 and IPv6 sockets denied; Unix sockets available")
		return
	}
	fixtures := []struct{ name, html, want string }{
		{"inline", "<!doctype html><title>JavaScript</title><body><div id='result'>waiting</div><script>document.getElementById('result').innerHTML='<h1>Rendered with JavaScript</h1><p>dynamic body</p>'</script>", "Rendered with JavaScript"},
		{"external-and-fetch", "<!doctype html><title>External JS</title><script src='/app.js'></script><body><main id='result'>waiting</main>", "fetched data"},
		{"large-dom", "<!doctype html><title>Large DOM</title><body><main id='result'></main><script>for(let i=0;i<10000;i++){let p=document.createElement('p');p.textContent='Rendered row '+i;document.getElementById('result').appendChild(p)}</script>", "Rendered row 9999"},
	}
	for _, f := range fixtures {
		for i := 0; i < *count; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			dir, err := os.MkdirTemp("", "browser-bench-")
			if err != nil {
				panic("profile creation failed")
			}
			begin := time.Now()
			s, err := browser.Start(ctx, "/opt/utils/browser-launch", "/usr/lib/chromium/chromium-headless-shell", dir)
			startup := time.Since(begin)
			if err != nil {
				fmt.Fprintln(os.Stderr, "sandboxed browser could not start")
				os.Exit(1)
			}
			result, err := browser.Render(ctx, s, "https://fixture.example/", func(ctx context.Context, r browser.Request) (browser.Response, error) {
				body, typ := f.html, "text/html; charset=utf-8"
				switch r.URL {
				case "https://fixture.example/":
				case "https://fixture.example/app.js":
					body = `window.addEventListener('DOMContentLoaded',()=>fetch('/data.json').then(r=>r.json()).then(d=>{document.getElementById('result').textContent=d.message}))`
					typ = "text/javascript"
				case "https://fixture.example/data.json":
					body = `{"message":"fetched data"}`
					typ = "application/json"
				default:
					return browser.Response{}, fmt.Errorf("unexpected synthetic request")
				}
				return browser.Response{Status: 200, Headers: map[string]string{"Content-Type": typ}, Body: []byte(body)}, nil
			})
			if err != nil || !strings.Contains(result.HTML, f.want) {
				fmt.Fprintln(os.Stderr, "render fixture failed:", f.name, err)
				s.Close()
				cancel()
				os.Exit(1)
			}
			markdown, _, partial, err := htmlrender.Convert(ctx, []byte(result.HTML), nil)
			if err != nil {
				panic("conversion failed")
			}
			elapsed := time.Since(begin)
			s.Close()
			cancel()
			os.RemoveAll(dir)
			json.NewEncoder(os.Stdout).Encode(map[string]any{"fixture": f.name, "sample": i + 1, "startup_ms": float64(startup.Microseconds()) / 1000, "render_ms": result.RenderMS, "total_ms": float64(elapsed.Microseconds()) / 1000, "dom_bytes": len(result.HTML), "markdown_bytes": len(markdown), "partial": partial})
		}
	}
}
