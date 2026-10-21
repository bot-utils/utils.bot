// Package staticsite renders the trusted website at build time. No HTTP listener,
// customer documents, credentials, or additional parser dependencies are used.
package staticsite

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"pdfservice/internal/docs"
	"pdfservice/internal/paths"
	"pdfservice/internal/protocol"
)

//go:embed request.js
var requestJS string

//go:embed response.js
var responseJS string

type Route struct {
	Key      string `json:"key,omitempty"`
	Redirect string `json:"redirect,omitempty"`
}
type Object struct {
	Key, ContentType, CacheControl string
	Body                           []byte `json:"-"`
}
type Bundle struct {
	Routes                    map[string]Route
	Objects                   []Object
	RequestCode, ResponseCode string `json:"-"`
}

func Build(resource, owner string, cfg protocol.Config) (Bundle, error) {
	return build(resource, owner, cfg, false)
}
func BuildWithHTML(resource, owner string, cfg protocol.Config) (Bundle, error) {
	return build(resource, owner, cfg, true)
}
func build(resource, owner string, cfg protocol.Config, html bool) (Bundle, error) {
	if resource != protocol.APIOrigin+"/v1/pdf/text" || net.ParseIP(owner) == nil || net.ParseIP(owner).To4() == nil || strings.Contains(owner, ":") {
		return Bundle{}, fmt.Errorf("static site requires canonical regional API and owner IPv4")
	}
	h := docs.NewWithConfig(resource, cfg)
	if html {
		h = docs.NewWithHTML(resource, cfg)
	}
	b := Bundle{Routes: map[string]Route{}}
	seen := map[string]bool{}
	render := func(path, accept, name string) error {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Accept", accept)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == 308 {
			loc := w.Header().Get("Location")
			if !strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "//") {
				return fmt.Errorf("nonlocal redirect")
			}
			b.Routes[name] = Route{Redirect: loc}
			return nil
		}
		if w.Code != 200 {
			return fmt.Errorf("unexpected static route status: %s", path)
		}
		ct := w.Header().Get("Content-Type")
		body := append([]byte(nil), w.Body.Bytes()...)
		digest := sha256.Sum256(append([]byte(ct+"\x00"), body...))
		key := "public/" + hex.EncodeToString(digest[:])
		b.Routes[name] = Route{Key: key}
		if !seen[key] {
			b.Objects = append(b.Objects, Object{Key: key, ContentType: ct, CacheControl: "public, max-age=31536000, immutable", Body: body})
			seen[key] = true
		}
		return nil
	}
	for _, path := range paths.DocumentationRoutes {
		if path == "/v1/pdf/text" {
			continue
		}
		if err := render(path, "text/html", path); err != nil {
			return Bundle{}, err
		}
	}
	for _, v := range []struct{ accept, name string }{{"application/yaml", "@yaml"}, {"application/json", "@json"}} {
		if err := render("/", v.accept, v.name); err != nil {
			return Bundle{}, err
		}
	}
	sort.Slice(b.Objects, func(i, j int) bool { return b.Objects[i].Key < b.Objects[j].Key })
	apiPaths := map[string]string{"/v1/pdf/text": resource}
	if html {
		apiPaths[protocol.HTMLPath] = protocol.APIOrigin + protocol.HTMLPath
	}
	config, _ := json.Marshal(struct {
		Public bool              `json:"public"`
		Owner  string            `json:"owner"`
		API    string            `json:"api"`
		Routes map[string]Route  `json:"routes"`
		APIs   map[string]string `json:"apis"`
	}{cfg.PublicAccess(), owner, resource, b.Routes, apiPaths})
	b.RequestCode = "var config=" + string(config) + ";\n" + requestJS
	responseConfig, _ := json.Marshal(struct {
		Public bool   `json:"public"`
		API    string `json:"api"`
	}{cfg.PublicAccess(), protocol.APIOrigin})
	b.ResponseCode = "var config=" + string(responseConfig) + ";\n" + responseJS
	if len(b.RequestCode) > 10<<10 || len(b.ResponseCode) > 10<<10 {
		return Bundle{}, fmt.Errorf("static CloudFront function exceeds size limit")
	}
	return b, nil
}
func (b Bundle) Write(directory string) error {
	if err := os.MkdirAll(filepath.Join(directory, "objects", "public"), 0700); err != nil {
		return err
	}
	for _, o := range b.Objects {
		if err := os.WriteFile(filepath.Join(directory, "objects", o.Key), o.Body, 0600); err != nil {
			return err
		}
	}
	for name, body := range map[string][]byte{"request.js": []byte(b.RequestCode), "response.js": []byte(b.ResponseCode)} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			return err
		}
	}
	manifest, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "manifest.json"), append(manifest, '\n'), 0600)
}
