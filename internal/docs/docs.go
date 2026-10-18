package docs

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"pdfservice/internal/protocol"
	"pdfservice/internal/serviceinfo"
)

//go:embed openapi.json assets/* templates/*.html
var files embed.FS

var pages = template.Must(template.ParseFS(files, "templates/*.html"))

type tool struct {
	Name, Summary, Route, Method, DocsURL string
}

type pageData struct {
	Tools                                         []tool
	Title, Description, Canonical, Base, Resource string
	Structured                                    template.JS
	Swagger                                       bool
	AgentMessage                                  string
	Repository, Transparency                      string
	Pitch, Robots                                 string
	PriceNote                                     string
	Public                                        bool
	PaymentStatus, PaymentDetails, Availability   string
}

// New renders only trusted, embedded content. Neither request headers nor query
// parameters can configure templates, URLs, scripts or the OpenAPI document.
func New(resource string) http.Handler { return NewWithConfig(resource, protocol.Config{}) }
func NewWithConfig(resource string, cfg protocol.Config) http.Handler {
	base := protocol.WebsiteBase(resource)
	apiBase := strings.TrimSuffix(resource, "/v1/pdf/text")
	spec := baseSpec(cfg)
	spec["servers"] = []map[string]string{{"url": apiBase, "description": endpointDescription(cfg)}}
	if apiBase != base {
		configureRegionalSpec(spec)
		for path, raw := range spec["paths"].(map[string]any) {
			if path != "/v1/pdf/text" {
				raw.(map[string]any)["servers"] = []map[string]string{{"url": base}}
			}
		}
	}
	spec["x-x402"] = map[string]any{"version": 2, "mode": cfg.Mode(), "requirements": cfg.Requirements(), "pricing": []map[string]any{
		{"minBytes": 1, "maxBytes": protocol.SmallPDFLimit, "requirements": cfg.ForSize(0).Requirements()},
		{"minBytes": protocol.SmallPDFLimit + 1, "maxBytes": protocol.MaxPDF, "requirements": cfg.ForSize(protocol.MaxPDF).Requirements()},
	}}
	spec["info"].(map[string]any)["termsOfService"] = base + "/terms"
	spec["externalDocs"] = map[string]string{"url": base + "/docs", "description": "Interactive API reference"}
	specJSON, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		panic(err)
	}
	specYAML, err := jsonYAML(specJSON)
	if err != nil {
		panic(err)
	}
	about := serviceinfo.Details()
	readmeMarkdown := []byte(serviceinfo.Markdown())
	metadata := "API tools for AI agents. Offload compute, save tokens and pay per use. Source-visible code for transparency, starting with PDF text extraction."
	structured, err := json.Marshal(map[string]any{
		"@context": "https://schema.org",
		"@graph": []any{
			map[string]any{"@type": "WebSite", "@id": base + "/#website", "url": base + "/", "name": "utils.bot", "description": metadata, "sameAs": []string{serviceinfo.RepositoryURL}},
			map[string]any{"@type": "WebPage", "@id": base + "/#webpage", "url": base + "/", "name": "AI agent tools and PDF text extraction | utils.bot", "description": metadata, "isPartOf": map[string]string{"@id": base + "/#website"}},
		},
	})
	if err != nil {
		panic(err)
	}
	status, details, availability := paymentCopy(cfg)
	priceNote := ""
	if cfg.Mode() == protocol.ModeBase {
		priceNote = "PDF pricing: " + protocol.PricingDescription + ". Successful partial or blank results are charged the full fee; parsing failures are not charged."
	}
	data := pageData{Repository: serviceinfo.RepositoryURL, Transparency: about.Transparency, PriceNote: priceNote, Public: cfg.PublicAccess(), Pitch: about.Summary, Robots: robotsDirective(cfg), AgentMessage: about.Message, PaymentStatus: status, PaymentDetails: details, Availability: availability, Title: "AI agent tools and PDF text extraction | utils.bot", Description: metadata, Canonical: base + "/", Base: base, Resource: resource, Tools: toolsFromSpec(spec), Structured: template.JS(structured)}
	render := func(name string, data pageData) []byte {
		var out bytes.Buffer
		if err := pages.ExecuteTemplate(&out, name, data); err != nil {
			panic(err)
		}
		return out.Bytes()
	}
	home := render("home", data)
	data.AgentMessage = ""
	data.Title, data.Description, data.Canonical, data.Structured, data.Swagger = "API reference | utils.bot", "Interactive API reference for the utils.bot PDF text extraction API. Inspect request and response schemas, x402 payment headers, limits and error codes.", base+"/docs", "", true
	swagger := render("swagger", data)
	data.Title, data.Description, data.Canonical, data.Swagger = "Terms, privacy and information | utils.bot", "Terms, privacy, payments, document limits, retries and copyright for the utils.bot API.", base+"/info", false
	information := []byte(informationMarkdown(spec))
	terms := []byte(termsMarkdown(spec))
	discovery := discoveryForAPI(base, apiBase, cfg)
	// Keep the multi-MiB Swagger assets shared across requests.
	assets := make(map[string][]byte)
	entries, err := files.ReadDir("assets")
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		asset, err := files.ReadFile("assets/" + entry.Name())
		if err != nil {
			panic(err)
		}
		assets["/assets/"+entry.Name()] = asset
	}
	assets["/assets/site-v3.css"] = assets["/assets/site.css"]
	assets["/assets/site-v4.css"] = assets["/assets/site.css"]
	assets["/assets/site-v5.css"] = assets["/assets/site.css"]
	assets["/assets/initializer-v3.js"] = assets["/assets/initializer.js"]
	assets["/assets/initializer-v4.js"] = assets["/assets/initializer.js"]
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'")
		if apiBase == protocol.APIOrigin {
			w.Header().Set("Content-Security-Policy", strings.Replace(w.Header().Get("Content-Security-Policy"), "connect-src 'self'", "connect-src 'self' "+protocol.APIOrigin, 1))
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Link", DiscoveryLink)
		if !cfg.PublicAccess() {
			w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		}
		// Documentation is small and immutable. Do not let multipart ranges
		// multiply formatting work or byte ranges on a cached asset.
		if len(r.Header.Values("Range")) != 0 || len(r.Header.Values("If-Range")) != 0 {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "range_not_supported", http.StatusBadRequest)
			return
		}
		serve := func(name, contentType string, body []byte) {
			w.Header().Set("Content-Type", contentType)
			http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
		}
		switch r.URL.Path {
		case "/readme":
			serve("about", "text/markdown; charset=utf-8", readmeMarkdown)
		case "/openapi":
			serve("openapi", "application/yaml", specYAML)
		case "/openapi/json":
			serve("openapi", "application/json", specJSON)
		case "/agents", "/openapi.yaml":
			http.Redirect(w, r, "/openapi", http.StatusPermanentRedirect)
		case "/openapi.json":
			http.Redirect(w, r, "/openapi/json", http.StatusPermanentRedirect)
		case "/docs":
			serve("docs", "text/html; charset=utf-8", swagger)
		case "/disclaimers":
			http.Redirect(w, r, "/info", http.StatusPermanentRedirect)
		case "/terms":
			serve("terms", "text/markdown; charset=utf-8", terms)
		case "/info":
			serve("info", "text/markdown; charset=utf-8", information)
		case "/llms.txt":
			serve("llms.txt", discovery["/llms.txt"].ContentType, []byte(discovery["/llms.txt"].Body))
		case "/.well-known/security.txt":
			serve("security.txt", discovery[r.URL.Path].ContentType, []byte(discovery[r.URL.Path].Body))
		case "/robots.txt":
			serve("robots.txt", discovery["/robots.txt"].ContentType, []byte(discovery["/robots.txt"].Body))
		case "/sitemap.xml":
			serve("sitemap.xml", discovery["/sitemap.xml"].ContentType, []byte(discovery["/sitemap.xml"].Body))
		case "/", "/v1/pdf/text":
			w.Header().Set("Vary", "Accept")
			format := representation(r.Header.Get("Accept"))
			if accept := strings.TrimSpace(r.Header.Get("Accept")); accept == "" || accept == "*/*" {
				format = "html"
			}
			switch format {
			case "html":
				if r.URL.Path != "/" {
					http.Redirect(w, r, "/docs", http.StatusPermanentRedirect)
					return
				}
				serve("index", "text/html; charset=utf-8", home)
			case "json":
				serve("openapi", "application/json", specJSON)
			case "yaml":
				serve("openapi", "application/yaml", specYAML)
			default:
				http.Error(w, "Accept text/html, application/yaml or application/json; /openapi always serves YAML", http.StatusNotAcceptable)
			}
		default:
			if asset, ok := assets[r.URL.Path]; ok {
				contentType := "text/plain; charset=utf-8"
				switch {
				case strings.HasSuffix(r.URL.Path, ".js"):
					contentType = "text/javascript; charset=utf-8"
				case strings.HasSuffix(r.URL.Path, ".css"):
					contentType = "text/css; charset=utf-8"
				case strings.HasSuffix(r.URL.Path, ".svg"):
					contentType = "image/svg+xml"
				}
				serve(r.URL.Path, contentType, asset)
				return
			}
			http.NotFound(w, r)
		}
	})
}

// Public tools and deep links come from the same embedded API contract.
// A future tool opts in with a name/summary; infrastructure endpoints stay out.
func toolsFromSpec(spec map[string]any) []tool {
	var tools []tool
	routes := spec["paths"].(map[string]any)
	keys := make([]string, 0, len(routes))
	for key := range routes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, route := range keys {
		operations := routes[route].(map[string]any)
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			op, ok := operations[method].(map[string]any)
			if !ok {
				continue
			}
			name, _ := op["x-tool-name"].(string)
			if name == "" {
				continue
			}
			summary, _ := op["x-tool-summary"].(string)
			operationID, _ := op["operationId"].(string)
			tags, _ := op["tags"].([]any)
			if summary == "" || operationID == "" || len(tags) == 0 {
				panic("tool needs summary, operationId and tag")
			}
			tag, ok := tags[0].(string)
			if !ok || tag == "" {
				panic("invalid tool tag")
			}
			tools = append(tools, tool{Name: name, Summary: summary, Route: route, Method: strings.ToUpper(method), DocsURL: "/docs#/" + url.PathEscape(tag) + "/" + url.PathEscape(operationID)})
		}
	}
	return tools
}

func robotsDirective(cfg protocol.Config) string {
	if cfg.PublicAccess() {
		return "index, follow"
	}
	return "noindex, nofollow"
}
func endpointDescription(cfg protocol.Config) string {
	if cfg.PublicAccess() {
		return "Public " + cfg.Mode() + " endpoint"
	}
	return "Restricted " + cfg.Mode() + " endpoint"
}
