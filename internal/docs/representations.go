package docs

import (
	"bytes"
	"encoding/json"
	"math"
	"mime"
	"sort"
	"strconv"
	"strings"
)

const DiscoveryLink = `</openapi>; rel="service-desc"; type="application/yaml", </openapi/json>; rel="alternate"; type="application/json", </docs>; rel="service-doc"; type="text/html", </readme>; rel="about"; type="text/markdown", </info>; rel="privacy-policy"; type="text/markdown", </terms>; rel="terms-of-service"; type="text/markdown"`

// Negotiate representations through HTTP Accept, without guessing identities
// from spoofable User-Agent strings. Unspecified/wildcard clients get YAML.
func representation(accept string) string {
	if strings.TrimSpace(accept) == "" {
		return "yaml"
	}
	best, bestQ := "", float64(0)
	for _, candidate := range []struct{ name, media string }{{"yaml", "application/yaml"}, {"json", "application/json"}, {"html", "text/html"}} {
		specificity, quality := -1, float64(0)
		for _, part := range strings.Split(accept, ",") {
			media, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			q := float64(1)
			if raw, ok := params["q"]; ok {
				q, err = strconv.ParseFloat(raw, 64)
				if err != nil || math.IsNaN(q) || q < 0 || q > 1 {
					continue
				}
			}
			score := -1
			switch {
			case media == candidate.media || candidate.name != "html" && media == "application/vnd.oai.openapi+"+candidate.name:
				score = 2
			case media == strings.Split(candidate.media, "/")[0]+"/*":
				score = 1
			case media == "*/*":
				score = 0
			}
			if score > specificity || score == specificity && q > quality {
				specificity, quality = score, q
			}
		}
		if specificity >= 0 && quality > bestQ {
			best, bestQ = candidate.name, quality
		}
	}
	return best
}

// Emit the JSON data model as YAML 1.2 block collections with JSON-quoted keys
// and scalars. This is a serializer for our trusted spec, not a YAML parser.
// Quoting preserves response-code keys, booleans-as-strings and descriptions;
// both HTTP representations come from exactly the same document.
func jsonYAML(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var node any
	if err := dec.Decode(&node); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	var emit func(any, int)
	writeValue := func(value any, depth int) {
		switch v := value.(type) {
		case map[string]any:
			if len(v) > 0 {
				out.WriteByte('\n')
				emit(v, depth+1)
				return
			}
		case []any:
			if len(v) > 0 {
				out.WriteByte('\n')
				emit(v, depth+1)
				return
			}
		}
		scalar, _ := json.Marshal(value) // node contains only validated JSON types.
		out.WriteByte(' ')
		out.Write(scalar)
		out.WriteByte('\n')
	}
	emit = func(value any, depth int) {
		indent := strings.Repeat("  ", depth)
		switch v := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				quoted, _ := json.Marshal(key)
				out.WriteString(indent)
				out.Write(quoted)
				out.WriteByte(':')
				writeValue(v[key], depth)
			}
		case []any:
			for _, child := range v {
				out.WriteString(indent + "-")
				writeValue(child, depth)
			}
		default:
			scalar, _ := json.Marshal(value)
			out.WriteString(indent)
			out.Write(scalar)
			out.WriteByte('\n')
		}
	}
	emit(node, 0)
	return out.Bytes(), nil
}
