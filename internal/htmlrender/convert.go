package htmlrender

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"

	"pdfservice/internal/htmllimits"
)

// Convert uses a bounded streaming tokenizer, never a browser, recursive DOM or
// external resources. Markdown is untrusted page data, not an instruction filter.
func Convert(ctx context.Context, source []byte, base *url.URL) (string, string, bool, error) {
	if len(source) > MaxHTML {
		return "", "", false, ErrSize
	}
	z := html.NewTokenizer(bytes.NewReader(source))
	z.SetMaxBuf(htmllimits.MaxHTMLToken)
	var out, title strings.Builder
	var skipped string
	var link string
	pre, inTitle, truncated := false, false, false
	tokens := 0
	appendText := func(s string) {
		if truncated {
			return
		}
		remain := MaxMarkdown - out.Len()
		if len(s) > remain {
			s = s[:remain]
			for !utf8.ValidString(s) && len(s) > 0 {
				s = s[:len(s)-1]
			}
			truncated = true
		}
		out.WriteString(s)
	}
	newline := func() {
		if out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") {
			appendText("\n")
		}
	}
	for {
		if tokens++; tokens > htmllimits.MaxHTMLTokens {
			return "", "", false, ErrComplexity
		}
		if tokens%128 == 0 && ctx.Err() != nil {
			return "", "", false, ctx.Err()
		}
		kind := z.Next()
		if kind == html.ErrorToken {
			if z.Err() != io.EOF {
				return "", "", false, ErrComplexity
			}
			break
		}
		t := z.Token()
		if skipped != "" {
			if kind == html.EndTagToken && t.Data == skipped {
				skipped = ""
			}
			continue
		}
		if kind == html.StartTagToken || kind == html.SelfClosingTagToken {
			switch t.Data {
			case "script", "style", "noscript", "template", "iframe", "svg", "math":
				if kind != html.SelfClosingTagToken {
					skipped = t.Data
				}
				continue
			case "title":
				inTitle = true
				continue
			}
		}
		if kind == html.EndTagToken && t.Data == "title" {
			inTitle = false
			continue
		}
		if inTitle {
			if kind == html.TextToken && title.Len() < htmllimits.MaxHTMLTitle {
				text := strings.Join(strings.Fields(t.Data), " ")
				if len(text) > htmllimits.MaxHTMLTitle-title.Len() {
					text = text[:htmllimits.MaxHTMLTitle-title.Len()]
					for !utf8.ValidString(text) && len(text) > 0 {
						text = text[:len(text)-1]
					}
				}
				title.WriteString(text)
			}
			continue
		}
		switch kind {
		case html.TextToken:
			text := t.Data
			if !pre {
				text = strings.Join(strings.Fields(text), " ")
				if text != "" && len(t.Data) > 0 && unicode.IsSpace([]rune(t.Data)[0]) && out.Len() > 0 && !strings.HasSuffix(out.String(), "\n") && !strings.HasSuffix(out.String(), " ") {
					text = " " + text
				}
				// Escape Markdown controls so hidden source constructs do not become images.
				text = strings.NewReplacer("\\", "\\\\", "!", "\\!", "[", "\\[", "]", "\\]", "*", "\\*", "_", "\\_", "`", "\\`", "<", "&lt;", ">", "&gt;").Replace(text)
				if len(t.Data) > 0 && unicode.IsSpace([]rune(t.Data)[len([]rune(t.Data))-1]) && text != "" {
					text += " "
				}
			}
			appendText(strings.ToValidUTF8(text, "�"))
		case html.StartTagToken, html.SelfClosingTagToken:
			switch t.Data {
			case "h1", "h2", "h3", "h4", "h5", "h6":
				newline()
				appendText(strings.Repeat("#", int(t.Data[1]-'0')) + " ")
			case "p", "div", "section", "article", "header", "footer", "nav", "ul", "ol", "table", "tr", "blockquote":
				newline()
			case "li":
				newline()
				appendText("- ")
			case "br", "hr":
				newline()
			case "td", "th":
				appendText(" | ")
			case "pre":
				newline()
				appendText("````\n")
				pre = true
			case "a":
				if link == "" {
					for _, a := range t.Attr {
						if a.Key == "href" {
							u, err := url.Parse(a.Val)
							if err == nil {
								u = base.ResolveReference(u)
								if (u.Scheme == "https" || u.Scheme == "http") && u.User == nil && len(u.String()) < 2048 {
									link = u.String()
									appendText("[")
								}
							}
							break
						}
					}
				}
			}
		case html.EndTagToken:
			switch t.Data {
			case "h1", "h2", "h3", "h4", "h5", "h6", "p", "div", "section", "article", "li", "ul", "ol", "tr", "blockquote":
				newline()
			case "pre":
				pre = false
				newline()
				appendText("````\n")
			case "a":
				if link != "" {
					appendText("](" + strings.NewReplacer("(", "%28", ")", "%29", " ", "%20", "<", "%3C", ">", "%3E").Replace(link) + ")")
					link = ""
				}
			}
		}
	}
	if ctx.Err() != nil {
		return "", "", false, ctx.Err()
	}
	return strings.TrimSpace(out.String()), strings.TrimSpace(title.String()), truncated, nil
}
