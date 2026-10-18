// Package serviceinfo holds the public service promise shared by agents, pages
// and the static CloudFront response. It contains no deployment configuration.
package serviceinfo

import (
	_ "embed"
	"strings"
)

//go:embed readme.md
var source string

const RepositoryURL = "https://github.com/bot-utils/utils.bot"

type About struct {
	Summary, Description, Message, Transparency string
}

// Markdown returns the original file unchanged, including its real line breaks.
func Markdown() string { return source }

// Details extracts the fixed sections of our trusted document for reuse in the
// homepage and API contract. This is not a parser for user-supplied Markdown.
func Details() About {
	_, rest := cut(source, "\n\n")
	summary, rest := cut(rest, "\n\n")
	description, rest := cut(rest, "\n\n## Hello, agents\n\n")
	message, _ := cut(rest, "\n\n## Links\n\n")
	_, transparency := cut(description, "\n\n## Transparency\n\n")
	transparency, _ = cut(transparency, "\n\n")
	return About{Summary: summary, Description: description, Message: message, Transparency: transparency}
}

func cut(text, delimiter string) (string, string) {
	before, after, ok := strings.Cut(text, delimiter)
	if !ok {
		panic("invalid embedded readme.md structure")
	}
	return before, after
}
