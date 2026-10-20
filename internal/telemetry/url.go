package telemetry

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

const MaxRequestURLBytes = 2048

// RequestURL retains the encoded path, query order and nonsensitive values.
// It classifies decoded query names without rewriting their original spelling.
// It never reads Host, headers, the uploaded document or a submitted fetch URL.
func RequestURL(path, query string, forceQuery bool) (target string, truncated, redacted bool) {
	var out strings.Builder
	out.Grow(MaxRequestURLBytes)
	put := func(value string) bool {
		remaining := MaxRequestURLBytes - out.Len()
		if len(value) > remaining {
			prefix := value[:remaining]
			if utf8.ValidString(value) {
				for !utf8.ValidString(prefix) {
					prefix = prefix[:len(prefix)-1]
				}
			}
			out.WriteString(prefix)
			truncated = true
			return false
		}
		out.WriteString(value)
		return true
	}
	if put(path) && (query != "" || forceQuery) && put("?") {
		first := true
		for part := range strings.SplitSeq(query, "&") {
			if !first && !put("&") {
				break
			}
			first = false
			key, value, hasValue := strings.Cut(part, "=")
			if !put(key) {
				break
			}
			if !hasValue {
				continue
			}
			if !put("=") {
				break
			}
			if sensitiveQueryName(key) {
				value = "[REDACTED]"
				redacted = true
			}
			if !put(value) {
				break
			}
		}
	}
	target = strings.ToValidUTF8(out.String(), "\uFFFD")
	if len(target) > MaxRequestURLBytes {
		target = target[:MaxRequestURLBytes]
		truncated = true
	}
	// Do not append a misleading replacement rune if truncation split UTF-8.
	if truncated {
		for !utf8.ValidString(target) {
			target = target[:len(target)-1]
		}
	}
	return
}

func sensitiveQueryName(key string) bool {
	for range 2 {
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			return true // Preserve the malformed name, but not an ambiguous value.
		}
		if decoded == key {
			break
		}
		key = decoded
	}
	key = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, key)
	switch key {
	case "key", "auth", "code", "sig", "pwd", "pin", "jwt", "bearer", "payment", "email", "phone", "address", "ip", "ipaddress":
		return true
	}
	for _, sensitive := range []string{"token", "apikey", "accesskey", "privatekey", "walletkey", "signingkey", "seed", "mnemonic", "recoveryphrase", "password", "passwd", "passcode", "passphrase", "secret", "signature", "authorization", "credential", "cookie", "session"} {
		if strings.Contains(key, sensitive) {
			return true
		}
	}
	return false
}
