// Package jsonwire bounds and checks small control messages before decoding.
package jsonwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// Unmarshal preserves protocol extension fields, but rejects ambiguous objects.
func Unmarshal(data []byte, value any, maxBytes int) error {
	if err := validate(data, maxBytes); err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

// Decode also rejects unknown fields in our private typed messages.
func Decode(data []byte, value any, maxBytes int) error {
	if err := validate(data, maxBytes); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(value)
}

func Check(data []byte, maxBytes int) error { return validate(data, maxBytes) }

func validate(data []byte, maxBytes int) error {
	if len(data) == 0 || len(data) > maxBytes || !utf8.Valid(data) {
		return errors.New("invalid JSON size or encoding")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	values := 0
	var visit func(int) error
	visit = func(depth int) error {
		values++
		if depth > 32 || values > 4096 {
			return errors.New("JSON complexity limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				var keys []string
				for d.More() {
					token, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := token.(string)
					if !ok || len(key) > 256 || len(keys) >= 64 {
						return errors.New("JSON object limit")
					}
					for _, prior := range keys {
						if strings.EqualFold(prior, key) {
							return errors.New("duplicate JSON field")
						}
					}
					keys = append(keys, key)
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return errors.New("invalid JSON object")
				}
			case '[':
				for d.More() {
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return errors.New("invalid JSON array")
				}
			default:
				return errors.New("invalid JSON delimiter")
			}
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

// MarshalResponse serializes an HTTP JSON body without expanding &, < and >
// into HTML escapes. Never embed its output into HTML or JavaScript. Callers
// must set application/json and nosniff; untrusted text is validated separately.
func MarshalResponse(value any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}
