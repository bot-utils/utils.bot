package parser

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestWorkerDirectoryMustBeAbsolute(t *testing.T) {
	for _, dir := range []string{"", ".", "workers"} {
		_, outcome, err := (Parser{Dir: dir}).attempt(context.Background(), "pdfium", []byte("%PDF-1.4"))
		if outcome != "setup_failed" || !errors.Is(err, ErrSetup) {
			t.Fatalf("relative worker directory %q did not fail closed: outcome=%q error=%v", dir, outcome, err)
		}
	}
}

func TestWorkerResultBounds(t *testing.T) {
	cases := []string{
		`{"pageCount":null,"truncated":false,"pages":[]}`,
		`{"pageCount":0,"truncated":null,"pages":[]}`,
		`{"pageCount":1,"truncated":false,"pages":[],"pageCount":1}`,
		`{"pageCount":1,"truncated":false,"pages":[],"action":"kill"}`,
		`{"pageCount":1,"truncated":false,"pages":[]} {}`,
		`{"pageCount":1,"truncated":false,"pages":[{"index":0,"width":1,"height":1,"text":"` + string([]byte{0xff}) + `"}]}`,
		`{"pageCount":1,"truncated":false,"pages":[{"index":0,"width":1,"WIDTH":2,"height":1,"text":""}]}`,
		`{"pageCount":1,"truncated":false,"pages":[{"width":1,"height":1,"text":""}]}`,
		`{"pageCount":1,"truncated":false,"pages":[{"index":0,"width":null,"height":1,"text":""}]}`,
		`{"pageCount":1000,"truncated":false,"pages":[` + strings.Repeat(`{"index":0,"width":1,"height":1,"text":""},`, 100) + `{"index":0,"width":1,"height":1,"text":""}]}`,
	}
	for _, raw := range cases {
		if _, err := decodeResult([]byte(raw)); err == nil {
			t.Fatal("unsafe worker output accepted")
		}
	}
	valid := `{"pageCount":1,"truncated":false,"pages":[{"index":0,"width":612,"height":792,"text":"hello"}]}`
	r, err := decodeResult([]byte(valid))
	if err != nil || validate(&r) != nil {
		t.Fatal("valid worker response rejected")
	}
}

func TestIncompletePageListRequiresTruncation(t *testing.T) {
	r := Result{PageCount: 2, Pages: []Page{{Index: 0, Width: 612, Height: 792, Text: "hello"}}}
	if validate(&r) == nil {
		t.Fatal("unmarked missing page accepted")
	}
	r.Truncated = true
	if validate(&r) != nil {
		t.Fatal("explicitly truncated result rejected")
	}
}
