package server

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestConnectionLimitClosesExcessAndReleasesSlot(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := LimitListener(raw, 1).(*limitedListener)
	defer l.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("healthy")) })}
	done := make(chan error, 1)
	go func() { done <- server.Serve(l) }()
	defer func() { _ = server.Close(); <-done }()
	first, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	until := time.Now().Add(time.Second)
	for len(l.slots) != 1 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if len(l.slots) != 1 {
		t.Fatal("first connection was not admitted")
	}
	extra, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = extra.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("excess connection not closed: %v", err)
	}
	_ = first.Close()
	until = time.Now().Add(time.Second)
	for len(l.slots) != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + raw.Addr().String())
	if err != nil {
		t.Fatal("healthy request blocked after release", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "healthy" {
		t.Fatalf("response=%q err=%v", data, err)
	}
}

func TestConnectionCloseReleasesOnlyOnce(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	releases := 0
	c := &limitedConn{Conn: a, release: func() { releases++ }}
	_ = c.Close()
	_ = c.Close()
	if releases != 1 {
		t.Fatal("slot released more than once")
	}
}
