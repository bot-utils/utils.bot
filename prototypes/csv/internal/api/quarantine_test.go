package api

import (
	"context"
	"net/http/httptest"
	"pdfservice/internal/csvtabular"
	"testing"
)

func TestCleanupFailureQuarantinesFurtherWorkAndHealth(t *testing.T) {
	calls := 0
	s := New(func(context.Context, Job) (tabular.Result, error) {
		calls++
		return tabular.Result{}, &tabular.Error{Code: "worker_cleanup_failed", Status: 503}
	}, nil)
	for range 2 {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, request(t, "/csv/dedupe", `{"key_columns":["id"],"keep":"first"}`, map[string]string{"file": "id\nx\n"}))
		if w.Code != 503 {
			t.Fatal(w.Code)
		}
	}
	if calls != 1 {
		t.Fatal("continued work after unconfirmed cleanup")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:18082/health", nil))
	if w.Code != 503 {
		t.Fatal("quarantined health appeared ready")
	}
}
