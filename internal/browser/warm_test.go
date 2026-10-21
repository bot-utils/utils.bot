package browser

import (
	"context"
	"testing"
)

func TestWarmBrowserFailsClosedWithoutSnapshot(t *testing.T) {
	var w Warm
	ctx := context.Background()
	if w.Restore(ctx) == nil || w.Validate(ctx) == nil {
		t.Fatal("uninitialized browser accepted")
	}
	if _, err := w.Take(ctx); err == nil {
		t.Fatal("missing snapshot accepted")
	}
	w.Close()
	if w.Prepare(ctx) == nil || w.Restore(ctx) == nil {
		t.Fatal("closed browser restarted")
	}
}
