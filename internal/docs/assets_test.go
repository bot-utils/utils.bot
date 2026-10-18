package docs

import (
	"net/http/httptest"
	"testing"
)

func TestSwaggerAssetRequestsDoNotCopyBundle(t *testing.T) {
	handler := New("http://example.test/v1/pdf/text")
	request := httptest.NewRequest("HEAD", "/assets/swagger-ui-bundle.js", nil)
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 200 || response.Body.Len() != 0 {
				b.Fatal("asset HEAD failed")
			}
		}
	})
	if result.AllocedBytesPerOp() > 64<<10 {
		t.Fatalf("asset request copies bundle: %d bytes/request", result.AllocedBytesPerOp())
	}
}
