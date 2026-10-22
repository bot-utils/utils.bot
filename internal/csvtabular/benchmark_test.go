package tabular

import (
	"encoding/json"
	"strings"
	"testing"
)

func BenchmarkAggregate50000(b *testing.B) {
	data := []byte("region,amount,payload\n" + strings.Repeat("west,0.10,synthetic repeated event payload\n", 50_000))
	opts := json.RawMessage(`{"group_columns":["region"],"metrics":[{"name":"events","op":"count_rows"},{"name":"total","op":"sum","column":"amount"}]}`)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := Execute("aggregate", opts, map[string][]byte{"file": data})
		if err != nil || r.Rows[0][2] != "5000" {
			b.Fatal(r, err)
		}
	}
}
