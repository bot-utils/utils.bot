package protocol

import (
	"strings"
	"testing"
)

func TestRegionalQuoteUsesCanonicalAPIAndWebsiteTerms(t *testing.T) {
	for _, origin := range []string{SiteOrigin, APIOrigin, "http://localhost:8080"} {
		resource := origin + "/v1/pdf/text"
		q := (Config{}).Quote(resource)
		termsOrigin := origin
		if origin == APIOrigin {
			termsOrigin = SiteOrigin
		}
		if q.Resource.URL != resource || !strings.Contains(q.Resource.Description, termsOrigin+"/terms#terms-of-use") {
			t.Fatalf("wrong quote: %+v", q.Resource)
		}
		if origin == APIOrigin && strings.Contains(q.Resource.Description, APIOrigin+"/terms") {
			t.Fatal("terms advertised at API listener")
		}
	}
}
