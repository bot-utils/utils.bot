package docs

import (
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"pdfservice/internal/paths"
)

func TestDistributedSwaggerRetainsNoticeAndReferencedLicenses(t *testing.T) {
	bundle, err := files.ReadFile("assets/swagger-ui-bundle.js")
	if err != nil {
		t.Fatal(err)
	}
	notices := regexp.MustCompile(`[A-Za-z0-9._-]+\.LICENSE\.txt`).FindAllString(string(bundle), -1)
	if len(notices) == 0 {
		t.Fatal("bundled-license reference not checked")
	}
	notices = append(notices, "SWAGGER-UI-NOTICE", "SWAGGER-UI-LICENSE")
	handler := New("https://utils.bot/v1/pdf/text")
	for _, name := range notices {
		path := "/assets/" + name
		if !paths.Supported(path) {
			t.Fatal("notice blocked at the front door", name)
		}
		expected, err := files.ReadFile("assets/" + name)
		if err != nil || len(expected) == 0 {
			t.Fatal("missing bundled attribution", name, err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 200 || response.Body.String() != string(expected) || response.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatal("notice not served intact as plain text", name)
		}
	}
}

func TestSwaggerInitializerDisablesExternalAndPersistentState(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is required for executing the browser initializer")
	}
	initializer, err := files.ReadFile("assets/initializer.js")
	if err != nil {
		t.Fatal(err)
	}
	check := `
let options;
const window={addEventListener:(name,callback)=>{if(name!=='DOMContentLoaded')throw Error('unexpected browser hook');callback();}};
const SwaggerUIBundle=(config)=>{options=config;};
SwaggerUIBundle.presets={apis:{}};
` + string(initializer) + `
if(!options||options.url!=='/openapi'||options.queryConfigEnabled!==false||options.validatorUrl!==null||options.persistAuthorization!==false||options.withCredentials!==false)throw Error('unsafe browser configuration');
if(options.configUrl||options.urls||options.oauth2RedirectUrl)throw Error('external configuration enabled');
`
	if output, err := exec.Command("node", "-e", check).CombinedOutput(); err != nil {
		t.Fatalf("unsafe browser initializer: %v %s", err, strings.TrimSpace(string(output)))
	}
}
