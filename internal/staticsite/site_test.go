package staticsite

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"pdfservice/internal/docs"
	"pdfservice/internal/protocol"
)

func TestStaticBundleMatchesTrustedLiveRendererAndContainsNoOperatorData(t *testing.T) {
	resource := protocol.APIOrigin + "/v1/pdf/text"
	b, err := Build(resource, "203.0.113.99", protocol.Config{})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Build(resource, "203.0.113.99", protocol.Config{})
	if !reflect.DeepEqual(b, again) {
		t.Fatal("nondeterministic assets")
	}
	objects := map[string]Object{}
	for _, o := range b.Objects {
		objects[o.Key] = o
		if strings.Contains(string(o.Body), "203.0.113.99") || !strings.HasPrefix(o.Key, "public/") || strings.Contains(o.Key, "..") {
			t.Fatal("private information or unsafe object key")
		}
	}
	h := docs.New(resource)
	for path, route := range b.Routes {
		if strings.HasPrefix(path, "@") {
			continue
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Accept", "text/html")
		h.ServeHTTP(w, r)
		if route.Redirect != "" {
			if route.Redirect != w.Header().Get("Location") {
				t.Fatal("redirect drift", path)
			}
			continue
		}
		o := objects[route.Key]
		if !bytes.Equal(o.Body, w.Body.Bytes()) || o.ContentType != w.Header().Get("Content-Type") {
			t.Fatal("content/contract drift", path)
		}
	}
	if len(b.Objects) < 10 || len(b.RequestCode) > 10240 || strings.Contains(b.RequestCode, "203.0.113.99") == false {
		t.Fatal("incomplete private bundle")
	}
}
func TestStaticViewerGateNegotiatesAndNeverForwardsCustomerData(t *testing.T) {
	if _, e := exec.LookPath("node"); e != nil {
		t.Skip("node executes exact local CloudFront function")
	}
	b, e := Build(protocol.APIOrigin+"/v1/pdf/text", "203.0.113.99", protocol.Config{})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(b.Routes)
	check := `const routes=` + string(raw) + `;
for(const [uri,accept,key] of [['/','text/html','/'],['/','application/yaml','@yaml'],['/','application/json','@json'],['/','application/json;q=0,application/yaml;q=.5','@yaml'],['/docs','text/html','/docs'],['/openapi','','/openapi'],['/assets/swagger-ui-bundle.js','','/assets/swagger-ui-bundle.js']]){
 const request={method:'GET',uri,querystring:{},headers:{host:{value:'utils.bot'},accept:{value:accept},authorization:{value:'secret'},'payment-signature':{value:'secret'},'x-forwarded-for':{value:'secret'}},cookies:{secret:{value:'secret'}}};
 Object.defineProperty(request,'body',{get(){throw Error('body read')}});
 const r=handler({viewer:{ip:'203.0.113.99'},request});
 if(r.uri!=='/'+routes[key].key || r!==request || Object.keys(r.headers).join(',')!=='host' || Object.keys(r.cookies).length)throw Error(JSON.stringify(r));
 const denied=handler({viewer:{ip:'198.51.100.1'},request:{method:'GET',uri,headers:{},querystring:{}}});
 if(denied.statusCode!==403)throw Error('private cached asset exposed');
}
for(const [method,uri,headers,q,want] of [['POST','/v1/pdf/text',{}, {},307],['GET','/assets/private.pem',{}, {},404],['PUT','/docs',{}, {},405],['GET','/docs',{range:{value:'bytes=0-0'}}, {},400],['GET','/docs',{}, {a:{value:'1'}},400],['GET','/',{accept:{value:'image/png'}}, {},406],['GET','/openapi.yaml',{}, {},308],['GET','/agents',{}, {},308],['HEAD','/agents',{}, {},308],['POST','/health',{}, {},405],['GET','/docs',{'content-length':{value:'1'}}, {},400]]) {
 const r=handler({viewer:{ip:'203.0.113.99'},request:{method,uri,headers,querystring:q}});
 if(r.statusCode!==want)throw Error(JSON.stringify(r));
 if(want===307 && r.headers.location.value!=='https://api.utils.bot/v1/pdf/text')throw Error('untrusted redirect');
 if(uri==='/agents' && r.headers.location.value!=='/openapi')throw Error('noncanonical agent spec redirect');
}
`
	if out, e := exec.Command("node", "-e", b.RequestCode+check).CombinedOutput(); e != nil {
		t.Fatalf("%v: %s", e, out)
	}
	check = `const r=handler({response:{statusCode:200,headers:{'set-cookie':{value:'secret'}}}});if(r.headers['set-cookie'] || r.headers['x-robots-tag'].value!=='noindex, nofollow' || !r.headers['content-security-policy'].value.includes('https://api.utils.bot') || r.headers['cache-control'].value!=='no-store')throw Error(JSON.stringify(r));`
	if out, e := exec.Command("node", "-e", b.ResponseCode+check).CombinedOutput(); e != nil {
		t.Fatalf("%v: %s", e, out)
	}
}
func TestStaticExportRejectsWrongAPIOrOwner(t *testing.T) {
	for _, c := range [][2]string{{"https://evil.invalid/v1/pdf/text", "203.0.113.99"}, {protocol.APIOrigin + "/v1/pdf/text", "0.0.0.0/0"}} {
		if _, e := Build(c[0], c[1], protocol.Config{}); e == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}
