package edge

import (
	"encoding/json"
	"os/exec"
	"pdfservice/internal/docs"
	"pdfservice/internal/protocol"
	"testing"
)

func TestDiscoveryIsStaticAndPublicOnlyOnExplicitLaunch(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node unavailable")
	}
	base, err := protocol.NewConfig(protocol.ModeBase, "0x2222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{"0", "1"} {
		cfg, err := base.WithPublicAccess(setting)
		if err != nil {
			t.Fatal(err)
		}
		code, err := StaticCode("/discovery", "203.0.113.10", cfg)
		if err != nil {
			t.Fatal(err)
		}
		script := `
let results={};
for(const uri of Object.keys(config.documents)){
 const request={method:'GET',uri,headers:{},querystring:{}};
 Object.defineProperty(request,'body',{get(){throw Error('body read')}});
 const good=handler({viewer:{ip:config.ownerIP},request});
 const outsider=handler({viewer:{ip:'198.51.100.8'},request});
 if(good===request||good.statusCode!==200||outsider.statusCode!==(config.public?200:403))throw Error('private/static boundary');
 if(good.headers['x-robots-tag'].value!==(config.public?'index, follow':'noindex, nofollow'))throw Error('indexing state mismatch');
 results[uri]={body:good.body,contentType:good.headers['content-type'].value};
}
for(const uri of ['/__proto__','constructor','/v1/pdf/text']){
 if(handler({viewer:{ip:config.ownerIP},request:{method:'GET',uri,headers:{},querystring:{}}}).statusCode!==404)throw Error('unexpected static route');
}
console.log(JSON.stringify(results));
`
		raw, err := exec.Command("node", "-e", edgeLogCapture+code+script).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, raw)
		}
		var got map[string]docs.Document
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		for path, want := range docs.Discovery("https://utils.bot", cfg) {
			if got[path] != want {
				t.Fatal("edge/origin drift", path)
			}
		}
	}
}

func TestPublicStaticPoliciesAndUnpaidQuoteKeepAdmissionRules(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node unavailable")
	}
	cfg, err := protocol.NewConfig(protocol.ModeBase, "0x2222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = cfg.WithPublicAccess("1")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/info", "/terms"} {
		var code string
		if route == "/readme" {
			code, err = CodeWithConfig("https://utils.bot/v1/pdf/text", "203.0.113.10", cfg)
		} else {
			code, err = StaticCode(route, "203.0.113.10", cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := exec.Command("node", "-e", edgeLogCapture+code+`const uri=`+mustJSON(route)+`;const r=handler({viewer:{ip:'198.51.100.8'},request:{method:'GET',uri,headers:{},querystring:{}}});if(r.statusCode!==200||r.headers['x-robots-tag'].value!=='index, follow')throw Error('public static document unavailable');const bad=handler({viewer:{ip:'198.51.100.8'},request:{method:'PUT',uri,headers:{},querystring:{}}});if(bad.statusCode!==405)throw Error('method admission lost');`).CombinedOutput()
		if err != nil {
			t.Fatalf("%v %s", err, raw)
		}
	}
	code, err := CodeWithConfig("https://utils.bot/v1/pdf/text", "203.0.113.10", cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command("node", "-e", edgeLogCapture+code+`const r=handler({viewer:{ip:'198.51.100.8'},request:{method:'POST',uri:'/v1/pdf/text',headers:{},querystring:{}}});if(r.statusCode!==402||r.headers['x-payment-mode'].value!=='cdp-base')throw Error('public quote bypass or mode mismatch');`).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, raw)
	}
}
func mustJSON(v string) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
