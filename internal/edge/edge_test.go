package edge

import (
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"regexp"
	"testing"

	"pdfservice/internal/protocol"
)

func TestEdgeConfigurationRejectsUnsafeResources(t *testing.T) {
	for _, resource := range []string{"http://utils.bot/v1/pdf/text", "https://evil.test/v1/pdf/text", "https://utils.bot/v1/pdf/text?override=1", "https://user@utils.bot/v1/pdf/text"} {
		if _, err := Code(resource, "203.0.113.10"); err == nil {
			t.Fatal("invalid resource accepted", resource)
		}
	}
	if _, err := Code("https://utils.bot/v1/pdf/text", "0.0.0.0/0"); err == nil {
		t.Fatal("broad owner address accepted")
	}
}

func TestEdgeUsesCloudFrontSupportedStatements(t *testing.T) {
	// Node accepts for-of, but CloudFront's supported ES6 statement list
	// includes const/let rather than for-of. Keep this boundary explicit.
	unsupported := regexp.MustCompile(`for\s*\([^\n]*\sof\s`)
	if unsupported.MatchString(source) {
		t.Fatal("CloudFront does not support for-of statements")
	}
}

func TestEdgeRequestsUseStandardQuoteAndNeverReadBody(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is used only for local CloudFront JavaScript tests")
	}
	code, err := Code("https://utils.bot/v1/pdf/text", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	// Node's built-in VM executes the exact generated function. There are no npm
	// dependencies, network calls, native PDF inputs or payment keys in this test.
	check := `
const cases = [
 ['POST','/v1/pdf/text',{},402],
 ['POST','/v1/pdf/text',{'payment-signature':{value:''}},402],
 ['POST','/v1/pdf/text',{'payment-signature':{value:'fixture'},'content-type':{value:'application/pdf'}},0],
 ['PUT','/v1/pdf/text',{},405], ['DELETE','/',{},405],
 ['GET','/v100/words',{},404], ['POST','/v100/words',{},404],
 ['POST','/docs',{},405], ['GET','/openapi.yaml',{},0],
 ['GET','/assets/swagger-ui-bundle.js',{'range':{value:'bytes=0-0'}},400],
 ['HEAD','/openapi',{'if-range':{value:'fixture'}},400],
 ['POST','/v1/pdf/text',{'payment-signature':{value:'fixture',multiValue:[{value:'fixture'},{value:'other'}]}},400],
 ['POST','/v1/pdf/text',{'payment-signature':{value:'fixture'},'content-type':{value:'text/plain'}},415],
 ['POST','/v1/pdf/text',{'payment-signature':{value:'fixture'},'content-type':{value:'application/pdf'},'content-length':{value:'104857601'}},413],
 ['POST','/v1/pdf/text',{'payment-signature':{value:'fixture'},'content-type':{value:'application/pdf'},'content-encoding':{value:'gzip'}},415]
];
let quote;
for(const [method,uri,headers,status] of cases) {
 const request={method,uri,headers,querystring:{}};
 Object.defineProperty(request,'body',{get(){throw Error('body read at edge')}});
 const response=handler({viewer:{ip:'203.0.113.10'},request});
 if((response.statusCode||0)!==status)throw Error(method+' '+uri+': '+JSON.stringify(response));
 if(status===0 && response!==request)throw Error('request replaced');
 if(status===402)quote=response;
}
for(const uri of config.routes) {
 const response=handler({viewer:{ip:'203.0.113.10'},request:{method:'HEAD',uri,headers:{},querystring:{}}});
 if(response.statusCode && !(uri==='/readme' && response.statusCode===200 && response.body===''))throw Error('supported route rejected: '+uri);
 for(const method of ['GET','HEAD']) {
  const denied=handler({viewer:{ip:'198.51.100.2'},request:{method,uri,headers:{'user-agent':{value:'Googlebot'}},querystring:{}}});
  if(denied.statusCode!==403)throw Error('private documentation exposed: '+uri);
 }
}
if(handler({viewer:{ip:'198.51.100.2'},request:{method:'POST',uri:'/v1/pdf/text',headers:{}}}).statusCode!==403)throw Error('public mock access allowed');
if(handler({viewer:{ip:'203.0.113.10'},request:{method:'GET',uri:'/',headers:{},querystring:{bad:{value:'1'}}}}).statusCode!==400)throw Error('query accepted');
console.log(JSON.stringify(quote));
`
	cmd := exec.Command("node", "-e", edgeLogCapture+code+check)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("edge execution: %v: %s", err, raw)
	}
	var response struct {
		Body    string `json:"body"`
		Headers map[string]struct {
			Value string `json:"value"`
		} `json:"headers"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	header, err := base64.StdEncoding.Strict().DecodeString(response.Headers["payment-required"].Value)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(protocol.Quote("https://utils.bot/v1/pdf/text"))
	if string(header) != string(want) || response.Body != string(want) {
		t.Fatal("edge x402 quote diverged from backend")
	}
}

func TestRealQuoteUsesSameBaseRequirements(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node unavailable")
	}
	cfg, err := protocol.NewConfig(protocol.ModeBase, "0x2222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	code, err := CodeWithConfig("https://utils.bot/v1/pdf/text", "203.0.113.10", cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command("node", "-e", edgeLogCapture+code+`const r=handler({viewer:{ip:'203.0.113.10'},request:{method:'POST',uri:'/v1/pdf/text',headers:{}}}); if(r.statusCode!==402||r.headers['x-payment-mode'].value!=='cdp-base')throw Error('wrong payment mode');console.log(r.body);`).CombinedOutput()
	if err != nil {
		t.Fatalf("edge: %v %s", err, raw)
	}
	var actual any
	if err := json.Unmarshal(raw, &actual); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(cfg.Quote("https://utils.bot/v1/pdf/text"))
	got, _ := json.Marshal(actual)
	if string(got) != string(want) { // JSON property order is irrelevant.
		var a, b any
		_ = json.Unmarshal(got, &a)
		_ = json.Unmarshal(want, &b)
		aa, _ := json.Marshal(a)
		bb, _ := json.Marshal(b)
		if string(aa) != string(bb) {
			t.Fatal("edge/backend Base quote differs")
		}
	}
}
