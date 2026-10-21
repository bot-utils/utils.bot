package edge

import (
	"os/exec"
	"pdfservice/internal/docs"
	"pdfservice/internal/protocol"
	"testing"
)

func TestStaticPoliciesFitAndNeverReachOriginOrReadBodies(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node unavailable")
	}
	for _, mode := range []string{protocol.ModeMock, protocol.ModeSepolia, protocol.ModeBase} {
		payTo := "0x2222222222222222222222222222222222222222"
		if mode == protocol.ModeMock {
			payTo = ""
		}
		cfg, err := protocol.NewConfig(mode, payTo)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range []string{"/info", "/terms"} {
			code, err := StaticCode(route, "203.0.113.10", cfg)
			if err != nil {
				t.Fatal(route, err)
			}
			script := `
const cases=[['GET',{}, {},'203.0.113.10',200],['HEAD',{}, {},'203.0.113.10',200],['POST',{}, {},'203.0.113.10',405],['GET',{}, {},'198.51.100.8',403],['GET',{}, {x:{value:'x'}},'203.0.113.10',400],['GET',{range:{value:'bytes=0-0'}},{},'203.0.113.10',400]];
let body;
for(const [method,headers,querystring,ip,status] of cases){
 headers['payment-signature']={value:'sensitive-signature'};
 const request={method,uri:config.route,headers,querystring};
 Object.defineProperty(request,'body',{get(){throw Error('body read')}});
 const response=handler({viewer:{ip},request});
 if(response===request||response.statusCode!==status)throw Error('origin reached or wrong admission');
 if(response.body.includes('sensitive-signature'))throw Error('header reflected');
 if(status===200){
  if(response.headers['content-type'].value!=='text/markdown; charset=utf-8')throw Error('bad content type');
  if(method==='HEAD'&&response.body!=='')throw Error('HEAD body');
  if(method==='GET')body=response.body;
 }
}
if(handler({viewer:{ip:'203.0.113.10'},request:{method:'GET',uri:'/other',headers:{},querystring:{}}}).statusCode!==404)throw Error('wrong route allowed');
console.log(body);
`
			raw, err := exec.Command("node", "-e", edgeLogCapture+code+script).CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, raw)
			}
			want := docs.Information(cfg)
			if route == "/terms" {
				want = docs.Terms(cfg)
			}
			if string(raw) != want+"\n" {
				t.Fatal("static policy drift", route)
			}
		}
	}
	for _, route := range []string{"/about", "/", "/info?bad=1"} {
		if _, err := StaticCode(route, "203.0.113.10", protocol.Config{}); err == nil {
			t.Fatal("unsupported route", route)
		}
	}
	if _, err := StaticCode("/info", "0.0.0.0/0", protocol.Config{}); err == nil {
		t.Fatal("unbounded owner")
	}
}
