package edge

import (
	"os/exec"
	"pdfservice/internal/protocol"
	"pdfservice/internal/serviceinfo"
	"testing"
)

func TestStaticAboutNeverInvokesOriginOrReadsBody(t *testing.T) {
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
		code, err := CodeWithConfig("https://utils.bot/v1/pdf/text", "203.0.113.10", cfg)
		if err != nil {
			t.Fatal(err)
		}
		check := `
const cases=[['GET',{}, {},'203.0.113.10',200],['HEAD',{}, {},'203.0.113.10',200],['POST',{}, {},'203.0.113.10',405],['GET',{}, {},'198.51.100.8',403],['GET',{}, {x:{value:'x'}},'203.0.113.10',400],['GET',{range:{value:'bytes=0-1'}},{},'203.0.113.10',400]];
let body;
for (const [method,headers,querystring,ip,status] of cases) {
 headers['x-agent-pdf-origin']={value:'spoofed-secret'};
 headers['payment-signature']={value:'sensitive-signature'};
 const request={method,uri:'/readme',headers,querystring};
 Object.defineProperty(request,'body',{get(){throw Error('body read')}});
 const result=handler({viewer:{ip},request});
 if(result===request||result.statusCode!==status)throw Error('origin reached or incorrect gate');
 if(result.body.includes('spoofed-secret')||result.body.includes('sensitive-signature'))throw Error('header leaked');
 if(status===200){
  if(result.headers['content-type'].value!=='text/markdown; charset=utf-8'||result.headers['x-content-type-options'].value!=='nosniff')throw Error('unsafe headers');
  if(method==='HEAD'&&result.body!=='')throw Error('HEAD body emitted');
  if(method==='GET')body=result.body;
 }
}
console.log(body);
`
		raw, err := exec.Command("node", "-e", code+check).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", mode, err, raw)
		}
		if string(raw) != serviceinfo.Markdown()+"\n" {
			t.Fatal("edge Markdown differs from canonical file")
		}
	}
}
