package edge

import (
	"os/exec"
	"pdfservice/internal/protocol"
	"strings"
	"testing"
)

func TestReadmeUsesStaticOriginAndDoesNotReadBody(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node unavailable")
	}
	code, err := CodeWithConfig("https://utils.bot/v1/pdf/text", "203.0.113.10", protocol.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(code, "readmeMarkdown") || len(code) > 10<<10 {
		t.Fatal("document inlined into edge code")
	}
	check := `
for(const [method,querystring,headers,ip,status] of [['GET',{}, {},'203.0.113.10',0],['HEAD',{}, {},'203.0.113.10',0],['POST',{}, {},'203.0.113.10',405],['GET',{}, {},'198.51.100.8',403],['GET',{x:{value:'x'}},{},'203.0.113.10',400],['GET',{}, {range:{value:'bytes=0-1'}},'203.0.113.10',400]]) {
 headers['x-agent-pdf-origin']={value:'spoofed'};headers['payment-signature']={value:'private'};headers.authorization={value:'private'};headers.cookie={value:'private'};
 const request={method,uri:'/readme',headers,querystring};Object.defineProperty(request,'body',{get(){throw Error('body read')}});
 const result=handler({viewer:{ip},request});
 if((result.statusCode||0)!==status)throw Error('gate changed');
 if(status===0 && (result!==request || Object.keys(result.headers).some(x=>['x-agent-pdf-origin','payment-signature','authorization','cookie'].includes(x))))throw Error('static request leaked credentials');
}`
	if out, err := exec.Command("node", "-e", edgeLogCapture+code+check).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
}
