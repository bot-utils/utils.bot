package edge

import (
	"os/exec"
	"testing"

	"pdfservice/internal/protocol"
)

func TestLegacyEdgePriceHintsAndCorrectedBackendQuoteAgree(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node needed for local JS execution")
	}
	cfg, _ := protocol.NewConfig(protocol.ModeBase, "0x2222222222222222222222222222222222222222")
	code, err := CodeWithConfig("https://utils.bot/v1/pdf/text", "203.0.113.10", cfg)
	if err != nil {
		t.Fatal(err)
	}
	check := `
for (const [size,amount] of [[undefined,'10000'],[26214400,'10000'],[26214401,'20000'],[104857600,'20000']]) {
 const headers={}; if(size!==undefined)headers['content-length']={value:String(size)};
 const request={method:'POST',uri:'/v1/pdf/text',headers,querystring:{}};
 Object.defineProperty(request,'body',{get(){throw Error('body read at edge')}});
 const r=handler({viewer:{ip:'203.0.113.10'},request});
 const body=JSON.parse(r.body), header=JSON.parse(Buffer.from(r.headers['payment-required'].value,'base64').toString('utf8'));
 if(r.statusCode!==402 || body.accepts[0].amount!==amount || JSON.stringify(body)!==JSON.stringify(header))throw Error('incorrect quote');
}
`
	if raw, err := exec.Command("node", "-e", edgeLogCapture+code+check).CombinedOutput(); err != nil {
		t.Fatalf("edge price parity: %v %s", err, raw)
	}
}
