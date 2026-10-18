package edge

import (
	"os/exec"
	"testing"

	"pdfservice/internal/protocol"
)

func TestRegionalLegacyPOSTRedirectIsFixedPrivateAndBodyFree(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node required for local JS execution")
	}
	code, err := Code(protocol.APIOrigin+"/v1/pdf/text", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	check := `
for(const signed of [false,true]) {
 const request={method:'POST',uri:'/v1/pdf/text',headers:{'x-agent-pdf-origin':{value:'forged'}},querystring:{}};
 if(signed)request.headers['payment-signature']={value:'fixture'};
 Object.defineProperty(request,'body',{get(){throw Error('body inspected')}});
 const result=handler({viewer:{ip:'203.0.113.10'},request});
 if(result.statusCode!==307 || result.headers.location.value!=='https://api.utils.bot/v1/pdf/text' || result.headers['payment-required'] || result.headers['cache-control'].value!=='no-store')throw Error(JSON.stringify(result));
 if(handler({viewer:{ip:'198.51.100.1'},request}).statusCode!==403)throw Error('private gate bypassed');
}
for(const [method,uri,query,headers,want] of [
 ['PUT','/v1/pdf/text',{}, {},405],['POST','/bad',{}, {},404],
 ['POST','/v1/pdf/text',{bad:{value:'1'}}, {},400],
 ['POST','/v1/pdf/text',{}, {range:{value:'bytes=0-0'}},400]]) {
 const result=handler({viewer:{ip:'203.0.113.10'},request:{method,uri,querystring:query,headers}});
 if(result.statusCode!==want)throw Error(JSON.stringify(result));
}
if(config.paymentRequired!==undefined || config.quoteJSON!=='')throw Error('obsolete quote retained');
const request={method:'GET',uri:'/docs',headers:{'x-agent-pdf-origin':{value:'forged'}},querystring:{}};
const result=handler({viewer:{ip:'203.0.113.10'},request});
if(result!==request || result.headers['x-agent-pdf-origin'])throw Error('website routing or origin protection changed');
`
	if raw, err := exec.Command("node", "-e", code+check).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	for _, url := range []string{protocol.APIOrigin + ":443/v1/pdf/text", protocol.APIOrigin + "/v1/pdf/text?", protocol.APIOrigin + "/v1/pdf/text#fragment", "https://api.utils.bot.evil/v1/pdf/text"} {
		if _, err := Code(url, "203.0.113.10"); err == nil {
			t.Fatal("unsafe redirect resource accepted", url)
		}
	}
}
