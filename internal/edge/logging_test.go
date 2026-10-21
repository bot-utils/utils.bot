package edge

import (
	"os/exec"
	"strings"
	"testing"
)

// Keep the runtime's diagnostic channel separate from the test result printed
// on stdout. Reject unexpected fields rather than blindly discarding logs.
const edgeLogCapture = `
const edgeTestLogMessages=[];
const edgeOriginalLog=console.log.bind(console);
console.log=(...args)=>{
 if(typeof args[0]==='string' && args[0].startsWith('telemetry=summary')){
  if(args.length!==1 || !/^telemetry=summary role=edge outcome=(response|payment_rejected|quote_issued) status=[0-9]{3} code=[a-z_]+$/.test(args[0]))throw Error('unsafe edge telemetry');
  edgeTestLogMessages.push(args[0]);return;
 }
 edgeOriginalLog(...args);
};
`

func TestEdgeTelemetryContainsOnlyFixedOperationalCategories(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node unavailable")
	}
	code, err := Code("https://utils.bot/v1/pdf/text", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	script := `
const headers={'cookie':{value:'private-cookie-canary'},authorization:{value:'private-authorization-canary'}};
handler({viewer:{ip:'203.0.113.10'},request:{method:'POST',uri:'/v1/pdf/text',headers:{...headers},querystring:{}}});
handler({viewer:{ip:'203.0.113.10'},request:{method:'POST',uri:'/v1/pdf/text',headers:{...headers,'payment-signature':{value:'private-proof-canary',multiValue:[{value:'a'},{value:'b'}]}},querystring:{}}});
handler({viewer:{ip:'203.0.113.10'},request:{method:'GET',uri:'/private-path-canary',headers:{...headers},querystring:{}}});
if(edgeTestLogMessages.length!==3 || !edgeTestLogMessages.some(x=>x.includes('outcome=quote_issued')) || !edgeTestLogMessages.some(x=>x.includes('outcome=payment_rejected')))throw Error('operational outcome missing');
if(edgeTestLogMessages.some(x=>x.includes('canary')||x.includes('203.0.113.10')))throw Error('private data in telemetry');
`
	out, err := exec.Command("node", "-e", edgeLogCapture+code+script).CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}
	if strings.Contains(string(out), "canary") || strings.Contains(string(out), "203.0.113.10") {
		t.Fatal("unstructured diagnostic leaked customer data")
	}
}
