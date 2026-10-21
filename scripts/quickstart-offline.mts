// Synthetic quote, local signer, no outbound network or funded settlement.
import { readFile, writeFile } from 'node:fs/promises';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverTypedDataAddress } from 'viem';
const key = `0x${'01'.repeat(32)}` as `0x${string}`;
process.env.EVM_PRIVATE_KEY = key;
await writeFile('document.pdf', '%PDF-1.7\nsynthetic quickstart fixture');
const pdf = await readFile('document.pdf');
const payTo = `0x${'2'.repeat(40)}`;
const asset = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const quote = {x402Version:2,resource:{url:'https://api.utils.bot/v1/pdf/text',description:'Synthetic fixture',mimeType:'application/json'}, accepts:[{scheme:'exact',network:'eip155:8453',amount:'10000',asset,payTo,maxTimeoutSeconds:60,extra:{name:'USD Coin',version:'2'}}]};
let calls=0;
globalThis.fetch = async(input,init) => {
 const request = new Request(input,init);
 calls++;
 if(request.url!==quote.resource.url||request.method!=='POST'||request.headers.get('Content-Type')!=='application/pdf'||!Buffer.from(await request.arrayBuffer()).equals(pdf))throw Error('Request or replay changed');
 if(calls===1){if(request.headers.has('PAYMENT-SIGNATURE'))throw Error('Initial request already signed');return new Response(JSON.stringify(quote),{status:402,headers:{'PAYMENT-REQUIRED':Buffer.from(JSON.stringify(quote)).toString('base64'),'Content-Type':'application/json'}});}
 if(calls!==2)throw Error('Unexpected network call');
 const proof=JSON.parse(Buffer.from(request.headers.get('PAYMENT-SIGNATURE')!,'base64').toString());
 const {authorization,signature}=proof.payload;
 if(authorization.to.toLowerCase()!==payTo||authorization.value!=='10000'||proof.accepted.network!=='eip155:8453')throw Error('Quote mismatch');
 const address=await recoverTypedDataAddress({domain:{name:'USD Coin',version:'2',chainId:8453,verifyingContract:asset},types:{TransferWithAuthorization:[{name:'from',type:'address'},{name:'to',type:'address'},{name:'value',type:'uint256'},{name:'validAfter',type:'uint256'},{name:'validBefore',type:'uint256'},{name:'nonce',type:'bytes32'}]},primaryType:'TransferWithAuthorization',message:authorization,signature});
 if(address.toLowerCase()!==privateKeyToAccount(key).address.toLowerCase())throw Error('Invalid signature');
 return new Response(JSON.stringify({pageCount:1,pages:[{index:0,text:'Hello, agent.'}],truncated:false}),{status:200,headers:{'Content-Type':'application/json','PAYMENT-RESPONSE':Buffer.from(JSON.stringify({success:true,transaction:'0x'+'b'.repeat(64),network:'eip155:8453'})).toString('base64')}});
};
await import('./client.ts');
for(let n=0;n<100&&calls<2;n++)await new Promise(r=>setTimeout(r,10));
if(calls!==2||process.exitCode)throw Error('Quickstart did not complete');
console.log(JSON.stringify({offlineQuickstartPassed:true,httpCalls:calls,fundedSettlements:0}));
