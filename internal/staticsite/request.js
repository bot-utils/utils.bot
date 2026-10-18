function reply(status,code,extra) {
 var h={'content-type':{value:'application/json'},'cache-control':{value:'no-store'},'x-content-type-options':{value:'nosniff'},'x-robots-tag':{value:config.public?'index, follow':'noindex, nofollow'}};
 if(extra)for(var key in extra)h[key]={value:extra[key]};
 return {statusCode:status,headers:h,body:JSON.stringify({error:code})};
}
function representation(value) {
 if(!value || value.trim()==='' || value.trim()==='*/*')return 'html';
 var candidates=['yaml','json','html'],media=['application/yaml','application/json','text/html'],best='',bestQ=0;
 for(var i=0;i<candidates.length;i++) {
  var specificity=-1,quality=0,parts=value.toLowerCase().split(',');
  for(var j=0;j<parts.length;j++) {
   var fields=parts[j].trim().split(';'),type=fields[0].trim(),q=1,valid=true;
   for(var k=1;k<fields.length;k++) {var p=fields[k].trim().split('=');if(p[0]==='q'){q=Number(p[1]);if(!p[1]||!isFinite(q)||q<0||q>1)valid=false;}}
   if(!valid)continue;
   var score=-1;
   if(type===media[i] || (i<2 && type==='application/vnd.oai.openapi+'+candidates[i]))score=2;
   else if(type===media[i].split('/')[0]+'/*')score=1;
   else if(type==='*/*')score=0;
   if(score>specificity || (score===specificity && q>quality)){specificity=score;quality=q;}
  }
  if(specificity>=0 && quality>bestQ){best=candidates[i];bestQ=quality;}
 }
 return best;
}
function handler(event) {
 var r=event.request;
 if(!config.public && (!event.viewer || event.viewer.ip!==config.owner))return reply(403,'not_public');
 var uri=r.uri,api=uri==='/v1/pdf/text';
 if(r.headers.accept && r.headers.accept.value.length>512)return reply(400,'accept_header_too_large');
 if(uri!=='/health' && !api && !Object.prototype.hasOwnProperty.call(config.routes,uri))return reply(404,'not_found');
 if(r.method!=='GET' && r.method!=='HEAD' && !(api&&r.method==='POST'))return reply(405,'method_not_allowed',{allow:api?'GET, HEAD, POST':'GET, HEAD'});
 if(Object.keys(r.querystring||{}).length || /%/.test(uri))return reply(400,'noncanonical_request_url');
 if(r.headers.range || r.headers['if-range'])return reply(400,'range_not_supported');
 if(api && r.method==='POST')return reply(307,'use_regional_api',{location:config.api});
 if(r.headers['transfer-encoding'] || (r.headers['content-length'] && r.headers['content-length'].value!=='0'))return reply(400,'unexpected_request_body');
 var route=config.routes[uri];
 if(uri==='/' || api) {
  var format=representation(r.headers.accept?r.headers.accept.value:'');
  if(!format)return reply(406,'unsupported_representation');
  if(format==='html' && api)return reply(308,'documentation',{location:'/docs'});
  route=config.routes[format==='html'?'/':format==='json'?'@json':'@yaml'];
 }
 // Origin receives only a fixed object key (or /health), no viewer cookies,
 // signatures, query parameters or viewer-supplied identity/authorization headers.
 var host=r.headers.host;
 r.headers=host?{host:host}:{};r.cookies={};
 if(uri==='/health')return r;
 if(route.redirect)return reply(308,'canonical_documentation',{location:route.redirect});
 r.uri='/'+route.key;
 return r;
}
