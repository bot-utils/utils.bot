function reply(status, error, extra) {
    console.log('telemetry=summary role=edge outcome=response status='+status+' code='+error);
    var h = {'content-type':{value:'application/json'},'cache-control':{value:'no-store'},'x-content-type-options':{value:'nosniff'}};
    if (extra) { h.allow = {value:extra}; }
    return {statusCode:status,headers:h,body:JSON.stringify({error:error})};
}
function handler(event) {
    var r=event.request;
    if (!config.public && (!event.viewer || event.viewer.ip!==config.ownerIP)) { return reply(403,'not_public'); }
    var doc;
    if (config.documents) {
        if (Object.prototype.hasOwnProperty.call(config.documents,r.uri)) { doc=config.documents[r.uri]; }
    } else if(r.uri===config.route) { doc={body:config.body,contentType:'text/markdown; charset=utf-8'}; }
    if (!doc) { return reply(404,'not_found'); }
    if (r.method!=='GET' && r.method!=='HEAD') { return reply(405,'method_not_allowed','GET, HEAD'); }
    if (Object.keys(r.querystring||{}).length) { return reply(400,'unsupported_query_parameters'); }
    if (r.headers.range || r.headers['if-range']) { return reply(400,'range_not_supported'); }
    return {statusCode:200,headers:{'content-type':{value:doc.contentType},'cache-control':{value:'public, max-age=300'},'x-robots-tag':{value:config.public?'index, follow':'noindex, nofollow'},'x-content-type-options':{value:'nosniff'},'referrer-policy':{value:'no-referrer'},'content-security-policy':{value:"default-src 'none'; frame-ancestors 'none'"},link:{value:'</openapi>; rel="service-desc"; type="application/yaml"'}},body:r.method==='HEAD'?'':doc.body};
}
