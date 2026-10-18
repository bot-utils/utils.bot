function handler(event) {
 var r=event.response;
 r.headers['x-content-type-options']={value:'nosniff'};
 r.headers['referrer-policy']={value:'no-referrer'};
 r.headers['x-robots-tag']={value:config.public?'index, follow':'noindex, nofollow'};
 r.headers['content-security-policy']={value:"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' "+config.api+"; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'"};
 r.headers.link={value:'</openapi>; rel="service-desc"; type="application/yaml", </readme>; rel="about"; type="text/markdown", </info>; rel="privacy-policy"; type="text/markdown", </terms>; rel="terms-of-service"; type="text/markdown"'};
 // Viewer-facing URLs may select a new immutable object on the next deploy.
 // Do not let browsers retain an outdated quote, legal page or private policy.
 r.headers['cache-control']={value:'no-store'};
 delete r.headers['set-cookie'];
 return r;
}
