function reply(status, code, extra) {
    var outcome = code === 'invalid_payment_header' || code === 'ambiguous_content_headers' ? 'payment_rejected' : 'response';
    console.log('telemetry=summary role=edge outcome=' + outcome + ' status=' + status + ' code=' + code);
    var headers = {
        'content-type': { value: 'application/json' },
        'cache-control': { value: 'no-store' },
        'x-content-type-options': { value: 'nosniff' }
    };
    if (extra) {
        for (var key in extra) { headers[key] = { value: extra[key] }; }
    }
    return { statusCode: status, headers: headers, body: JSON.stringify({ error: code }) };
}

function handler(event) {
    var request = event.request;
    if (!config.public && (!event.viewer || event.viewer.ip !== config.ownerIP)) {
        return reply(403, 'not_public');
    }
    var uri = request.uri;
    if (config.routes.indexOf(uri) === -1) { return reply(404, 'not_found'); }
    var api = uri === '/v1/pdf/text';
    var allow = api ? 'GET, HEAD, POST' : 'GET, HEAD';
    if (request.method !== 'GET' && request.method !== 'HEAD' && !(api && request.method === 'POST')) {
        return reply(405, 'method_not_allowed', { allow: allow });
    }
    if (Object.keys(request.querystring || {}).length) {
        return reply(400, 'unsupported_query_parameters');
    }
    var headers = request.headers;
    if (headers.range || headers['if-range']) {
        return reply(400, 'range_not_supported');
    }
    if (api && request.method === 'POST' && config.apiResource) {
        return reply(307, 'use_regional_api', { location: config.apiResource });
    }
    // The origin authentication token is supplied by CloudFront, never viewers.
    delete headers['x-agent-pdf-origin'];
    // Documents are static origin objects, not embedded into the 10 KiB
    // viewer function. Their size must not grow this function's code.
    if (!api) {
        delete headers['payment-signature'];
        delete headers.authorization;
        delete headers.cookie;
    }
    if (!api || request.method !== 'POST') { return request; }
    var payment = headers['payment-signature'];
    if (!payment || !payment.value || !payment.value.trim()) {
        var large = headers['content-length'] && /^(0|[1-9][0-9]*)$/.test(headers['content-length'].value) && Number(headers['content-length'].value) > config.smallPDFLimit;
        var quote = config.quoteJSON;
        if (large) {
            var parsed = JSON.parse(quote);
            parsed.accepts[0].amount = config.largeAmount;
            quote = JSON.stringify(parsed);
        }
        console.log('telemetry=summary role=edge outcome=quote_issued status=402 code=none');
        return {
            statusCode: 402,
            headers: {
                'content-type': { value: 'application/json' },
                'cache-control': { value: 'no-store' },
                'x-content-type-options': { value: 'nosniff' },
                'x-payment-mode': { value: config.paymentMode },
                'payment-required': { value: Buffer.from(quote).toString('base64') },
                link: { value: '</openapi>; rel="service-desc"; type="application/yaml"' }
            },
            body: quote
        };
    }
    if ((payment.multiValue && payment.multiValue.length !== 1) || payment.value.length > config.maxPaymentHeader || payment.value.indexOf(',') !== -1) {
        return reply(400, 'invalid_payment_header');
    }
    var names = ['content-type', 'content-encoding', 'content-length'];
    for (var index = 0; index < names.length; index++) {
        var name = names[index];
        var header = headers[name];
        if (header && header.multiValue && header.multiValue.length !== 1) {
            return reply(400, 'ambiguous_content_headers');
        }
    }
    var type = headers['content-type'];
    if (!type || type.value.split(';')[0].trim().toLowerCase() !== 'application/pdf') {
        return reply(415, 'application_pdf_required');
    }
    var encoding = headers['content-encoding'];
    if (encoding && encoding.value !== 'identity') { return reply(415, 'unsupported_content_encoding'); }
    var length = headers['content-length'];
    if (length) {
        if (!/^(0|[1-9][0-9]*)$/.test(length.value)) { return reply(400, 'invalid_content_length'); }
        if (Number(length.value) > config.maxPDF) { return reply(413, 'pdf_too_large'); }
    }
    return request;
}
