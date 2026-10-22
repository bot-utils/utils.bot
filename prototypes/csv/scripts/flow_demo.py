#!/usr/bin/env python3
"""Synthetic loopback client; no SDK, wallet, content output, or funded payment."""
import argparse
import base64
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import time
import urllib.error
import urllib.parse
import urllib.request


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def run(base, key):
    url = urllib.parse.urlsplit(base)
    if (url.scheme != 'http' or not url.hostname or
            not ipaddress.ip_address(url.hostname).is_loopback or url.username or
            url.password or url.query or url.fragment or url.path not in ('', '/')):
        raise ValueError('literal_loopback_origin_required')
    # Never follow a redirect or inherit proxies for capability-bearing requests.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            return None
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    owner = secrets.token_hex(32)

    def call(method, path, body=None, headers=None, expected=200):
        raw = body if isinstance(body, bytes) else compact(body) if body is not None else None
        fields = dict(headers or {})
        if raw is not None:
            fields.setdefault('Content-Type', 'application/json')
        req = urllib.request.Request(base.rstrip('/') + path, data=raw, headers=fields, method=method)
        try:
            response = client.open(req, timeout=45)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = response.read(8 * (1 << 20) + 1)
            if response.status != expected or len(result) > 8 * (1 << 20):
                raise RuntimeError('unexpected_flow_reply')
            return result, response.headers

    def proof(challenge):
        claim = dict(stage=challenge['stage'], owner=owner, nonce=secrets.token_hex(32),
                     resource=challenge['resource'], binding=challenge['binding'],
                     amount=challenge['amount'], expires_at=challenge['expires_at'])
        body = base64.urlsafe_b64encode(compact(claim)).decode().rstrip('=')
        signature = hmac.new(key.encode(), compact(['mock-signature-v1', body]), hashlib.sha256).hexdigest()
        return body + '.' + signature

    fixtures = {
        'dedupe': ({'key_columns': ['id'], 'keep': 'first'},
                   {'file': b'id,v\n1,HELLO\n1,HELLO\n2,WORLD\n'}, b'id,v\n1,HELLO\n2,WORLD\n'),
        'join': ({'left_key_columns': ['id'], 'right_key_columns': ['id'], 'type': 'inner'},
                 {'left': b'id,v\n1,HELLO\n', 'right': b'id,other\n1,YES\n'}, b'id,v,other\n1,HELLO,YES\n'),
        'aggregate': ({'group_columns': [], 'metrics': [{'name': 'count', 'op': 'count_rows'}]},
                      {'file': b'id,v\n1,HELLO\n1,HELLO\n2,WORLD\n'}, b'count\n3\n'),
        'transform': ({'column': 'v', 'op': 'lower'},
                      {'file': b'id,v\n1,HELLO\n2,WORLD\n'}, b'id,v\n1,hello\n2,world\n'),
    }
    for operation, (options, data, expected) in fixtures.items():
        specs = [dict(slot=slot, bytes=len(value), sha256=hashlib.sha256(value).hexdigest(), mode='multipart')
                 for slot, value in data.items()]
        intent = dict(operation=operation, options=options, files=specs, delivery='gzip')
        raw, _ = call('POST', '/csv/uploads', intent, expected=402)
        admission_headers = {'Payment-Signature': proof(json.loads(raw)),
                             'Idempotency-Key': secrets.token_hex(32),
                             'Recovery-Secret': secrets.token_hex(32)}
        raw, _ = call('POST', '/csv/uploads', intent, admission_headers)
        admitted = json.loads(raw)
        # Simulate a lost create response: one identity, same capability, no new job.
        again, _ = call('POST', '/csv/uploads', intent, admission_headers)
        recovered = json.loads(again)
        if (recovered['job_id'], recovered['capability']) != (admitted['job_id'], admitted['capability']):
            raise RuntimeError('create_recovery_changed_identity')
        capability = {'X-Job-Capability': admitted['capability']}
        job = '/csv/jobs/' + admitted['job_id']
        for grant in admitted['grants']:
            start = (grant['part'] - 1) * (4 << 20)
            call('PUT', grant['path'], data[grant['slot']][start:start + grant['bytes']],
                 {'Content-Type': 'application/octet-stream', 'X-Upload-Grant': grant['upload_grant']})
        call('POST', '/csv/uploads/' + admitted['job_id'] + '/finalize', {}, capability)
        call('POST', '/csv/' + operation, {'job_id': admitted['job_id']}, capability, 202)
        deadline = time.monotonic() + 45
        while True:
            raw, _ = call('GET', job, headers=capability)
            status = json.loads(raw)
            if status['artifact_state'] == 'RESULT_PREPARED':
                break
            if status['artifact_state'] not in ('QUEUED', 'RUNNING') or time.monotonic() >= deadline:
                raise RuntimeError('job_not_prepared')
            time.sleep(0.1)
        raw, _ = call('POST', job + '/payment', {}, capability, 402)
        raw, _ = call('POST', job + '/payment', {}, dict(capability, **{'Payment-Signature': proof(json.loads(raw))}))
        paid = json.loads(raw)
        manifest = paid['manifest']
        split = max(1, manifest['encoded_bytes'] // 2)
        chunks = []
        for byte_range in ('bytes=0-' + str(split - 1), 'bytes=' + str(split) + '-'):
            chunk, headers = call('GET', job + '/result.gz', headers=dict(capability, **{
                'Range': byte_range, 'Download-Attempt': secrets.token_hex(32)}), expected=206)
            if headers.get('Content-Encoding'):
                raise RuntimeError('compressed_file_route_was_transcoded')
            chunks.append(chunk)
        encoded = b''.join(chunks)
        if (len(encoded) != manifest['encoded_bytes'] or hashlib.sha256(encoded).hexdigest() != manifest['encoded_sha256']):
            raise RuntimeError('encoded_integrity_failed')
        decoded = gzip.decompress(encoded)
        if (decoded != expected or len(decoded) != manifest['logical_bytes'] or
                hashlib.sha256(decoded).hexdigest() != manifest['logical_sha256']):
            raise RuntimeError('logical_integrity_failed')
        encoded_again, headers = call('GET', job + '/result', headers=dict(capability, **{
            'Accept-Encoding': 'gzip', 'Download-Attempt': secrets.token_hex(32)}))
        if headers.get('Content-Encoding') != 'gzip' or encoded_again != encoded:
            raise RuntimeError('transparent_gzip_route_changed_artifact')
        call('POST', job + '/ack', dict(complete=True, version=manifest['version'],
                                      encoded_sha256=manifest['encoded_sha256']), capability)
        raw, _ = call('GET', job, headers=capability)
        if json.loads(raw)['artifact_state'] != 'ERASED':
            raise RuntimeError('acknowledgement_cleanup_unconfirmed')
        print(json.dumps(dict(operation=operation, status='passed', scope='local_synthetic_no_funds')), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='http://127.0.0.1:18083')
    parser.add_argument('--mock-key-file', required=True)
    args = parser.parse_args()
    path = Path(args.mock_key_file)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError('private_mock_key_required')
        key = os.read(fd, 66).decode().strip()
    finally:
        os.close(fd)
    if len(key) != 64 or bytes.fromhex(key).hex() != key:
        raise ValueError('invalid_mock_key')
    run(args.base, key)


if __name__ == '__main__':
    main()
