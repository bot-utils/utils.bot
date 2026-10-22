#!/usr/bin/env python3
"""Serial synthetic transform validation; stdout metrics only, no AWS calls."""
import json
import os
import re
import subprocess
import uuid

import local_trial

LABEL = 'utils.bot.transform.validation'
OPS = ('trim', 'lower', 'upper', 'replace')


def validate(value, mib, op):
    keys = {'status','operation','mib','rows','input_bytes','logical_bytes','encoded_bytes',
            'logical_sha256','encoded_sha256','fixture_seconds','worker_seconds','verification_seconds',
            'scope','go_version','unicode_version','process_peak_rss_bytes'}
    if (not isinstance(value,dict) or set(value)!=keys or value['status']!='ok' or
            value['mib']!=mib or value['operation']!=op or value['unicode_version']!='15.0.0' or
            value['scope']!='synthetic_only_provider_cleanup_and_billing_separate' or
            not re.fullmatch(r'go[0-9.]+',value['go_version'])):
        raise RuntimeError('invalid_metrics')
    import math
    for key in ('mib','rows','input_bytes','logical_bytes','encoded_bytes','process_peak_rss_bytes'):
        if type(value[key]) is not int or value[key]<0:raise RuntimeError('invalid_metrics')
    for key in ('fixture_seconds','worker_seconds','verification_seconds'):
        if type(value[key]) not in (int,float) or not math.isfinite(value[key]) or value[key]<0:raise RuntimeError('invalid_metrics')
    for key in ('logical_sha256','encoded_sha256'):
        if not isinstance(value[key],str) or not re.fullmatch(r'[a-f0-9]{64}',value[key]):raise RuntimeError('invalid_metrics')
    if not (mib*(1<<20)-4096 <= value['input_bytes'] <= mib*(1<<20) and
            0 < value['rows'] <= 10_000_000 and 0 < value['encoded_bytes'] <= 2<<30 and
            0 < value['logical_bytes'] <= 2<<30):raise RuntimeError('invalid_metrics')
    return value


def run(sizes=(16,128,1024)):
    if not sizes or len(set(sizes))!=len(sizes) or any(n not in (1,16,128,1024) for n in sizes):
        raise ValueError('invalid_sizes')
    local_trial._endpoint=local_trial.local_endpoint()
    image=local_trial.docker(['image','inspect','--format','{{.Id}}','utils-bot-csv-transform:local']).stdout.strip()
    if not re.fullmatch(r'sha256:[a-f0-9]{64}',image):raise RuntimeError('invalid_image')
    label=uuid.uuid4().hex;owned=[];results=[]
    selector='label='+LABEL+'='+label
    def cleanup():
        for name in owned:
            subprocess.run(['docker','--host',local_trial._endpoint,'kill',name],capture_output=True,timeout=10)
        local_trial.docker(['container','prune','--force','--filter',selector])
        local_trial.docker(['volume','prune','--all','--force','--filter',selector])
        if (local_trial.docker(['ps','--all','--filter',selector,'--format','{{.Names}}']).stdout.strip() or
                local_trial.docker(['volume','ls','--filter',selector,'--format','{{.Name}}']).stdout.strip()):
            raise RuntimeError('cleanup_unconfirmed')
        owned.clear()
    def create(args, memory='2g', volume=None, ipc='none'):
        name='utils-transform-'+label+'-'+uuid.uuid4().hex[:8];owned.append(name)
        if volume is None:
            volume=name;local_trial.docker(['volume','create','--label',LABEL+'='+label,volume])
        local_trial.docker(['create','--name',name,'--label',LABEL+'='+label,'--network=none','--ipc='+ipc,
            '--read-only','--user=10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges',
            '--pids-limit=32','--ulimit=core=0','--log-driver=none','--cpus=1','--memory='+memory,
            '--memory-swap='+memory,'--mount','type=volume,source='+volume+',target=/work',image,*args])
        return name,volume
    def attach(name,timeout=900):
        return subprocess.run(['docker','--host',local_trial._endpoint,'start','--attach',name],
                              stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout)
    def state(name):
        return json.loads(local_trial.docker(['inspect','--format','{{json .State}}',name]).stdout)
    try:
        name,_=create(['--probe','isolation']);out=attach(name,10)
        probe=json.loads(out.stdout)
        expected={'credentials_absent','exec_denied','ipv4_socket_denied','ipv6_socket_denied',
                  'nonroot','process_spawn_denied','root_readonly','unix_socket_denied','private_writable_work','uring_denied','foreign_fd_denied'}
        if set(probe)!=expected or not all(v is True for v in probe.values()) or state(name)['ExitCode']!=0:
            raise RuntimeError('isolation_probe_failed')
        print(json.dumps(dict(isolation=probe,scope='local_only')),flush=True);cleanup()
        for mib in sizes:
            for op in OPS:
                name,_=create(['--mib',str(mib),'--op',op]);out=attach(name)
                actual=state(name)
                if actual['Running'] or actual['ExitCode']!=0 or actual['OOMKilled'] or len(out.stdout)>4096:
                    raise RuntimeError('worker_failed')
                result=validate(json.loads(out.stdout),mib,op);results.append(result)
                print(json.dumps(dict(result,local_image=image,scope='local_only')),flush=True);cleanup()
        for scenario in ('late-expansion','output-limit','write-failure'):
            name,volume=create(['--mib','1','--op','replace','--scenario',scenario]);out=attach(name,20)
            if state(name)['Running'] or state(name)['ExitCode']==0 or json.loads(out.stdout)!={'status':'failed','code':{'late-expansion':'cell_limit','output-limit':'output_byte_limit','write-failure':'output_unavailable'}[scenario]}:
                raise RuntimeError('failure_scenario_not_rejected')
            check,_=create(['--probe','artifacts'],volume=volume);out=attach(check,10)
            if state(check)['ExitCode']!=0 or json.loads(out.stdout)!={'published_absent':True,'partial_present':True}:
                raise RuntimeError('partial_result_published')
            print(json.dumps(dict(scenario=scenario,no_published_result=True,scope='local_only')),flush=True);cleanup()
        name,volume=create(['--mib','1','--op','replace','--scenario','enospc-injected'])
        out=attach(name,20);value=json.loads(out.stdout)
        if (state(name)['ExitCode']!=1 or value.get('enospc_injected') is not True or value.get('published_absent') is not True or
                value.get('shm_status') not in {'absent','not_tmpfs','oversized','not_writable','unavailable','supported'}):raise RuntimeError('injected_enospc_not_observed')
        expected=dict(status='failed',code='output_unavailable',enospc_injected=True,published_absent=True,shm_status=value['shm_status'])
        if value!=expected:raise RuntimeError('invalid_injected_metrics')
        check,_=create(['--probe','artifacts'],volume=volume);out=attach(check,10)
        if json.loads(out.stdout)!={'published_absent':True,'partial_present':True}:raise RuntimeError('partial_result_published')
        print(json.dumps(dict(scenario='explicit_enospc_injection',no_published_result=True,scope='local_only')),flush=True);cleanup()
        name,_=create(['--mib','1','--op','trim','--scenario','fs-full'],ipc='private')
        out=attach(name,20)
        expected=dict(status='failed',code='output_unavailable',enospc_observed=True,published_absent=True)
        if state(name)['ExitCode']!=1 or json.loads(out.stdout)!=expected:raise RuntimeError('enospc_not_observed')
        print(json.dumps(dict(scenario='controlled_private_tmpfs_enospc',enospc_observed=True,no_published_result=True,scope='local_only')),flush=True);cleanup()
        for mode,memory in [('wait','2g'),('oom','128m')]:
            name,volume=create(['--probe',mode],memory)
            if mode=='wait':
                try:attach(name,1)
                except subprocess.TimeoutExpired:pass
                else:raise RuntimeError('wait_probe_returned')
                local_trial.docker(['kill','--signal=KILL',name])
            else:attach(name,20)
            actual=state(name)
            if actual['Running'] or actual['ExitCode']==0 or (mode=='oom' and not actual['OOMKilled']):
                raise RuntimeError('termination_not_confirmed')
            check,_=create(['--probe','artifacts'],volume=volume);out=attach(check,10)
            if state(check)['ExitCode']!=0 or json.loads(out.stdout)!={'published_absent':True,'partial_present':True}:raise RuntimeError('partial_result_published')
            print(json.dumps(dict(scenario=mode,termination_confirmed=True,oom_killed=actual['OOMKilled'],scope='local_only')),flush=True);cleanup()
    finally:
        cleanup();print(json.dumps(dict(cleanup_confirmed=True,no_aws_calls=True)),flush=True)
    return results


if __name__=='__main__':run()
