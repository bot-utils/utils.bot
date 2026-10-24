"""One-shot isolated Fargate validation. Never touches the live service or IAM.

Operational state is saved conditionally before resource creation and each task.
Uncertain starts stop dispatch; cleanup reconciles exact tokens, never retries work.
No CloudFormation template or policy document is written to disk.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid
from decimal import Decimal

import cloud_control as shared
import cloud_network
import large_plan
import network_admission
import network_costs
import transform_local

ACCOUNT=shared.ACCOUNT
NAME=shared.NAME
BUCKET=shared.BUCKET
KEY='trial/control/transform-validation-v1.json'
COMPLETION_KEY='trial/control/transform-controls-completion-v1.json'
PARENT_PLAN_SHA='2952b5fb698e4397e4488a7637b1e1fdc9909c0ec328478b9a9fb1d6ad96a7e5'
PARENT_WORKER_SHA='4976502347db2585717f1515e44089f813a4ceb9b898d5b14729a3dc682957de'
STACK='UtilsBotCsvTrialNetwork'
VPC='vpc-05be93e77ca1e1d3d'
SUBNET='subnet-0d1659853364bcb35'
GROUP='sg-08db78af120f1a6b6'
ENDPOINT_GROUP='sg-06879e2a3ef8c8d29'
ROLE='arn:aws:iam::'+ACCOUNT+':role/'+NAME+'-network-execution'
EXECUTION_HASH='5a69eb3d448a4c73ee497a6f637baf1b433222e7a5b6997a96444b938fe2e853'
PROBE_KEYS={'credentials_absent','exec_denied','ipv4_socket_denied','ipv6_socket_denied','nonroot','process_spawn_denied','root_readonly','unix_socket_denied','private_writable_work','uring_denied','foreign_fd_denied'}
# Independent local 1 GiB evidence; the cloud must reproduce the same bytes.
EXPECTED_LARGE={
 'trim':('45a61dc6c71eb91a864d49d182b4905c1aa6a27be666339ad5423215c4bbfdd4','fb85066d0f0addce678cf953beda5179fe7e6a09e2259f3845af21b858d126a4'),
 'lower':('ccf5b3b73f33456561f4f345c7d35eb7ef14fc57e297da08365fb8a08bb5d670','591ca0124902e91041c221115ba6489e0d0bc0b1ac31307132af2b9dc00024f5'),
 'upper':('feeafbd80389d5953f994f1e13c9c2fc20c7fde24f49b40895ae2e4673bd7d44','d1f0358bdda4e17058563b7ac7e3d53abc8bf9a65915e2b652fe08875296d26c'),
 'replace':('e683b670860dffaf151f27e982e6a142d9cb4c4513b3e91d25b53c9179ef80ee','5323ef9c9f729d80d7f97d2963d959a33ecd7617420ae0d524e3ecffa657e548'),
}

ENDPOINT_IDS=('TransformValidationEcrApi','TransformValidationEcrDocker','TransformValidationLogs')


def plan(digest,mode="initial"):
    result=large_plan.build(ACCOUNT,SUBNET,GROUP,digest)
    container=result['task_definition']['containerDefinitions'][0]
    container['name']='transform-trial'
    container['logConfiguration']['options']['awslogs-stream-prefix']='transform'
    cases=[dict(kind='isolation',command=['--probe','isolation'],expect='ok')]
    cases += [dict(kind=op,command=['--mib','1024','--op',op],expect='ok') for op in transform_local.OPS]
    cases += [dict(kind=scenario,command=['--mib','1','--op','replace','--scenario',scenario],expect='failure',code=code)
              for scenario,code in [('late-expansion','cell_limit'),('output-limit','output_byte_limit'),('fs-full','output_unavailable')]]
    cases += [dict(kind='oom',command=['--probe','oom'],expect='oom'),dict(kind='wait',command=['--probe','wait'],expect='stopped')]
    result.update(max_jobs=10,cases=cases,scope='synthetic transform validation only')
    result.pop('overrides')
    if mode=='remaining-controls':
        result['cases']=[dict(kind='enospc-injected',command=['--mib','1','--op','replace','--scenario','enospc-injected'],expect='failure',code='output_unavailable')]+cases[-2:]
        result.update(max_jobs=3,scope='finish unattempted OOM/cancellation and a supported injected ENOSPC check; never rerun the failed tmpfs task')
    elif mode!='initial':raise ValueError('invalid_mode')
    return result


def endpoints(template):
    body=copy.deepcopy(template)
    if any(key in body['Resources'] for key in ENDPOINT_IDS):raise shared.TrialFailure('endpoint_resources_already_present')
    def statement(actions,resources,suffix):
        return dict(Effect='Allow',Principal='*',Action=actions,Resource=resources,
                    Condition={'ArnEquals':{'aws:PrincipalArn':'arn:aws:iam::'+ACCOUNT+':role/'+NAME+'-'+suffix}})
    execution=statement(['ecr:GetAuthorizationToken'],['*'],'ecs-execution')
    pull=statement(['ecr:BatchCheckLayerAvailability','ecr:GetDownloadUrlForLayer','ecr:BatchGetImage'],
                   ['arn:aws:ecr:us-east-2:'+ACCOUNT+':repository/'+NAME],'ecs-execution')
    logs=[statement(['logs:CreateLogStream','logs:PutLogEvents'],['arn:aws:logs:us-east-2:'+ACCOUNT+':log-group:/utils-bot/csv-trial:log-stream:*'],'ecs-execution'),
          statement(['logs:CreateLogStream','logs:PutLogEvents'],['arn:aws:logs:us-east-2:'+ACCOUNT+':log-group:/aws-glue/python-jobs/'+v+':log-stream:*' for v in ('output','error')],'glue')]
    for logical,service,statements in zip(ENDPOINT_IDS,('ecr.api','ecr.dkr','logs'),([execution,pull],[execution,pull],logs)):
        policy=dict(Version='2012-10-17',Statement=statements)
        if not network_admission.endpoint_policy_ok(policy,service,ACCOUNT):raise shared.TrialFailure('invalid_endpoint_policy')
        body['Resources'][logical]=dict(Type='AWS::EC2::VPCEndpoint',Properties=dict(
            VpcId=VPC,VpcEndpointType='Interface',PrivateDnsEnabled=True,
            SubnetIds=[SUBNET],SecurityGroupIds=[ENDPOINT_GROUP],ServiceName='com.amazonaws.us-east-2.'+service,
            PolicyDocument=policy,Tags=[dict(Key='Project',Value='utils-bot'),dict(Key='Purpose',Value=NAME)]))
    return body


def reservation(jobs=10):
    if jobs not in (3,10):raise ValueError("invalid_job_count")
    result=network_costs.estimate()
    costs=result['cost_usd'];costs.pop('six_tier_workers')
    rates=network_costs.catalog().pinned
    workers=(rates['arm_cpu']+2*rates['arm_memory'])*Decimal(jobs)/3
    costs['transform_workers']=str(workers)
    total='1.000000' if jobs==3 else '2.000000'
    result.update(jobs=jobs,total_reserved_usd=total,scope='bounded serial synthetic transform validation tasks')
    if sum(Decimal(v) for v in costs.values())>Decimal(total):raise shared.TrialFailure('cost_reservation')
    return result


class Lease:
    def __init__(self,aws,directory,mode="initial"):
        if mode not in ("initial","remaining-controls"):raise ValueError("invalid_mode")
        self.mode=mode;self.key=KEY if mode=="initial" else COMPLETION_KEY
        self.aws=aws;self.directory=Path(directory);self.etag=None
        info=self.directory.stat()
        if not self.directory.is_dir() or self.directory.is_symlink() or info.st_uid!=os.getuid() or info.st_mode&0o077:
            raise shared.TrialFailure('invalid_evidence_directory')
        self.state=None
    def claim(self,wanted,protected):
        if self.state is not None or (self.directory/'ledger.json').exists():raise shared.TrialFailure('ledger_reuse')
        legacy=self.directory/'previous-trial.json'
        self.aws.call('s3api','get-object','--bucket',BUCKET,'--key',shared.KEY,str(legacy))
        old=json.loads(legacy.read_text())
        if old.get('cleanup_confirmed') is not True:raise shared.TrialFailure('previous_trial_cleanup_unconfirmed')
        previous=Decimal(old['reservation']['total_reserved_usd'])
        if not previous.is_finite() or previous<0:raise shared.TrialFailure('invalid_previous_reservation')
        parent_evidence={}
        if self.mode=='remaining-controls':
            path=self.directory/'parent-cohort.json'
            self.aws.call('s3api','get-object','--bucket',BUCKET,'--key',KEY,str(path))
            parent=json.loads(path.read_text());jobs=parent.get('jobs',[])
            expected=['isolation','trim','lower','upper','replace','late-expansion','output-limit','fs-full']
            if (parent.get('phase')!='failed' or parent.get('cleanup_confirmed') is not True or
                    parent.get('plan_sha256')!=PARENT_PLAN_SHA or parent.get('worker_source_sha256')!=PARENT_WORKER_SHA or
                    parent.get('protected')!=protected or [j.get('kind') for j in jobs]!=expected or
                    any(j.get('state')!='verified' for j in jobs[:-1]) or
                    jobs[-1].get('state')!='terminal_unverified' or jobs[-1].get('exit_code')!=1 or jobs[-1].get('provider_terminal')!='STOPPED' or
                    jobs[-1].get('observed_metrics')!={'status':'failed','code':'transform_trial_failed'} or
                    parent.get('reconciliation',{}).get('task_terminal_confirmed') is not True or
                    parent.get('reconciliation',{}).get('protected_unchanged') is not True):
                raise shared.TrialFailure('parent_cohort_not_reconciled')
            amount=Decimal(parent['reservation']['total_reserved_usd'])
            if not amount.is_finite() or amount<0:raise shared.TrialFailure('invalid_parent_reservation')
            previous+=amount
            parent_evidence=dict(key=KEY,sha256=shared.document_hash(parent),attempts=8,unverified_case='fs-full',no_retry=True)
        reserved=reservation(wanted['max_jobs'])
        if previous+Decimal(reserved['total_reserved_usd'])>5:raise shared.TrialFailure('cumulative_trial_budget')
        self.state=dict(schema_version=1,trial_id=uuid.uuid4().hex,phase='claimed',jobs=[],
                        controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),worker_source_sha256=source_hash(),
                        plan_sha256=shared.document_hash(wanted),max_jobs=wanted['max_jobs'],parent_evidence=parent_evidence,reservation=reserved,previous_reservation_usd=str(previous),
                        cleanup_confirmed=False,billing_confirmed=False,protected=protected)
        self.save(first=True)
    def save(self,first=False):
        path=self.directory/'ledger.json';path.write_text(json.dumps(self.state,sort_keys=True));path.chmod(0o600)
        condition=['--if-none-match','*'] if first else ['--if-match',self.etag]
        self.etag=self.aws.call('s3api','put-object','--bucket',BUCKET,'--key',self.key,'--body',str(path),
                                '--server-side-encryption','AES256',*condition)['ETag']
    def reserve(self,case):
        jobs=self.state['jobs']
        if self.state['phase']!='executing' or len(jobs)>=self.state['max_jobs'] or (jobs and jobs[-1]['state']!='verified'):
            raise shared.TrialFailure('dispatch_not_admitted')
        if any(job['kind']==case['kind'] for job in jobs):raise shared.TrialFailure('duplicate_case')
        job=dict(case,token='trfm'+uuid.uuid4().hex,state='submission_reserved');jobs.append(job);self.save();return job


def canonical(value):
    if isinstance(value,dict):return {k:canonical(v) for k,v in value.items()}
    if isinstance(value,list):return sorted((canonical(v) for v in value),key=lambda v:json.dumps(v,sort_keys=True))
    return value


def source_hash():
    root=Path(__file__).resolve().parents[1]
    repo=root.parent.parent
    paths=[root/'go.mod',root/'benchmarks/Dockerfile.transform',repo/'go.mod']
    for directory in (repo/'internal/csvtabular',repo/'internal/csvguard',root/'cmd/csv-transform-trial'):
        paths.extend(p for p in directory.glob('*.go') if not p.name.endswith('_test.go'))
    return shared.document_hash({p.relative_to(repo).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)})


def local_image(digest):
    local_trial=transform_local.local_trial
    local_trial._endpoint=local_trial.local_endpoint()
    image=json.loads(local_trial.docker(['image','inspect','sha256:'+digest]).stdout)[0]
    config=image['Config']
    if (image['Id']!='sha256:'+digest or image['Architecture']!='arm64' or image['Os']!='linux' or
            config['User']!='10001:10001' or config['Entrypoint']!=['/csv-transform-trial'] or
            set(config['Env'])!={'PATH=/nonexistent','GOMEMLIMIT=128MiB','GOMAXPROCS=1'} or
            config.get('Cmd') or config.get('Volumes')!={'/work':{}} or
            config.get('Labels',{}).get('utils.bot.transform.source')!=source_hash()):
        raise shared.TrialFailure('local_image_or_source_drift')
    return local_trial


def protected(aws):
    service=aws('ecs','describe-services','--cluster','agent-pdf-mock','--services','agent-pdf-mock')['services'][0]
    data=dict(service={k:service[k] for k in ('desiredCount','taskDefinition','deploymentConfiguration','networkConfiguration')},networks={})
    subnets=service['networkConfiguration']['awsvpcConfiguration']['subnets']
    live={v['VpcId'] for v in aws('ec2','describe-subnets','--subnet-ids',*subnets)['Subnets']}
    default={v['VpcId'] for v in aws('ec2','describe-vpcs','--filters','Name=is-default,Values=true')['Vpcs']}
    if len(live)!=1 or len(default)!=1 or VPC in live|default:raise shared.TrialFailure('protected_network_discovery_failed')
    for vpc in live|default:
        data['networks'][vpc]={action:aws('ec2',action,'--filters','Name=vpc-id,Values='+vpc) for action in ('describe-route-tables','describe-security-groups','describe-subnets')}
    distributions=aws('cloudfront','list-distributions').get('DistributionList',{}).get('Items',[])
    ids=[v['Id'] for v in distributions if 'utils.bot' in v.get('Aliases',{}).get('Items',[])]
    if len(ids)!=1:raise shared.TrialFailure('protected_distribution_discovery_failed')
    # Hash only; never persist the CloudFront origin headers.
    cf=aws('cloudfront','get-distribution-config','--id',ids[0])
    return dict(config_sha256=shared.document_hash(canonical(data)),cloudfront_sha256=shared.document_hash(canonical(cf)))


def iam(aws):
    role=aws('iam','get-role','--role-name',NAME+'-ecs-execution')['Role']
    if role.get('PermissionsBoundary',{}).get('PermissionsBoundaryArn')!=shared.BOUNDARY:raise shared.TrialFailure('boundary_drift')
    version=aws('iam','get-policy','--policy-arn',shared.BOUNDARY)['Policy']['DefaultVersionId']
    boundary=aws('iam','get-policy-version','--policy-arn',shared.BOUNDARY,'--version-id',version)['PolicyVersion']['Document']
    inline=aws('iam','get-role-policy','--role-name',NAME+'-ecs-execution','--policy-name','CsvTrialOnly')['PolicyDocument']
    if shared.document_hash(boundary)!=shared.BOUNDARY_HASH or shared.document_hash(inline)!=EXECUTION_HASH:raise shared.TrialFailure('iam_drift')
    if aws('iam','list-attached-role-policies','--role-name',NAME+'-ecs-execution')['AttachedPolicies'] or aws('iam','list-role-policies','--role-name',NAME+'-ecs-execution')['PolicyNames']!=['CsvTrialOnly']:
        raise shared.TrialFailure('unexpected_role_policy')


class Controller:
    def __init__(self,aws,lease,wanted):
        self.aws=aws;self.lease=lease;self.plan=wanted;self.definition=None;self.original=None;self.current=None
    def template(self):
        body=self.aws('cloudformation','get-template','--stack-name',STACK)['TemplateBody']
        return json.loads(body) if isinstance(body,str) else body
    def wait_stack(self):
        deadline=time.monotonic()+1200;last=None
        while time.monotonic()<deadline:
            status=self.aws('cloudformation','describe-stacks','--stack-name',STACK)['Stacks'][0]['StackStatus']
            if status!=last:print(json.dumps(dict(stack_status=status)),flush=True);last=status
            if not status.endswith('_IN_PROGRESS'):return status
            time.sleep(10)
        raise shared.TrialFailure('network_stack_deadline')
    def update(self,body):
        self.aws('cloudformation','update-stack','--stack-name',STACK,'--role-arn',ROLE,
                 '--template-body',json.dumps(body),'--client-request-token','transform-'+uuid.uuid4().hex)
        if self.wait_stack()!='UPDATE_COMPLETE':raise shared.TrialFailure('network_update_failed')
    def absent(self):
        deadline=time.monotonic()+300
        while time.monotonic()<deadline:
            interfaces=self.aws('ec2','describe-network-interfaces','--filters','Name=vpc-id,Values='+VPC)['NetworkInterfaces']
            endpoints=self.aws('ec2','describe-vpc-endpoints','--filters','Name=vpc-id,Values='+VPC)['VpcEndpoints']
            endpoint_ids={v for p in endpoints for v in p.get('NetworkInterfaceIds',[])}
            if not [v for v in interfaces if v['NetworkInterfaceId'] not in endpoint_ids]:return
            time.sleep(10)
        raise shared.TrialFailure('worker_interface_cleanup_unconfirmed')
    def admission(self):
        iam(self.aws)
        digest=self.plan['task_definition']['containerDefinitions'][0]['image'].split('@sha256:')[1]
        local_image(digest)
        self.aws('ecr','describe-images','--repository-name',NAME,'--image-ids','imageDigest=sha256:'+digest)
        if protected(self.aws)!=self.lease.state['protected']:raise shared.TrialFailure('protected_configuration_changed')
        shared.check_definition(self.plan['task_definition'],self.aws('ecs','describe-task-definition','--task-definition',self.definition)['taskDefinition'])
        observed=cloud_network.read(self.aws)
        if observed['failures']:raise shared.TrialFailure('network_admission_failed')
    def reconcile(self,job):
        if job.get('id'):return
        candidates=[]
        for state in ('RUNNING','STOPPED'):
            candidates+=self.aws('ecs','list-tasks','--cluster',NAME,'--desired-status',state,'--max-items','100')['taskArns']
        candidates=sorted(set(candidates))
        if candidates:
            tasks=self.aws('ecs','describe-tasks','--cluster',NAME,'--tasks',*candidates)['tasks']
            found=[v for v in tasks if v.get('startedBy')==job['token'] and v.get('taskDefinitionArn')==self.definition]
            if len(found)==1:job['id']=found[0]['taskArn'];return
        raise shared.TrialFailure('submission_uncertain_manual_reconciliation_required')
    def wait_job(self,job):
        deadline=time.monotonic()+1200;stop_requested=False
        while time.monotonic()<deadline:
            response=self.aws('ecs','describe-tasks','--cluster',NAME,'--tasks',job['id'])
            if response.get('failures') or len(response.get('tasks',[]))!=1:raise shared.TrialFailure('task_observation_uncertain')
            task=response['tasks'][0]
            if task['lastStatus']=='RUNNING' and job['expect']=='stopped' and not stop_requested:
                time.sleep(2);self.aws('ecs','stop-task','--cluster',NAME,'--task',job['id'],'--reason','controlled transform cancellation validation');stop_requested=True
            if task['lastStatus']=='STOPPED':
                container=task['containers'][0];exit_code=container.get('exitCode')
                if job['expect']=='ok' and exit_code!=0:raise shared.TrialFailure('task_failed')
                if job['expect']=='failure' and exit_code!=1:raise shared.TrialFailure('failure_not_observed')
                if job['expect']=='oom' and (exit_code!=137 or 'memory' not in container.get('reason','').lower()):raise shared.TrialFailure('oom_not_observed')
                if job['expect']=='stopped' and (not stop_requested or exit_code==0):raise shared.TrialFailure('cancellation_not_observed')
                job['provider']={k:task.get(k) for k in ('createdAt','pullStartedAt','pullStoppedAt','startedAt','executionStoppedAt','stoppedAt','cpu','memory','stopCode','stoppedReason')}
                job['exit_code']=exit_code;return
            time.sleep(5)
        raise shared.TrialFailure('task_deadline')
    def metrics(self,job):
        if job['expect'] in ('oom','stopped'):return {'provider_failure_verified':True}
        stream='transform/transform-trial/'+job['id'].split('/')[-1]
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            try:data=self.aws('logs','get-log-events','--log-group-name','/utils-bot/csv-trial','--log-stream-name',stream,'--start-from-head','--limit','100')
            except shared.TrialFailure:
                time.sleep(5);continue
            messages=[v['message'] for v in data['events']]
            if messages:
                if len(messages)!=1 or len(messages[0])>4096:raise shared.TrialFailure('unexpected_logs')
                value=json.loads(messages[0])
                if job['kind']=='isolation':
                    if set(value)!=PROBE_KEYS or not all(v is True for v in value.values()):raise shared.TrialFailure('isolation_failed')
                elif job['expect']=='failure':
                    expected={'status':'failed','code':job['code']}
                    if job['kind']=='fs-full':
                        if value.get('enospc_observed') is not True or value.get('published_absent') is not True:raise shared.TrialFailure('unverified_enospc')
                        expected.update(enospc_observed=True,published_absent=True)
                    if job['kind']=='enospc-injected':
                        if value.get('enospc_injected') is not True or value.get('published_absent') is not True:raise shared.TrialFailure('unverified_enospc_injection')
                        if value.get('shm_status') not in {'absent','not_tmpfs','oversized','not_writable','unavailable','supported'}:raise shared.TrialFailure('invalid_filesystem_diagnostic')
                        expected.update(enospc_injected=True,published_absent=True,shm_status=value['shm_status'])
                    if value!=expected:raise shared.TrialFailure('unexpected_failure_metrics')
                else:
                    transform_local.validate(value,1024,job['kind'])
                    if (value['logical_sha256'],value['encoded_sha256'])!=EXPECTED_LARGE[job['kind']] or value['go_version']!='go1.26.10' or value['rows']!=1095112 or value['input_bytes']!=1073741336:raise shared.TrialFailure('local_cloud_oracle_mismatch')
                return value
            time.sleep(5)
        raise shared.TrialFailure('metrics_missing')
    def run(self):
        state=self.lease.state
        try:
            self.original=self.template();self.current=endpoints(self.original)
            state.update(original_template_sha256=shared.document_hash(self.original),runtime_created=False,network_requested=False)
            self.lease.save()
            iam(self.aws)
            before=cloud_network.read(self.aws,allow_removed_runtime=True)
            if before['failures']!=['paid_endpoints_not_ready']:raise shared.TrialFailure('initial_network_state_not_clean')
            if any(v['repositoryName']==NAME for v in self.aws('ecr','describe-repositories')['repositories']):raise shared.TrialFailure('repository_already_present')
            state['phase']='network_preparing';state['network_requested']=True;self.lease.save()
            self.update(self.current)
            state['phase']='runtime_preparing';state['runtime_created']=True;self.lease.save()
            self.aws('ecs','create-cluster','--cluster-name',NAME,'--settings',json.dumps([dict(name='containerInsights',value='disabled')]),'--tags',json.dumps([dict(key='Project',value='utils-bot'),dict(key='Purpose',value=NAME)]))
            # Registry image is prepared only after this controller claims its lease.
            self.aws('ecr','create-repository','--repository-name',NAME,'--image-tag-mutability','IMMUTABLE','--tags',json.dumps([dict(Key='Project',Value='utils-bot'),dict(Key='Purpose',Value=NAME)]))
            self.upload()
            self.definition=self.aws('ecs','register-task-definition','--cli-input-json',json.dumps(self.plan['task_definition']))['taskDefinition']['taskDefinitionArn']
            state['definition']=self.definition;state['phase']='executing';self.lease.save()
            for case in self.plan['cases']:
                self.admission();job=self.lease.reserve(case)
                request=dict(cluster=NAME,taskDefinition=self.definition,launchType='FARGATE',platformVersion='1.4.0',count=1,
                             clientToken=job['token'],startedBy=job['token'],enableExecuteCommand=False,
                             networkConfiguration=self.plan['run_network'],
                             overrides={'containerOverrides':[{'name':'transform-trial','command':case['command']}]},
                             tags=[dict(key='Project',value='utils-bot'),dict(key='Purpose',value=NAME)])
                submitted=self.aws('ecs','run-task','--cli-input-json',json.dumps(request))
                if submitted.get('failures') or len(submitted.get('tasks',[]))!=1:raise shared.TrialFailure('task_start_uncertain')
                job['id']=submitted['tasks'][0]['taskArn']
                if not job['id'].startswith(shared.TASK_PREFIX):raise shared.TrialFailure('unexpected_task_identity')
                job['state']='submitted';self.lease.save();self.wait_job(job)
                job['metrics']=self.metrics(job);self.absent();job['state']='verified';self.lease.save()
                print(json.dumps(dict(kind=job['kind'],state='verified',metrics=job['metrics'])),flush=True)
            state['phase']='complete';self.lease.save()
        except Exception:
            state['phase']='failed';raise
        finally:
            self.cleanup()
    def upload(self):
        digest=self.plan['task_definition']['containerDefinitions'][0]['image'].split('@sha256:')[1]
        local=local_image(digest)
        registry=ACCOUNT+'.dkr.ecr.us-east-2.amazonaws.com'
        tag=registry+'/'+NAME+':transform-'+self.lease.state['worker_source_sha256'][:16]
        local.docker(['tag','sha256:'+digest,tag])
        root=Path(tempfile.mkdtemp(prefix='ecr-helper-',dir=self.lease.directory));root.chmod(0o700)
        try:
            (root/'config.json').write_text(json.dumps({'credHelpers':{registry:'utils-transform'}}))
            helper=root/'docker-credential-utils-transform'
            helper.write_text("#!/usr/bin/env python3\nimport json,subprocess,sys\n"+
                "if len(sys.argv)!=2 or sys.argv[1]!='get':sys.exit(1)\n"+
                "host=sys.stdin.read().strip().removeprefix('https://')\n"+
                "if host!="+repr(registry)+":sys.exit(1)\n"+
                "p=subprocess.run(['aws','ecr','get-login-password','--region','us-east-2'],capture_output=True)\n"+
                "if p.returncode:sys.exit(1)\n"+
                "print(json.dumps({'Username':'AWS','Secret':p.stdout.decode().strip()}))\n")
            helper.chmod(0o700)
            env=dict(os.environ,PATH=str(root)+os.pathsep+os.environ.get('PATH',''),AWS_MAX_ATTEMPTS='1')
            result=subprocess.run(['docker','--host',local._endpoint,'--config',str(root),'push',tag],
                                  env=env,capture_output=True,timeout=180)
            if result.returncode:raise shared.TrialFailure('image_upload_failed')
            self.aws('ecr','describe-images','--repository-name',NAME,'--image-ids','imageDigest=sha256:'+digest)
        finally:subprocess.run(['trash',str(root)],check=True,capture_output=True)
    def cleanup(self):
        state=self.lease.state
        for job in state['jobs']:
            self.reconcile(job)
            task=self.aws('ecs','describe-tasks','--cluster',NAME,'--tasks',job['id'])['tasks'][0]
            if task['lastStatus']!='STOPPED':self.aws('ecs','stop-task','--cluster',NAME,'--task',job['id'],'--reason','owned transform validation cleanup')
        deadline=time.monotonic()+300
        while state['jobs']:
            statuses=self.aws('ecs','describe-tasks','--cluster',NAME,'--tasks',*[job['id'] for job in state['jobs']])
            if statuses.get('failures'):raise shared.TrialFailure('cleanup_task_observation_uncertain')
            if all(v['lastStatus']=='STOPPED' for v in statuses['tasks']):break
            if time.monotonic()>=deadline:raise shared.TrialFailure('task_cleanup_unconfirmed')
            time.sleep(5)
        self.absent()
        if state.get('runtime_created'):
            repositories=self.aws('ecr','describe-repositories')['repositories']
            if any(v['repositoryName']==NAME for v in repositories):self.aws('ecr','delete-repository','--repository-name',NAME,'--force')
            cluster=self.aws('ecs','describe-clusters','--clusters',NAME)['clusters']
            if cluster and cluster[0]['status']=='ACTIVE':self.aws('ecs','delete-cluster','--cluster',NAME)
        if state.get('network_requested'):
            self.wait_stack();actual=self.template()
            if shared.document_hash(actual)==shared.document_hash(self.current):self.update(self.original)
            elif shared.document_hash(actual)!=shared.document_hash(self.original):raise shared.TrialFailure('network_cleanup_drift')
        if protected(self.aws)!=state['protected']:raise shared.TrialFailure('protected_configuration_changed')
        final=cloud_network.read(self.aws,allow_removed_runtime=True)
        if final['failures']!=['paid_endpoints_not_ready'] or len(final['snapshot']['endpoints'])!=1 or final['snapshot']['network_interfaces']:
            raise shared.TrialFailure('final_cleanup_not_verified')
        state['cleanup_confirmed']=True;self.lease.save()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-digest',required=True)
    parser.add_argument('--mode',choices=['initial','remaining-controls'],default='initial')
    args=parser.parse_args()
    wanted=plan(args.image_digest,args.mode)
    local_image(args.image_digest)
    aws=shared.AWS(os.environ)
    iam(aws.call)
    directory=Path(tempfile.mkdtemp(prefix='utils-transform-cloud-',dir='/private/tmp'));directory.chmod(0o700)
    lease=Lease(aws,directory,args.mode)
    lease.claim(wanted,protected(aws.call))
    print(json.dumps(dict(phase='claimed',evidence_directory=str(directory),reservation=lease.state['reservation']['total_reserved_usd'])),flush=True)
    def interrupted(_signum,_frame):raise shared.TrialFailure('controller_interrupted')
    previous={sig:signal.signal(sig,interrupted) for sig in (signal.SIGINT,signal.SIGTERM)}
    try:
        Controller(aws.call,lease,wanted).run()
        print(json.dumps(dict(phase=lease.state['phase'],cleanup_confirmed=lease.state['cleanup_confirmed'],billing_confirmed=False)),flush=True)
    except Exception as error:
        code=str(error) if isinstance(error,shared.TrialFailure) else 'controller_failed'
        print(json.dumps(dict(status='failed',code=code,cleanup_confirmed=lease.state.get('cleanup_confirmed',False))),flush=True)
        return 1
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)
    return 0


if __name__=='__main__':raise SystemExit(main())
