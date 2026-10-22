import copy
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

import cloud_control as shared
import transform_control as control
import transform_local
from test_cloud_control import FakeAWS


class TransformControlTests(unittest.TestCase):
    def root(self):
        root=Path(tempfile.mkdtemp(prefix='utils-transform-test-'));root.chmod(0o700)
        self.addCleanup(lambda:subprocess.run(['trash',str(root)],check=True,capture_output=True))
        return root
    def lease(self):
        aws=FakeAWS()
        aws.saved=[{'cleanup_confirmed':True,'reservation':{'total_reserved_usd':'1.078039'}}]
        lease=control.Lease(aws,self.root())
        lease.claim(control.plan('a'*64),{'synthetic':'baseline'})
        return aws,lease
    def test_ten_fixed_cases_no_role_or_public_ip(self):
        plan=control.plan('a'*64)
        self.assertEqual(plan['max_jobs'],10)
        self.assertEqual(plan['max_concurrency'],1)
        self.assertNotIn('taskRoleArn',plan['task_definition'])
        self.assertEqual(plan['run_network']['awsvpcConfiguration']['assignPublicIp'],'DISABLED')
        self.assertEqual([c['kind'] for c in plan['cases'][:5]],['isolation','trim','lower','upper','replace'])
        self.assertEqual(plan['cases'][-1]['expect'],'stopped')
    def test_network_template_only_adds_three_reviewed_endpoints(self):
        original={'Resources':{'Kept':{'Type':'AWS::EC2::VPC','Properties':{'CidrBlock':'10.88.0.0/24'}}},'Outputs':{'Kept':{'Value':'synthetic'}}}
        before=copy.deepcopy(original);after=control.endpoints(original)
        self.assertEqual(original,before)
        self.assertEqual(after['Outputs'],original['Outputs'])
        for key in control.ENDPOINT_IDS:
            props=after['Resources'].pop(key)['Properties']
            self.assertEqual(props['VpcId'],control.VPC)
            self.assertEqual(props['SecurityGroupIds'],[control.ENDPOINT_GROUP])
            self.assertTrue(props['PrivateDnsEnabled'])
        self.assertEqual(after,original)
        with self.assertRaises(shared.TrialFailure):control.endpoints(control.endpoints(original))
    def test_lease_reserves_before_dispatch_and_cannot_repeat_case(self):
        aws,lease=self.lease()
        self.assertTrue(aws.calls[1][2][aws.calls[1][2].index('--key')+1]==control.KEY)
        self.assertNotEqual(control.KEY,shared.KEY)
        self.assertEqual(lease.state['reservation']['jobs'],10)
        self.assertEqual(lease.state['reservation']['total_reserved_usd'],'2.000000')
        lease.state['phase']='executing';lease.save()
        case=control.plan('a'*64)['cases'][0];job=lease.reserve(case)
        self.assertEqual(aws.saved[-1]['jobs'][0]['state'],'submission_reserved')
        with self.assertRaises(shared.TrialFailure):lease.reserve(case)
        job['state']='verified';lease.save()
        with self.assertRaises(shared.TrialFailure):lease.reserve(case)
    def test_previous_unclean_or_over_budget_trial_blocks_claim(self):
        for legacy in [{'cleanup_confirmed':False,'reservation':{'total_reserved_usd':'1'}},
                       {'cleanup_confirmed':True,'reservation':{'total_reserved_usd':'4'}}]:
            aws=FakeAWS();aws.saved=[legacy];lease=control.Lease(aws,self.root())
            with self.assertRaises(shared.TrialFailure):lease.claim(control.plan('a'*64),{})
            self.assertEqual(len(aws.saved),1)
    def test_uncertain_start_is_reconciled_never_resubmitted(self):
        _,lease=self.lease();calls=[]
        def aws(service,action,*args):
            calls.append(action)
            if action=='list-tasks':return {'taskArns':['synthetic-task']}
            if action=='describe-tasks':return {'tasks':[{'startedBy':'owned','taskDefinitionArn':'definition','taskArn':'synthetic-task'}]}
            raise AssertionError(action)
        controller=control.Controller(aws,lease,control.plan('a'*64));controller.definition='definition'
        job={'token':'owned'};controller.reconcile(job)
        self.assertEqual(job['id'],'synthetic-task')
        self.assertNotIn('run-task',calls)
        controller.aws=lambda *args:{'taskArns':[]}
        with self.assertRaises(shared.TrialFailure):controller.reconcile({'token':'missing'})
    def test_canonical_network_state_does_not_depend_on_list_order(self):
        self.assertEqual(control.canonical({'rules':[{'port':443},{'port':80}]}),control.canonical({'rules':[{'port':80},{'port':443}]}))

    def test_failed_or_uncertain_first_task_stops_all_later_dispatch(self):
        for failure in ('submission','execution'):
            _,lease=self.lease();calls=[]
            wanted=control.plan('a'*64)
            def aws(service,action,*args):
                calls.append(action)
                if action=='describe-repositories':return {'repositories':[]}
                if action in ('create-cluster','create-repository'):return {}
                if action=='register-task-definition':return {'taskDefinition':{'taskDefinitionArn':'definition'}}
                if action=='run-task':
                    self.assertEqual(lease.state['jobs'][0]['state'],'submission_reserved')
                    if failure=='submission':raise shared.TrialFailure('aws_request_uncertain')
                    return {'tasks':[{'taskArn':shared.TASK_PREFIX+'synthetic'}]}
                raise AssertionError(action)
            class FakeController(control.Controller):
                def template(self):return {'Resources':{}}
                def update(self,body):pass
                def upload(self):pass
                def admission(self):pass
                def wait_job(self,job):raise shared.TrialFailure('task_failed')
                def cleanup(self):self.cleaned=True
            controller=FakeController(aws,lease,wanted);controller.cleaned=False
            with patch.object(control,'iam'),patch.object(control.cloud_network,'read',return_value={'failures':['paid_endpoints_not_ready']}):
                with self.assertRaises(shared.TrialFailure):controller.run()
            self.assertTrue(controller.cleaned)
            self.assertEqual(calls.count('run-task'),1)
            self.assertEqual(len(lease.state['jobs']),1)
            self.assertEqual(lease.state['phase'],'failed')
            self.assertEqual(lease.state['reservation']['total_reserved_usd'],'2.000000')


if __name__=='__main__':unittest.main()
