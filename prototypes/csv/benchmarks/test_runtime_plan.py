import copy
import unittest
import runtime_plan


class RuntimePlanTests(unittest.TestCase):
    def plan(self):
        return runtime_plan.build('111111111111', 'subnet-' + '1'*17, 'sg-' + '2'*17,
                                  'sg-' + '3'*17, '4'*64, '5'*64, '6'*64)

    def test_only_four_credentialless_fargate_tiers_and_two_bounded_glue_jobs(self):
        plan = self.plan()
        self.assertEqual(plan['max_jobs'], 6)
        self.assertEqual(plan['max_concurrency'], 1)
        self.assertEqual(len(plan['task_definitions']), 4)
        self.assertEqual(len(plan['glue_jobs']), 2)
        self.assertEqual(plan['run_network']['awsvpcConfiguration']['assignPublicIp'], 'DISABLED')
        for task in plan['task_definitions']:
            self.assertNotIn('taskRoleArn', task)
            self.assertEqual(task['requiresCompatibilities'], ['FARGATE'])
            self.assertEqual(task['volumes'], [{'name': 'work'}])
            self.assertEqual(len(task['containerDefinitions']), 1)
            container = task['containerDefinitions'][0]
            self.assertTrue(container['readonlyRootFilesystem'])
            self.assertFalse(container['privileged'])
            self.assertEqual(container['user'], '10001:10001')
            self.assertEqual(container['linuxParameters']['capabilities'], {'drop': ['ALL']})
            self.assertIn('@sha256:', container['image'])
            self.assertNotIn('environment', container)
        for job in plan['glue_jobs']:
            self.assertEqual(job['Timeout'], 15)
            self.assertEqual(job['MaxRetries'], 0)
            self.assertEqual(job['ExecutionProperty']['MaxConcurrentRuns'], 1)
            self.assertEqual(job['Command']['PythonVersion'], '3.9')
            self.assertEqual(job['DefaultArguments']['--library-set'], 'none')
            self.assertNotIn('--additional-python-modules', job['DefaultArguments'])

    def test_code_and_images_are_immutable_and_private_storage_is_required(self):
        plan = self.plan()
        self.assertEqual(set(plan['bucket']['public_access_block'].values()), {True})
        self.assertEqual(plan['bucket']['object_ownership'], 'BucketOwnerEnforced')
        self.assertEqual(plan['repository']['imageTagMutability'], 'IMMUTABLE')
        self.assertEqual(plan['logs']['existing_group_settings'], 'preserve')
        self.assertEqual(plan['cluster']['settings'],
                         [{'name': 'containerInsights', 'value': 'disabled'}])
        for job in plan['glue_jobs']:
            self.assertIn('/trial/code/' + '4'*64 + '/', job['Command']['ScriptLocation'])

    def test_unpinned_or_invalid_ids_and_shared_worker_groups_are_rejected(self):
        values = ['111111111111', 'subnet-' + '1'*17, 'sg-' + '2'*17,
                  'sg-' + '3'*17, '4'*64, '5'*64, '6'*64]
        for index, bad in ((0, '000000000000'), (1, 'subnet-arbitrary'),
                           (4, 'latest'), (5, 'https://outside.example/image'),
                           (6, 'SHA256:' + '6'*64)):
            changed = copy.copy(values); changed[index] = bad
            with self.assertRaises(ValueError):
                runtime_plan.build(*changed)
        changed = copy.copy(values); changed[3] = changed[2]
        with self.assertRaises(ValueError):
            runtime_plan.build(*changed)


if __name__ == '__main__':
    unittest.main()
