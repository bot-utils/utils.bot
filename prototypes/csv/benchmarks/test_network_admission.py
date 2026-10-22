import copy
import unittest
from datetime import datetime, timezone, timedelta
from network_admission import network_failures, phase_one_failures


ACCOUNT = '111111111111'
EXPECTED = dict(account_id=ACCOUNT, vpc_id='vpc-trial', subnet_id='subnet-trial',
                default_sg_id='sg-default', fargate_sg_id='sg-parser', glue_sg_id='sg-glue',
                endpoint_sg_id='sg-endpoint', route_table_id='rtb-trial',
                s3_prefix_list_id='pl-s3', dns_group_id='dns-trial')


def baseline():
    e = EXPECTED
    role = lambda name: 'arn:aws:iam::' + ACCOUNT + ':role/utils-bot-csv-trial-' + name
    def statement(actions, resources, identity=None):
        row = dict(Effect='Allow', Principal='*', Action=actions, Resource=resources)
        if identity:
            row['Condition'] = {'ArnEquals': {'aws:PrincipalArn': identity}}
        return row
    policies = {
        's3': [statement(['s3:GetObject'], ['arn:aws:s3:::prod-us-east-2-starport-layer-bucket/*']),
               statement(['s3:GetObject'], ['arn:aws:s3:::utils-bot-csv-trial-' + ACCOUNT + '-us-east-2/trial/code/*'], role('glue')),
               statement(['s3:GetBucketLocation'], ['arn:aws:s3:::utils-bot-csv-trial-' + ACCOUNT + '-us-east-2'], role('glue'))],
        'ecr': [statement(['ecr:GetAuthorizationToken'], ['*'], role('ecs-execution')),
                statement(['ecr:BatchCheckLayerAvailability', 'ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage'],
                          ['arn:aws:ecr:us-east-2:' + ACCOUNT + ':repository/utils-bot-csv-trial'], role('ecs-execution'))],
        'logs': [statement(['logs:CreateLogStream', 'logs:PutLogEvents'],
                           ['arn:aws:logs:us-east-2:' + ACCOUNT + ':log-group:/utils-bot/csv-trial:log-stream:*'], role('ecs-execution')),
                 statement(['logs:CreateLogStream', 'logs:PutLogEvents'],
                           ['arn:aws:logs:us-east-2:' + ACCOUNT + ':log-group:/aws-glue/python-jobs/' + n + ':log-stream:*' for n in ('output', 'error')], role('glue'))]}
    endpoints = []
    for kind in ('s3', 'ecr.api', 'ecr.dkr', 'logs'):
        row = dict(VpcEndpointId='vpce-' + kind, ServiceName='com.amazonaws.us-east-2.' + kind,
                   VpcId=e['vpc_id'], State='available',
                   PolicyDocument={'Version': '2012-10-17', 'Statement': copy.deepcopy(policies['ecr' if kind.startswith('ecr') else kind])})
        if kind == 's3':
            row.update(VpcEndpointType='Gateway', RouteTableIds=[e['route_table_id']])
        else:
            row.update(VpcEndpointType='Interface', SubnetIds=[e['subnet_id']],
                       Groups=[dict(GroupId=e['endpoint_sg_id'])], PrivateDnsEnabled=True, IpAddressType='ipv4')
        endpoints.append(row)
    pair = lambda group, start=443, end=443: dict(IpProtocol='tcp', FromPort=start, ToPort=end,
                                                 UserIdGroupPairs=[dict(GroupId=group, UserId=ACCOUNT)])
    s3 = dict(IpProtocol='tcp', FromPort=443, ToPort=443, PrefixListIds=[dict(PrefixListId=e['s3_prefix_list_id'])])
    groups = []
    for group, inbound, outbound in [
        (e['fargate_sg_id'], [], [pair(e['endpoint_sg_id']), s3]),
        (e['glue_sg_id'], [pair(e['glue_sg_id'], 0, 65535)], [pair(e['glue_sg_id'], 0, 65535), pair(e['endpoint_sg_id']), s3]),
        (e['endpoint_sg_id'], [pair(e['fargate_sg_id']), pair(e['glue_sg_id'])], [])]:
        groups.append(dict(GroupId=group, VpcId=e['vpc_id'], Tags=[dict(Key='Purpose', Value='utils-bot-csv-trial')],
                           IpPermissions=inbound, IpPermissionsEgress=outbound))
    allowed = ['api.ecr.us-east-2.amazonaws.com', ACCOUNT + '.dkr.ecr.us-east-2.amazonaws.com',
               'logs.us-east-2.amazonaws.com', 's3.us-east-2.amazonaws.com',
               's3-r-w.us-east-2.amazonaws.com',
               'utils-bot-csv-trial-' + ACCOUNT + '-us-east-2.s3.us-east-2.amazonaws.com',
               'prod-us-east-2-starport-layer-bucket.s3.us-east-2.amazonaws.com']
    return dict(checked_at=datetime.now(timezone.utc).isoformat(), cleanup_confirmed=True, active_owned_workers=[], network_interfaces=[],
                nontrial_dns_associations_before=[], nontrial_dns_associations_after=[],
                vpc=dict(VpcId=e['vpc_id'], State='available', CidrBlock='10.88.0.0/24',
                         Tags=[dict(Key='Purpose', Value='utils-bot-csv-trial')]),
                subnet=dict(SubnetId=e['subnet_id'], VpcId=e['vpc_id'], MapPublicIpOnLaunch=False, State='available'),
                default_security_group=dict(GroupId=e['default_sg_id'], VpcId=e['vpc_id'], GroupName='default',
                                            IpPermissions=[], IpPermissionsEgress=[]),
                default_sg_network_interfaces=[], firewall_config=dict(FirewallFailOpen='DISABLED'),
                dns_association=dict(VpcId=e['vpc_id'], FirewallRuleGroupId=e['dns_group_id'], Status='COMPLETE', Priority=101),
                dns_rules=[dict(Action='ALLOW', Priority=100, FirewallDomainListId='allow', FirewallDomainRedirectionAction='INSPECT_REDIRECTION_DOMAIN'),
                           dict(Action='BLOCK', Priority=200, FirewallDomainListId='block', FirewallDomainRedirectionAction='INSPECT_REDIRECTION_DOMAIN', BlockResponse='NODATA')],
                dns_domains={'allow': allowed, 'block': ['*']}, worker_security_groups=groups,
                production_connections=[], public_addresses=[], endpoints=endpoints,
                route_tables=[dict(RouteTableId=e['route_table_id'], VpcId=e['vpc_id'],
                                   Associations=[dict(SubnetId=e['subnet_id'])],
                                   Routes=[dict(DestinationCidrBlock='10.88.0.0/24', GatewayId='local', State='active'),
                                           dict(DestinationPrefixListId=e['s3_prefix_list_id'], GatewayId='vpce-s3', State='active')])])


class AdmissionTests(unittest.TestCase):
    def test_private_exact_binding_is_accepted(self):
        self.assertEqual(network_failures(baseline(), EXPECTED), [])

    def test_bucket_metadata_permission_cannot_read_other_buckets_or_objects(self):
        for action, resource in [('s3:GetObject', 'arn:aws:s3:::*'),
                                 ('s3:GetBucketLocation', 'arn:aws:s3:::*')]:
            row = baseline()
            metadata = row['endpoints'][0]['PolicyDocument']['Statement'][2]
            metadata.update(Action=[action], Resource=[resource])
            self.assertIn('endpoint_policy_not_reviewed', network_failures(row, EXPECTED))

    def test_dns_root_dot_matches_the_same_exact_name_only(self):
        row = baseline()
        row['dns_domains'] = {key: [name + '.' for name in names] for key, names in row['dns_domains'].items()}
        self.assertEqual(network_failures(row, EXPECTED), [])
        row['endpoints'] = row['endpoints'][:1]
        self.assertEqual(phase_one_failures(row, EXPECTED), [])
        for changed in ('api.ecr.us-east-2.amazonaws.com..', '*.amazonaws.com.', ' api.ecr.us-east-2.amazonaws.com.'):
            changed_row = baseline(); changed_row['dns_domains']['allow'][0] = changed
            self.assertIn('dns_allowlist_not_verified', network_failures(changed_row, EXPECTED))

    def test_reserved_association_priority_is_rejected(self):
        row = baseline(); row['dns_association']['Priority'] = 100
        self.assertIn('dns_allowlist_not_verified', network_failures(row, EXPECTED))

    def test_default_group_requires_exact_identity_empty_rules_and_no_attachments(self):
        for key, value in [('GroupId', 'sg-other'), ('VpcId', 'vpc-other'), ('IpPermissions', [{}]), ('IpPermissionsEgress', [{}])]:
            row = baseline(); row['default_security_group'][key] = value
            self.assertIn('default_security_group_not_hardened', network_failures(row, EXPECTED))
        row = baseline(); row['default_sg_network_interfaces'] = [{'NetworkInterfaceId': 'eni-unexpected'}]
        self.assertIn('default_security_group_in_use_or_unknown', network_failures(row, EXPECTED))

    def test_phase_one_cannot_dispatch(self):
        row = baseline(); row['endpoints'] = row['endpoints'][:1]
        self.assertIn('paid_endpoints_not_ready', network_failures(row, EXPECTED))
        self.assertEqual(phase_one_failures(row, EXPECTED), [])

    def test_dns_public_routes_and_cleanup_fail_closed(self):
        row = baseline(); row['firewall_config']['FirewallFailOpen'] = 'ENABLED'
        self.assertIn('dns_not_fail_closed', network_failures(row, EXPECTED))
        row = baseline(); row['cleanup_confirmed'] = False
        self.assertIn('cleanup_unknown', network_failures(row, EXPECTED))
        row = baseline(); row['checked_at'] = (datetime.now(timezone.utc)-timedelta(seconds=45)).isoformat()
        self.assertIn('stale_network_readback', network_failures(row, EXPECTED))
        row = baseline(); row['dns_domains']['allow'].append('*.amazonaws.com')
        self.assertIn('dns_allowlist_not_verified', network_failures(row, EXPECTED))
        for route in [dict(DestinationCidrBlock='0.0.0.0/0', GatewayId='igw-other', State='active'),
                      dict(DestinationIpv6CidrBlock='::/0', GatewayId='eigw-other', State='active')]:
            row = baseline(); row['route_tables'][0]['Routes'].append(route)
            self.assertIn('unapproved_route', network_failures(row, EXPECTED))

    def test_endpoint_and_worker_access_cannot_be_broadened(self):
        row = baseline(); row['endpoints'][1]['PolicyDocument']['Statement'][1]['Action'] = ['ecr:*']
        self.assertIn('endpoint_policy_not_reviewed', network_failures(row, EXPECTED))
        row = baseline(); row['endpoints'][1]['SubnetIds'] = ['subnet-other']
        self.assertIn('interface_endpoint_binding', network_failures(row, EXPECTED))
        row = baseline(); row['worker_security_groups'][0]['IpPermissionsEgress'].append(
            dict(IpProtocol='-1', IpRanges=[dict(CidrIp='0.0.0.0/0')]))
        self.assertIn('worker_rules_not_verified', network_failures(row, EXPECTED))

    def test_cdk_placeholder_is_rejected_after_hardening(self):
        row = baseline(); row['worker_security_groups'][2]['IpPermissionsEgress'] = [
            dict(IpProtocol='icmp', FromPort=252, ToPort=86, IpRanges=[dict(CidrIp='255.255.255.255/32')])]
        self.assertIn('worker_rules_not_verified', network_failures(row, EXPECTED))
        row['endpoints'] = row['endpoints'][:1]
        self.assertEqual(phase_one_failures(row, EXPECTED), [])

    def test_preparation_accepts_only_standard_or_empty_default_rules(self):
        row = baseline(); row['endpoints'] = row['endpoints'][:1]
        group = row['default_security_group']
        group['IpPermissions'] = [dict(IpProtocol='-1', UserIdGroupPairs=[dict(GroupId=EXPECTED['default_sg_id'], UserId=ACCOUNT)])]
        group['IpPermissionsEgress'] = [dict(IpProtocol='-1', IpRanges=[dict(CidrIp='0.0.0.0/0')])]
        self.assertEqual(phase_one_failures(row, EXPECTED), [])
        group['IpPermissions'].append(dict(IpProtocol='-1', IpRanges=[dict(CidrIp='0.0.0.0/0')]))
        self.assertIn('unexpected_initial_default_sg_rules', phase_one_failures(row, EXPECTED))
        row = baseline(); row['endpoints'] = row['endpoints'][:1]; row['network_interfaces'] = [{'id':'eni-unexpected'}]
        self.assertIn('preparation_has_network_interfaces_or_unknown', phase_one_failures(row, EXPECTED))

    def test_preparation_dummy_is_endpoint_egress_only(self):
        row = baseline(); row['endpoints'] = row['endpoints'][:1]
        row['worker_security_groups'][0]['IpPermissionsEgress'].append(
            dict(IpProtocol='icmp', FromPort=252, ToPort=86, IpRanges=[dict(CidrIp='255.255.255.255/32')]))
        self.assertIn('worker_rules_not_verified', phase_one_failures(row, EXPECTED))

    def test_nontrial_dns_changes_are_rejected(self):
        row = baseline(); row['nontrial_dns_associations_after'] = [dict(Id='foreign', VpcId='vpc-production')]
        self.assertIn('nontrial_dns_association_changed', network_failures(row, EXPECTED))

    def test_missing_readback_is_denied(self):
        self.assertTrue(network_failures({}, EXPECTED))


if __name__ == '__main__':
    unittest.main()
