"""Fresh read-only admission for the one existing isolated CSV trial VPC."""
import concurrent.futures
import datetime
import network_admission

def read(aws):

    def batch(calls):
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            return dict(pool.map(lambda item: (item[0], aws(*item[1])), calls.items()))
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', 'UtilsBotCsvTrialNetwork')
    if not 'error' not in stack:
        raise RuntimeError('network_readback_invariant') from None
    state = stack['Stacks'][0]
    if state['StackStatus'] not in ('CREATE_COMPLETE', 'UPDATE_COMPLETE'):
        raise RuntimeError('trial_stack_not_ready')
    out = {v['OutputKey']: v['OutputValue'] for v in state['Outputs']}
    res = aws('cloudformation', 'list-stack-resources', '--stack-name', 'UtilsBotCsvTrialNetwork')['StackResourceSummaries']
    physical = {r['LogicalResourceId']: r['PhysicalResourceId'] for r in res}
    vpc = out['TrialVpc']
    if not vpc == 'vpc-05be93e77ca1e1d3d':
        raise RuntimeError('network_readback_invariant') from None
    if not out['TrialSubnet'] == 'subnet-0d1659853364bcb35':
        raise RuntimeError('network_readback_invariant') from None
    if not out['FargateSecurityGroup'] == 'sg-08db78af120f1a6b6':
        raise RuntimeError('network_readback_invariant') from None
    if not out['GlueSecurityGroup'] == 'sg-0e263078696001505':
        raise RuntimeError('network_readback_invariant') from None
    data = batch({'vpc': ['ec2', 'describe-vpcs', '--vpc-ids', vpc], 'subnet': ['ec2', 'describe-subnets', '--subnet-ids', out['TrialSubnet']], 'sgs': ['ec2', 'describe-security-groups', '--filters', 'Name=vpc-id,Values=' + vpc], 'routes': ['ec2', 'describe-route-tables', '--filters', 'Name=vpc-id,Values=' + vpc], 'endpoints': ['ec2', 'describe-vpc-endpoints', '--filters', 'Name=vpc-id,Values=' + vpc], 'enis': ['ec2', 'describe-network-interfaces', '--filters', 'Name=vpc-id,Values=' + vpc], 'firewall': ['route53resolver', 'get-firewall-config', '--resource-id', vpc], 'association': ['route53resolver', 'get-firewall-rule-group-association', '--firewall-rule-group-association-id', physical['DnsAssociation']], 'rules': ['route53resolver', 'list-firewall-rules', '--firewall-rule-group-id', physical['DnsFirewall']], 'allow': ['route53resolver', 'list-firewall-domains', '--firewall-domain-list-id', physical['AllowedDnsNames']], 'block': ['route53resolver', 'list-firewall-domains', '--firewall-domain-list-id', physical['BlockedDnsNames']], 'associations': ['route53resolver', 'list-firewall-rule-group-associations'], 'peerings': ['ec2', 'describe-vpc-peering-connections'], 'transit': ['ec2', 'describe-transit-gateway-vpc-attachments'], 'vpn': ['ec2', 'describe-vpn-gateways'], 'igw': ['ec2', 'describe-internet-gateways', '--filters', 'Name=attachment.vpc-id,Values=' + vpc], 'egress': ['ec2', 'describe-egress-only-internet-gateways'], 'nats': ['ec2', 'describe-nat-gateways', '--filter', 'Name=vpc-id,Values=' + vpc], 'jobs': ['glue', 'get-jobs', '--query', 'Jobs[].Name'], 'tasks': ['ecs', 'list-tasks', '--cluster', 'utils-bot-csv-trial', '--desired-status', 'RUNNING'], 'dns_support': ['ec2', 'describe-vpc-attribute', '--vpc-id', vpc, '--attribute', 'enableDnsSupport'], 'dns_hostnames': ['ec2', 'describe-vpc-attribute', '--vpc-id', vpc, '--attribute', 'enableDnsHostnames']})
    if not not any((isinstance(v, dict) and 'error' in v for v in data.values())):
        raise RuntimeError('network_readback_invariant') from None
    if not (data['dns_support']['EnableDnsSupport']['Value'] and data['dns_hostnames']['EnableDnsHostnames']['Value']):
        raise RuntimeError('network_readback_invariant') from None
    groups = {s['GroupId']: s for s in data['sgs']['SecurityGroups']}
    interfaces = data['enis']['NetworkInterfaces']
    if not len(groups) == 4:
        raise RuntimeError('network_readback_invariant') from None
    expected = dict(account_id='818416606421', vpc_id=vpc, subnet_id=out['TrialSubnet'], default_sg_id=out['TrialDefaultSecurityGroup'], fargate_sg_id=out['FargateSecurityGroup'], glue_sg_id=out['GlueSecurityGroup'], endpoint_sg_id=out['EndpointSecurityGroup'], route_table_id=physical['VpcisolatedSubnet1RouteTableE442650B'], s3_prefix_list_id='pl-7ba54012', dns_group_id=physical['DnsFirewall'])
    active = []
    active.extend(data['tasks']['taskArns'])
    for name in data['jobs']:
        if name in ('utils-bot-csv-trial-glue-small', 'utils-bot-csv-trial-glue-large'):
            runs = aws('glue', 'get-job-runs', '--job-name', name)
            if not 'error' not in runs:
                raise RuntimeError('network_readback_invariant') from None
            active.extend((r['Id'] for r in runs['JobRuns'] if r['JobRunState'] not in ('SUCCEEDED', 'FAILED', 'STOPPED', 'TIMEOUT', 'ERROR', 'EXPIRED')))
    connections = []
    connections.extend((p for p in data['peerings']['VpcPeeringConnections'] if p['RequesterVpcInfo']['VpcId'] == vpc or p['AccepterVpcInfo']['VpcId'] == vpc))
    connections.extend((a for a in data['transit']['TransitGatewayVpcAttachments'] if a['VpcId'] == vpc))
    connections.extend((g for g in data['vpn']['VpnGateways'] if any((a['VpcId'] == vpc for a in g.get('VpcAttachments', [])))))
    connections.extend(data['igw']['InternetGateways'])
    connections.extend((g for g in data['egress']['EgressOnlyInternetGateways'] if any((a['VpcId'] == vpc for a in g.get('Attachments', [])))))
    connections.extend((g for g in data['nats']['NatGateways'] if g['State'] != 'deleted'))
    endpoint_enis = {i for endpoint in data['endpoints']['VpcEndpoints'] for i in endpoint.get('NetworkInterfaceIds', [])}
    worker_interfaces = [e for e in interfaces if e['NetworkInterfaceId'] not in endpoint_enis]
    for e in interfaces:
        if e['NetworkInterfaceId'] in endpoint_enis:
            if not (e['SubnetId'] == out['TrialSubnet'] and {g['GroupId'] for g in e['Groups']} == {out['EndpointSecurityGroup']}):
                raise RuntimeError('network_readback_invariant') from None
    snapshot = dict(checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), cleanup_confirmed=not active and (not worker_interfaces), active_owned_workers=active, network_interfaces=interfaces, nontrial_dns_associations_before=[], nontrial_dns_associations_after=data['associations']['FirewallRuleGroupAssociations'], vpc=data['vpc']['Vpcs'][0], subnet=data['subnet']['Subnets'][0], default_security_group=groups[out['TrialDefaultSecurityGroup']], default_sg_network_interfaces=[e for e in interfaces if any((g['GroupId'] == out['TrialDefaultSecurityGroup'] for g in e['Groups']))], firewall_config=data['firewall']['FirewallConfig'], dns_association=data['association']['FirewallRuleGroupAssociation'], dns_rules=data['rules']['FirewallRules'], dns_domains={physical['AllowedDnsNames']: data['allow']['Domains'], physical['BlockedDnsNames']: data['block']['Domains']}, worker_security_groups=[groups[out[k]] for k in ('FargateSecurityGroup', 'GlueSecurityGroup', 'EndpointSecurityGroup')], production_connections=connections, public_addresses=[e['Association'] for e in interfaces if e.get('Association', {}).get('PublicIp')], endpoints=data['endpoints']['VpcEndpoints'], route_tables=data['routes']['RouteTables'])
    return {'status': state['StackStatus'], 'expected': expected, 'snapshot': snapshot, 'failures': network_admission.network_failures(snapshot, expected)}
