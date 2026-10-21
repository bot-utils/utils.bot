"""Read-only network admission. A valid CloudFormation stack is not job readiness."""
import json
from datetime import datetime, timezone


def _set(value):
    return set(value if isinstance(value, list) else [value])


def endpoint_policy_ok(document, kind, account):
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return False
    role = lambda suffix: 'arn:aws:iam::' + account + ':role/utils-bot-csv-trial-' + suffix
    execution, glue = role('ecs-execution'), role('glue')
    prefix = 'arn:aws:logs:us-east-2:' + account + ':log-group:'
    bucket = 'utils-bot-csv-trial-' + account + '-us-east-2'
    if kind == 's3':
        expected = [
            ({'s3:GetObject'}, {'arn:aws:s3:::prod-us-east-2-starport-layer-bucket/*'}, None),
            ({'s3:GetObject'}, {'arn:aws:s3:::' + bucket + '/trial/code/*'}, glue),
        ]
    elif kind in ('ecr.api', 'ecr.dkr'):
        expected = [
            ({'ecr:GetAuthorizationToken'}, {'*'}, execution),
            ({'ecr:BatchCheckLayerAvailability', 'ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage'},
             {'arn:aws:ecr:us-east-2:' + account + ':repository/utils-bot-csv-trial'}, execution),
        ]
    elif kind == 'logs':
        expected = [
            ({'logs:CreateLogStream', 'logs:PutLogEvents'}, {prefix + '/utils-bot/csv-trial:log-stream:*'}, execution),
            ({'logs:CreateLogStream', 'logs:PutLogEvents'},
             {prefix + '/aws-glue/python-jobs/' + name + ':log-stream:*' for name in ('output', 'error')}, glue),
        ]
    else:
        return False
    statements = document.get('Statement', []) if isinstance(document, dict) else []
    if len(statements) != len(expected):
        return False
    for statement in statements:
        principal = statement.get('Principal')
        if principal not in ('*', {'AWS': '*'}, {'AWS': ['*']}):
            return False
        match = None
        for i, (actions, resources, arn) in enumerate(expected):
            condition = {'ArnEquals': {'aws:PrincipalArn': arn}} if arn else {}
            if (statement.get('Effect') == 'Allow' and
                    _set(statement.get('Action', [])) == actions and
                    _set(statement.get('Resource', [])) == resources and
                    statement.get('Condition', {}) == condition and
                    not any(k in statement for k in ('NotAction', 'NotResource', 'NotPrincipal'))):
                match = i
                break
        if match is None:
            return False
        expected.pop(match)
    return not expected



def dns_rules_ok(snapshot, expected):
    account = expected['account_id']
    domains = {
        'api.ecr.us-east-2.amazonaws.com', account + '.dkr.ecr.us-east-2.amazonaws.com',
        'logs.us-east-2.amazonaws.com', 's3.us-east-2.amazonaws.com',
        'utils-bot-csv-trial-' + account + '-us-east-2.s3.us-east-2.amazonaws.com',
        'prod-us-east-2-starport-layer-bucket.s3.us-east-2.amazonaws.com',
    }
    association = snapshot['dns_association']
    if (association.get('VpcId') != expected['vpc_id'] or
            association.get('FirewallRuleGroupId') != expected['dns_group_id'] or
            association.get('Status') != 'COMPLETE' or association.get('Priority') != 100):
        return False
    rules = sorted(snapshot['dns_rules'], key=lambda r: r['Priority'])
    if len(rules) != 2:
        return False
    for rule, action, priority, wanted in zip(rules, ('ALLOW', 'BLOCK'), (100, 200), (domains, {'*'})):
        if (rule.get('Action') != action or rule.get('Priority') != priority or
                rule.get('FirewallDomainRedirectionAction') != 'INSPECT_REDIRECTION_DOMAIN' or
                set(snapshot['dns_domains'][rule['FirewallDomainListId']]) != wanted):
            return False
        if action == 'BLOCK' and rule.get('BlockResponse') != 'NODATA':
            return False
    return True


def worker_rules_ok(snapshot, expected, preparation_only=False):
    def signatures(rules):
        result = set()
        for rule in rules:
            protocol, start, end = rule['IpProtocol'], rule.get('FromPort'), rule.get('ToPort')
            if rule.get('Ipv6Ranges'):
                return None
            for ip in rule.get('IpRanges', []):
                if not preparation_only or (protocol, start, end, ip.get('CidrIp')) != ('icmp', 252, 86, '255.255.255.255/32'):
                    return None
            for pair in rule.get('UserIdGroupPairs', []):
                if pair.get('VpcPeeringConnectionId') or pair.get('UserId', expected['account_id']) != expected['account_id']:
                    return None
                result.add((protocol, start, end, pair['GroupId']))
            for prefix in rule.get('PrefixListIds', []):
                result.add((protocol, start, end, prefix['PrefixListId']))
        return result
    parser, glue, endpoint = (expected[name] for name in ('fargate_sg_id', 'glue_sg_id', 'endpoint_sg_id'))
    https = lambda target: ('tcp', 443, 443, target)
    self_tcp = ('tcp', 0, 65535, glue)
    wanted = {parser: (set(), {https(endpoint), https(expected['s3_prefix_list_id'])}),
              glue: ({self_tcp}, {self_tcp, https(endpoint), https(expected['s3_prefix_list_id'])}),
              endpoint: ({https(parser), https(glue)}, set())}
    groups = snapshot['worker_security_groups']
    if len(groups) != 3:
        return False
    for group in groups:
        if (group['GroupId'] not in wanted or group['VpcId'] != expected['vpc_id'] or
                {t['Key']: t['Value'] for t in group.get('Tags', [])}.get('Purpose') != 'utils-bot-csv-trial'):
            return False
        if (signatures(group['IpPermissions']), signatures(group['IpPermissionsEgress'])) != wanted.pop(group['GroupId']):
            return False
    return not wanted


def _network_failures(snapshot, expected, now=None, preparation_only=False):
    """Every dispatch needs a fresh live snapshot; absent/unknown means deny.

    expected contains reviewed CloudFormation output IDs, never HTTP/job input.
    No mutation or job execution is performed by this module.
    """
    errors = []
    now = now or datetime.now(timezone.utc)
    try:
        checked = datetime.fromisoformat(snapshot['checked_at'])
        age = (now - checked).total_seconds()
        if not 0 <= age <= 30:
            errors.append('stale_network_readback')
        if snapshot.get('active_owned_workers') != []:
            errors.append('owned_workers_active_or_unknown')
        if snapshot.get('cleanup_confirmed') is not True:
            errors.append('cleanup_unknown')
        before = {a['Id']: a for a in snapshot['nontrial_dns_associations_before'] if a['VpcId'] != expected['vpc_id']}
        after = {a['Id']: a for a in snapshot['nontrial_dns_associations_after'] if a['VpcId'] != expected['vpc_id']}
        if before != after:
            errors.append('nontrial_dns_association_changed')
        vpc = snapshot['vpc']
        vpc_id = expected['vpc_id']
        if (vpc['VpcId'] != vpc_id or vpc.get('State') != 'available' or
                vpc.get('CidrBlock') != '10.88.0.0/24' or
                vpc.get('Ipv6CidrBlockAssociationSet') or
                {t['Key']: t['Value'] for t in vpc.get('Tags', [])}.get('Purpose') != 'utils-bot-csv-trial'):
            errors.append('wrong_or_unowned_vpc')
        subnet = snapshot['subnet']
        if (subnet['SubnetId'] != expected['subnet_id'] or subnet['VpcId'] != vpc_id or
                subnet.get('MapPublicIpOnLaunch') is not False or subnet.get('AssignIpv6AddressOnCreation') or
                subnet.get('Ipv6CidrBlockAssociationSet') or subnet.get('State') != 'available'):
            errors.append('subnet_not_private')
        default = snapshot['default_security_group']
        if (default['GroupId'] != expected['default_sg_id'] or default['VpcId'] != vpc_id or
                default['GroupName'] != 'default' or
                (not preparation_only and (default.get('IpPermissions') != [] or default.get('IpPermissionsEgress') != []))):
            errors.append('default_security_group_not_hardened')
        if {t['Key']:t['Value'] for t in default.get('Tags', [])}.get('Purpose') is not None:
            errors.append('default_security_group_must_remain_unowned_by_network_role')
        if snapshot.get('default_sg_network_interfaces') != []:
            errors.append('default_security_group_in_use_or_unknown')
        if snapshot.get('firewall_config', {}).get('FirewallFailOpen') != 'DISABLED':
            errors.append('dns_not_fail_closed')
        if not dns_rules_ok(snapshot, expected):
            errors.append('dns_allowlist_not_verified')
        if not worker_rules_ok(snapshot, expected, preparation_only):
            errors.append('worker_rules_not_verified')
        if snapshot.get('production_connections') != []:
            errors.append('network_connection_or_unknown')
        if snapshot.get('public_addresses') != []:
            errors.append('public_address_or_unknown')

        endpoints = snapshot['endpoints']
        services = {'s3'} if preparation_only else {'s3', 'ecr.api', 'ecr.dkr', 'logs'}
        seen = set()
        s3_id = None
        for endpoint in endpoints:
            name = endpoint.get('ServiceName', '')
            kind = name.removeprefix('com.amazonaws.us-east-2.')
            if kind not in services or kind in seen:
                errors.append('unexpected_endpoint')
                continue
            seen.add(kind)
            if endpoint.get('VpcId') != vpc_id or endpoint.get('State') != 'available':
                errors.append('endpoint_not_owned_or_available')
            if not endpoint_policy_ok(endpoint.get('PolicyDocument'), kind, expected['account_id']):
                errors.append('endpoint_policy_not_reviewed')
            if kind == 's3':
                s3_id = endpoint['VpcEndpointId']
                if endpoint.get('VpcEndpointType') != 'Gateway' or endpoint.get('RouteTableIds') != [expected['route_table_id']]:
                    errors.append('s3_gateway_route_binding')
            elif (endpoint.get('VpcEndpointType') != 'Interface' or
                    endpoint.get('SubnetIds') != [expected['subnet_id']] or
                    {g['GroupId'] for g in endpoint.get('Groups', [])} != {expected['endpoint_sg_id']} or
                    endpoint.get('PrivateDnsEnabled') is not True or
                    endpoint.get('IpAddressType', 'ipv4') != 'ipv4'):
                errors.append('interface_endpoint_binding')
        if seen != services:
            errors.append('paid_endpoints_not_ready')
        tables = snapshot['route_tables']
        found_table = False
        found_s3_route = False
        for table in tables:
            if table.get('VpcId') != vpc_id:
                errors.append('foreign_route_table')
            if table['RouteTableId'] == expected['route_table_id']:
                found_table = True
                if not any(a.get('SubnetId') == expected['subnet_id'] for a in table.get('Associations', [])):
                    errors.append('subnet_route_table_mismatch')
            for route in table.get('Routes', []):
                local = route.get('DestinationCidrBlock') == '10.88.0.0/24' and route.get('GatewayId') == 'local'
                gateway = (route.get('DestinationPrefixListId') == expected['s3_prefix_list_id'] and
                           route.get('GatewayId') == s3_id)
                if gateway and table['RouteTableId'] == expected['route_table_id']:
                    found_s3_route = True
                if not (local or gateway) or route.get('State') != 'active':
                    errors.append('unapproved_route')
        if not found_s3_route:
            errors.append('s3_gateway_route_missing')
        if not found_table:
            errors.append('route_table_missing')
    except (KeyError, TypeError, ValueError, AttributeError):
        errors.append('incomplete_or_malformed_readback')
    return sorted(set(errors))


def network_failures(snapshot, expected, now=None):
    """Phase-two validation of supplied observations; no live reads or dispatch."""
    return _network_failures(snapshot, expected, now, preparation_only=False)


def phase_one_failures(snapshot, expected, now=None):
    """Validate preparation only. Success never authorizes jobs or paid endpoints.

    Default SG rules and CDK's unreachable endpoint-SG placeholder can still
    require exact-ID revocation. Phase-two validation rejects either afterward.
    """
    return _network_failures(snapshot, expected, now, preparation_only=True)
