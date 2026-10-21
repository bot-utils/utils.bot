"""Ohio trial reservations. Estimates are not an AWS-enforced spending cap."""
import json
from types import SimpleNamespace
import math
from decimal import Decimal as D
from pathlib import Path

SOURCE_URLS = {
    'catalog': 'https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json',
    'privatelink': 'https://aws.amazon.com/privatelink/pricing/',
    'dns_firewall': 'https://aws.amazon.com/route53/pricing/',
    'cloudwatch': 'https://aws.amazon.com/cloudwatch/pricing/',
    'ecr': 'https://aws.amazon.com/ecr/pricing/',
}


def catalog():
    snapshot = json.loads(Path(__file__).with_name('rates.json').read_text())
    if snapshot['region'] != 'us-east-2' or snapshot['currency'] != 'USD':
        raise ValueError('unexpected rate scope')
    rates = {key: D(entry['USD']) for key, entry in snapshot['rates'].items()}
    endpoint_usage = {'USE2-VpcEndpoint-Hours': rates['endpoint_hour'],
                      'USE2-VpcEndpoint-Bytes': rates['endpoint_data']}
    return SimpleNamespace(CPU=rates['arm_cpu'], RAM=rates['arm_memory'],
                           X86_CPU=rates['x86_cpu'], X86_RAM=rates['x86_memory'],
                           GLUE=rates['glue_dpu'], STORAGE=rates['s3_storage'],
                           PUT=rates['s3_write_request'], pinned=rates,
                           rate=lambda service, usage: endpoint_usage[usage])


def estimate(jobs_per_tier=1, billable_minutes=20, endpoint_hours=4,
             endpoint_gb=2, dns_queries=100000, log_gb='0.1',
             image_gb=2, storage_hours=48, reserve='0.50'):
    """Six resource tiers, serial synthetic jobs, zero customer transfers.

    The 20-minute billed allowance is 15 minutes execution + five minutes
    startup/stop contingency, not proof that AWS billing cannot exceed it.
    Reservation survives failed cleanup and unconfirmed provider termination.
    """
    if any(v < 0 for v in (jobs_per_tier, billable_minutes, endpoint_hours,
                           endpoint_gb, dns_queries, image_gb, storage_hours)):
        raise ValueError('negative reservation quantity')
    if jobs_per_tier < 1 or billable_minutes < 1 or endpoint_hours < 1:
        raise ValueError('missing positive trial lifetime')
    if any(not D(str(v)).is_finite() or D(str(v)) < 0 for v in (log_gb, reserve)):
        raise ValueError('invalid log/reserve quantity')
    c = catalog()
    n = lambda value: D(str(value))
    hourly = [
        n(c.CPU) / 4 + n(c.RAM),
        n(c.X86_CPU) / 4 + n(c.X86_RAM),
        n(c.GLUE) / 16,
        n(c.CPU) * 4 + n(c.RAM) * 16,
        n(c.X86_CPU) * 4 + n(c.X86_RAM) * 16,
        n(c.GLUE),
    ]
    worker = sum(hourly) * n(jobs_per_tier) * n(billable_minutes) / 60
    # Each partial interface-endpoint hour is billed as a full hour.
    network = n(3 * math.ceil(endpoint_hours)) * n(c.rate('AmazonVPC', 'USE2-VpcEndpoint-Hours'))
    parts = {
        'six_tier_workers': worker,
        'three_private_endpoints': network,
        'endpoint_processed_data': n(endpoint_gb) * n(c.rate('AmazonVPC', 'USE2-VpcEndpoint-Bytes')),
        'dns_firewall_queries': n(dns_queries) * c.pinned['dns_million_queries'] / 1000000,
        'seven_dns_entries': D(7) * c.pinned['dns_domain_month'] * n(storage_hours) / 730,
        # Standard on-demand ingestion; no free tier or shared allowance.
        'logs_ingestion': n(log_gb) * c.pinned['logs_ingestion'],
        'logs_storage': n(log_gb) * c.pinned['logs_storage'] * n(storage_hours) / 730,
        'private_image_storage': n(image_gb) * c.pinned['image_storage'] * n(storage_hours) / 730,
        'code_storage': D('0.01') * n(c.STORAGE) * n(storage_hours) / 730,
        's3_requests': D(2000) * n(c.PUT),
        'teardown_and_billing_lag_reserve': n(reserve),
        'internet_result_downloads': D(0),
    }
    total = sum(parts.values())
    return {
        'scope': 'synthetic engine-only; no customer data, upload/download, public API or payment',
        'region': 'us-east-2', 'jobs': 6 * jobs_per_tier,
        'billed_minute_allowance_per_job': billable_minutes,
        'endpoint_lifetime_hours': endpoint_hours,
        'cost_usd': {k: str(v.quantize(D('0.000001'))) for k, v in parts.items()},
        'total_reserved_usd': str(total.quantize(D('0.000001'))),
        'fits_proposed_five_usd': total <= 5,
        'not_a_hard_cap': True, 'estimate_only': True,
        'overrun_response': 'stop dispatch, stop owned workers, retain reservations until termination and cleanup confirmed; disclose any AWS overrun',
        'sources': SOURCE_URLS,
    }


def reservation_fits_reviewed_scope(reservation, settled_usd, outstanding_usd, limit_usd,
          network_reviewed=False, iam_reviewed=False, budget_reviewed=False, reviewed_max_jobs=0):
    """Estimate arithmetic only: flags/dicts are not owner authorization or dispatch proof."""
    if not all((network_reviewed, iam_reviewed, budget_reviewed)) or reservation['jobs'] > reviewed_max_jobs:
        return False
    values = [D(str(v)) for v in (settled_usd, outstanding_usd, limit_usd)]
    if any(not v.is_finite() or v < 0 for v in values):
        return False
    settled, outstanding, limit = values
    reserve = D(reservation['total_reserved_usd'])
    return reserve.is_finite() and reserve >= 0 and settled + outstanding + reserve <= limit


if __name__ == '__main__':
    import json
    print(json.dumps({'first_six_cloud_jobs': estimate(),
                      'original_66_job_scenario': estimate(jobs_per_tier=11, endpoint_hours=24,
                                                          endpoint_gb=10, dns_queries=250000)}, indent=2))
