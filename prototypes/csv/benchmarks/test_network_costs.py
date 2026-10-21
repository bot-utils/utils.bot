import unittest
from copy import deepcopy
from network_costs import estimate, reservation_fits_reviewed_scope


class CostTests(unittest.TestCase):
    def test_partial_endpoint_hours_round_up(self):
        first = estimate(endpoint_hours=1.1)
        second = estimate(endpoint_hours=2)
        self.assertEqual(first['cost_usd']['three_private_endpoints'],
                         second['cost_usd']['three_private_endpoints'])

    def test_all_known_overhead_is_charged(self):
        result = estimate()
        for key in ('three_private_endpoints', 'endpoint_processed_data',
                    'dns_firewall_queries', 'seven_dns_entries', 'logs_ingestion',
                    'private_image_storage', 's3_requests', 'teardown_and_billing_lag_reserve'):
            self.assertGreater(float(result['cost_usd'][key]), 0)
        self.assertTrue(result['not_a_hard_cap'])
        self.assertEqual(result['cost_usd']['internet_result_downloads'], '0.000000')

    def test_estimate_comparison_requires_review_flags(self):
        r = estimate()
        self.assertFalse(reservation_fits_reviewed_scope(r, 0, 0, 5))
        self.assertFalse(reservation_fits_reviewed_scope(r, 0, 0, 5, True, True, False))
        self.assertTrue(reservation_fits_reviewed_scope(r, 0, 0, 5, True, True, True, 6))
        self.assertFalse(reservation_fits_reviewed_scope(r, 4.9, 0.1, 5, True, True, True, 6))
        self.assertFalse(reservation_fits_reviewed_scope(r, 0, 5, 5, True, True, True, 6))

    def test_six_job_authorization_does_not_admit_full_matrix(self):
        self.assertFalse(reservation_fits_reviewed_scope(estimate(jobs_per_tier=11, endpoint_hours=24), 0, 0, 5, True, True, True, 6))

    def test_invalid_balances_fail_closed(self):
        r = estimate()
        for value in ('NaN', 'Infinity', '-1'):
            self.assertFalse(reservation_fits_reviewed_scope(r, value, 0, 5, True, True, True, 6))
        for value in ('NaN', 'Infinity', '-1'):
            with self.assertRaises(ValueError):
                estimate(log_gb=value)
        r = deepcopy(r); r['total_reserved_usd'] = '-1'
        self.assertFalse(reservation_fits_reviewed_scope(r, 0, 0, 5, True, True, True, 6))


if __name__ == '__main__':
    unittest.main()
