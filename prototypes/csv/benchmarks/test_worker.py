import gzip
import hashlib
import json
import random
import tempfile
import unittest
from pathlib import Path

from fixtures import HEADER, encode, reference, generate
from worker import Failure, execute


class WorkerTests(unittest.TestCase):
    def check_case(self, operation, left, right=(), **options):
        root = Path(tempfile.mkdtemp(prefix='utils-csv-trial-'))
        self.addCleanup(self.trash, root)
        (root / 'left.csv').write_bytes(encode(HEADER, left))
        (root / 'right.csv').write_bytes(encode(HEADER, right))
        try:
            result = execute(operation, root / 'left.csv', root / 'right.csv' if operation == 'join' else None,
                             root / 'work', **options)
        except Failure:
            self.assertFalse((root / 'work/result.csv.gz').exists())
            raise
        expected = reference(operation, left, right, options.get('keep', 'first'))
        artifact = (root / 'work/result.csv.gz').read_bytes()
        self.assertEqual(gzip.decompress(artifact), expected)
        self.assertEqual(result['logical_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertEqual(result['encoded_sha256'], hashlib.sha256(artifact).hexdigest())
        return result, artifact

    @staticmethod
    def trash(path):
        import subprocess
        subprocess.run(['trash', str(path)], check=True, capture_output=True)

    def test_edge_cases_and_order(self):
        left = [['a|b', 'c', '0.1', 'comma,new\nline'], ['a', 'b|c', '-0.10', '中文'],
                ['', '', '+1.000000000000000001', ''], ['a|b', 'c', '2', 'last'],
                ['a', 'b|c', '99999999999999999999.000000000000000001', '🙂']]
        right = [['a|b', 'c', '1', 'one'], ['a|b', 'c', '2', 'two'], ['', '', '0', 'empty']]
        for op in ('dedupe', 'join', 'aggregate'):
            with self.subTest(operation=op):
                self.check_case(op, left, right)
                self.check_case(op, [])
        self.check_case('dedupe', left, keep='last')

    def test_randomized_independent_oracle(self):
        rng = random.Random(20261021)
        for trial in range(12):
            left = [[str(rng.randrange(8)), str(rng.randrange(4)), str(rng.randrange(-100, 100)) + '.125',
                     rng.choice(['', 'quoted,"x"', 'row\nbreak', 'é'])] for _ in range(40)]
            right = [[str(rng.randrange(8)), str(rng.randrange(4)), '0.1', str(i)] for i in range(25)]
            for op in ('dedupe', 'join', 'aggregate'):
                self.check_case(op, left, right)

    def test_deterministic_encoded_bytes(self):
        left = [['k', 'g', '1.0', 'repeated' * 100]]
        _, first = self.check_case('dedupe', left)
        _, second = self.check_case('dedupe', left)
        self.assertEqual(first, second)

    def test_limits_and_no_payable_artifact_on_failure(self):
        rows = [['k', 'g', '1', 'x'], ['k', 'g', '2', 'y']]
        for operation, kwargs, code in [
                ('dedupe', {'max_input': 1}, 'file_limit'),
                ('dedupe', {'max_rows': 1}, 'row_limit'),
                ('dedupe', {'max_output': 1}, 'output_limit'),
                ('dedupe', {'max_encoded': 1}, 'encoded_limit'),
                ('join', {'max_pairs': 3}, 'pair_limit'),
                ('aggregate', {'max_groups': 0}, 'group_limit')]:
            with self.subTest(code=code):
                with self.assertRaisesRegex(Failure, '^' + code + '$'):
                    self.check_case(operation, rows, rows, **kwargs)
        with self.assertRaisesRegex(Failure, '^invalid_decimal$'):
            self.check_case('aggregate', [['k', 'g', '', '']])

    def test_exact_byte_boundaries(self):
        rows = [['k', 'g', '1', 'x']]
        result, _ = self.check_case('dedupe', rows)
        self.check_case('dedupe', rows, max_input=len(encode(HEADER, rows)),
                        max_output=result['logical_bytes'], max_encoded=result['encoded_bytes'])
        with self.assertRaisesRegex(Failure, '^output_limit$'):
            self.check_case('dedupe', rows, max_output=result['logical_bytes'] - 1)
        with self.assertRaisesRegex(Failure, '^encoded_limit$'):
            self.check_case('dedupe', rows, max_encoded=result['encoded_bytes'] - 1)

    def test_planted_large_fixture_oracle(self):
        root = Path(tempfile.mkdtemp(prefix='utils-csv-trial-'))
        self.addCleanup(self.trash, root)
        for stride in (2, 4):
            fixture = root / ('fixture-' + str(stride))
            manifest = generate(fixture, mib=1, join_stride=stride)
            self.assertEqual(manifest['fixture_version'], 2)
            for filename, entry in manifest['files'].items():
                self.assertLessEqual(entry['bytes'], 1 << 20)
                self.assertGreater(entry['bytes'], (1 << 20) - 2048)
                self.assertEqual((fixture / filename).stat().st_size, entry['bytes'])
            for operation in ('dedupe', 'join', 'aggregate'):
                result = execute(operation, fixture / 'left.csv',
                                 fixture / 'right.csv' if operation == 'join' else None,
                                 root / ('work-' + operation + str(stride)))
                self.assertEqual(result['logical_sha256'], manifest['expected_logical_sha256'][operation])

    def test_duplicate_header_rejected(self):
        root = Path(tempfile.mkdtemp(prefix='utils-csv-trial-'))
        self.addCleanup(self.trash, root)
        path = root / 'invalid.csv'
        path.write_text('key,key,amount,payload\na,b,1,c\n')
        with self.assertRaisesRegex(Failure, '^invalid_header$'):
            execute('dedupe', path, None, root / 'work')


if __name__ == '__main__':
    unittest.main()
