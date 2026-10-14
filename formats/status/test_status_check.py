"""Tests for status_check.py: python3 -m unittest discover -s formats/status -p 'test_*.py'"""
import datetime as dt
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import status_check as S  # noqa: E402

GOOD = {'schema': 'lighthouse-status/v1', 'repository': 'LighthouseRobotics/omnilist', 'status': 'active',
        'summary': 'A listing pilot.', 'lastVerified': '2026-10-14', 'verifiedBy': 'npm test (local)',
        'nextAction': 'Run the pilot.', 'blockers': [], 'startHere': 'README.md'}


class StatusCheckTest(unittest.TestCase):
    def test_good_document(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(root))
        open(os.path.join(root, 'README.md'), 'w').close()
        self.assertEqual(S.problems(GOOD, root, dt.date(2026, 10, 14)), [])
        self.assertEqual(S.problems(dict(GOOD, lastVerified=None), root), [])

    def test_every_rule(self):
        today = dt.date(2026, 10, 14)
        cases = [
            (dict(GOOD, schema='lighthouse-status/v2'), 'schema must be'),
            (dict(GOOD, repository='someone/omnilist'), 'repository must be'),
            (dict(GOOD, status='done'), 'status must be'),
            (dict(GOOD, summary=''), 'summary must be'),
            (dict(GOOD, lastVerified='2026-13-01'), 'YYYY-MM-DD'),
            (dict(GOOD, lastVerified='2026-10-15'), 'in the future'),
            (dict(GOOD, blockers='billing'), 'blockers must be'),
            (dict(GOOD, status='blocked'), 'must name its blockers'),
            (dict(GOOD, extra=1), 'unknown field extra'),
            ({k: v for k, v in GOOD.items() if k != 'nextAction'}, 'missing nextAction'),
            ([], 'one JSON object'),
        ]
        for doc, why in cases:
            with self.subTest(why=why):
                self.assertTrue(any(why in p for p in S.problems(doc, today=today)), S.problems(doc, today=today))

    def test_start_here_must_exist_in_the_repository(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(root))
        self.assertIn('startHere names README.md, which is not in the repository', S.problems(GOOD, root))
        self.assertIn('startHere must stay inside the repository',
                      S.problems(dict(GOOD, startHere='../../etc/passwd'), root))
        open(os.path.join(root, 'README.md'), 'w').close()
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(root)
        self.assertEqual(S.problems(GOOD, '.', dt.date(2026, 10, 14)), [], 'a relative root works')

    def test_schema_file_lists_the_same_fields(self):
        with open(os.path.join(os.path.dirname(S.__file__), 'lighthouse-status-v1.schema.json')) as f:
            schema = json.load(f)
        self.assertEqual(tuple(schema['required']), S.FIELDS)
        self.assertEqual(tuple(schema['properties']['status']['enum']), S.STATUSES)


if __name__ == '__main__':
    unittest.main()
