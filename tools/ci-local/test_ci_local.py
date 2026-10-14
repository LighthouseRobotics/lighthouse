"""Tests for ci_local.py. Standard library only; the end-to-end cases need git and bash.

Run: python3 -m unittest discover -s tools/ci-local -p 'test_*.py'
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ci_local as C  # noqa: E402

try:
    import yaml as _pyyaml
except ImportError:  # optional cross-check only
    _pyyaml = None

WORKFLOW_SHAPES = '''
name: Demo   # a comment
on:
  push:
    branches: [main, 'release/**']
    paths-ignore: ['docs/**', "**/*.md"]
  workflow_dispatch:
env:
  A: 1
  B: '1'
  C: on
  D: 3.10
  E: ~
  F: "tab\\tand \\u00e9"
  G: 'it''s'
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@abc # v4
        with:
          fetch-depth: 0
      - name: Many lines
        run: |
          echo one
          # not a comment
          echo "two # also kept"

      - run: >-
          folded
          text

          next
      - run: echo plain # cut
      -   name: wide dash
          run: x
      - if: github.event_name == 'push' &&
          github.ref == 'refs/heads/main'
        run: echo continued
list:
- a
- - nested
  - deeper
- {k: v, 'q': "w"}
- [1,
   2]
'''


def _git(cwd, *args):
    subprocess.run(['git', '-C', cwd] + list(args), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class YamlTest(unittest.TestCase):
    def test_workflow_shapes(self):
        got = C.parse_yaml(WORKFLOW_SHAPES)
        self.assertEqual(got['name'], 'Demo')
        self.assertEqual(got['on']['push']['branches'], ['main', 'release/**'])
        self.assertEqual(got['on']['push']['paths-ignore'], ['docs/**', '**/*.md'])
        self.assertIsNone(got['on']['workflow_dispatch'])
        self.assertEqual(got['env'], {'A': 1, 'B': '1', 'C': 'on', 'D': 3.1, 'E': None, 'F': 'tab\tand \u00e9',
                                      'G': "it's"})
        steps = got['jobs']['test']['steps']
        self.assertEqual(steps[0], {'uses': 'actions/checkout@abc', 'with': {'fetch-depth': 0}})
        self.assertEqual(steps[1]['run'], 'echo one\n# not a comment\necho "two # also kept"\n')
        self.assertEqual(steps[2]['run'], 'folded text\nnext')
        self.assertEqual(steps[3]['run'], 'echo plain')
        self.assertEqual(steps[4], {'name': 'wide dash', 'run': 'x'})
        self.assertEqual(steps[5]['if'], "github.event_name == 'push' && github.ref == 'refs/heads/main'")
        self.assertEqual(got['list'], ['a', ['nested', 'deeper'], {'k': 'v', 'q': 'w'}, [1, 2]])

    def test_block_scalar_chomping(self):
        got = C.parse_yaml('a: |-\n  x\n\nb: |+\n  y\n\nc: >\n  p\n    more\n  q\nd: |\n\ne: 1\n')
        self.assertEqual(got, {'a': 'x', 'b': 'y\n\n', 'c': 'p\n  more\nq\n', 'd': '', 'e': 1})

    def test_refuses_what_it_does_not_support(self):
        for text, why in [('a: &x 1\nb: *x\n', 'anchors'), ('a: !!str 1\n', 'tags'), ('a: 1\na: 2\n', 'duplicate'),
                          ('a:\n\tb: 1\n', 'tabs'), ('a: b: c\n', 'quote it'), ('a: 1\n---\nb: 2\n', 'one document'),
                          ('a: "open\n  close"\n', 'end on the line'), ('a: [1, 2\n', 'not closed'),
                          ('a: 1\n  b: 2\n', 'line 1'), ('- a\nb: 1\n', 'line 2')]:
            with self.subTest(text=text), self.assertRaisesRegex(C.YamlError, why):
                C.parse_yaml(text)

    @unittest.skipUnless(_pyyaml, 'PyYAML is not installed; the cases above still run')
    def test_agrees_with_pyyaml(self):
        def norm(v):
            if isinstance(v, dict):
                return {('on' if k is True else str(k)): norm(x) for k, x in v.items()}
            return [norm(x) for x in v] if isinstance(v, list) else v
        chomping = 'a: |-\n  x\n\nb: |+\n  y\n\nc: >\n  p\n    more\n  q\nd: |\n\ne: 1\n'
        for text in (WORKFLOW_SHAPES.replace('C: on', 'C: onward'), chomping):
            self.assertEqual(C.parse_yaml(text), norm(_pyyaml.safe_load(text)))


class ExprTest(unittest.TestCase):
    def test_operators_and_coercion(self):
        e = C.Expr({'github': {'event_name': 'push', 'ref': 'refs/heads/main', 'event': {}}, 'matrix': {'n': 2}})
        self.assertIs(e.evaluate("github.event_name != 'pull_request' || github.event.pull_request.draft == false"),
                      True)
        self.assertEqual(e.evaluate("github.event.pull_request.number || github.ref"), 'refs/heads/main')
        self.assertEqual(e.evaluate("matrix.n && 'yes'"), 'yes')
        self.assertEqual(e.evaluate("matrix.missing && 'yes'"), None)
        self.assertIs(e.evaluate("'ABC' == 'abc'"), True)
        self.assertIs(e.evaluate("'1' == 1"), True)
        self.assertIs(e.evaluate("null == 0"), True)
        self.assertIs(e.evaluate("'x' == 0"), False)
        self.assertIs(e.evaluate("matrix.n >= 2 && !(matrix.n < 2)"), True)
        self.assertIs(e.evaluate("GitHub.EVENT_NAME == 'push'"), True)
        self.assertIs(e.evaluate("github.event == github.event"), True)
        self.assertIs(e.evaluate("fromJSON('{}') == fromJSON('{}')"), False)

    def test_functions(self):
        e = C.Expr({'github': {'event': {'labels': [{'name': 'a'}, {'name': 'b'}]}}})
        self.assertIs(e.evaluate("contains(github.event.labels.*.name, 'B')"), True)
        self.assertIs(e.evaluate("contains('Hello world', 'WORLD')"), True)
        self.assertIs(e.evaluate("startsWith('refs/heads/main', 'refs/HEADS')"), True)
        self.assertIs(e.evaluate("endsWith('file.MD', '.md')"), True)
        self.assertEqual(e.evaluate("format('{0}-{1} {{x}}', 'a', 2)"), 'a-2 {x}')
        self.assertEqual(e.evaluate("join(fromJSON('[1,2]'), '+')"), '1+2')
        self.assertEqual(e.evaluate("fromJSON('{\"a\": [3]}').a[0]"), 3)
        self.assertEqual(json.loads(e.evaluate("toJSON(github.event.labels[1])")), {'name': 'b'})
        with self.assertRaisesRegex(C.ExprError, 'not supported'):
            e.evaluate('frobnicate(1)')
        with self.assertRaises(C.ExprError):
            e.evaluate("github.event ==")

    def test_hash_files(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.makedirs(os.path.join(d, 'a'))
        for name in ('a/x.json', 'a/y.json'):
            with open(os.path.join(d, name), 'w') as f:
                f.write(name)
        e = C.Expr({}, workspace=d)
        both = e.evaluate("hashFiles('a/**/*.json')")
        self.assertRegex(both, r'^[0-9a-f]{64}$')
        self.assertNotEqual(both, e.evaluate("hashFiles('a/**/*.json', '!a/y.json')"))
        self.assertEqual(e.evaluate("hashFiles('missing/*')"), '')

    def test_conditions_and_interpolation(self):
        e = C.Expr({'matrix': {'flag': False, 'n': 3.0}}, status='failure')
        self.assertFalse(C.condition(None, e))
        self.assertTrue(C.condition('always()', e))
        self.assertTrue(C.condition('${{ failure() }}', e))
        self.assertFalse(C.condition('true', e), 'without a status function the condition is success() && ...')
        e.status = 'success'
        self.assertTrue(C.condition(True, e))
        self.assertIs(C.interpolate('${{ matrix.flag }}', e), False)
        self.assertEqual(C.interpolate('a-${{ matrix.n }}-${{ 1 == 1 }}', e), 'a-3-true')
        C.interpolate('t=${{ secrets.NPM_TOKEN }} ${{ github.token }} ${{ vars.X }}', e)
        self.assertEqual(e.unavailable, {'secrets.NPM_TOKEN', 'github.token', 'vars.X'})


class FilterTest(unittest.TestCase):
    def test_patterns(self):
        self.assertTrue(C.filter_match('docs/a/b.md', ['docs/**']))
        self.assertTrue(C.filter_match('README.md', ['**/*.md']))
        self.assertTrue(C.filter_match('a/b/README.md', ['**/*.md']))
        self.assertFalse(C.filter_match('learn/x/essay.html', ['learn/*essay.html']))
        self.assertTrue(C.filter_match('learn/my-essay.html', ['learn/*essay.html']))
        self.assertFalse(C.filter_match('src/keep.js', ['src/**', '!src/keep.js']))
        self.assertTrue(C.filter_match('feature/x', ['feature/*']))
        self.assertFalse(C.filter_match('feature/x/y', ['feature/*']))

    def test_triggers(self):
        on = {'push': {'branches': ['main'], 'paths-ignore': ['docs/**']}, 'pull_request': None,
              'workflow_dispatch': None}
        self.assertEqual(C.trigger(on, 'push', 'refs/heads/main', 'main', None),
                         (True, 'runs on push; path filters not checked (no --base)'))
        self.assertFalse(C.trigger(on, 'push', 'refs/heads/dev', 'main', None)[0])
        self.assertFalse(C.trigger(on, 'push', 'refs/heads/main', 'main', ['docs/a.md'])[0])
        self.assertTrue(C.trigger(on, 'push', 'refs/heads/main', 'main', ['docs/a.md', 'src/a.js'])[0])
        self.assertTrue(C.trigger(on, 'pull_request', '', 'main', None)[0])
        self.assertFalse(C.trigger('workflow_dispatch', 'push', 'refs/heads/main', 'main', None)[0])
        self.assertFalse(C.trigger({'push': {'tags': ['v*']}}, 'push', 'refs/heads/main', 'main', None)[0])

    def test_matrix_and_order(self):
        combos = C.expand_matrix({'matrix': {'os': ['a', 'b'], 'n': [1, 2], 'exclude': [{'os': 'b', 'n': 2}],
                                             'include': [{'os': 'a', 'extra': 'x'}, {'os': 'c', 'n': 9}]}})
        self.assertEqual(combos, [{'os': 'a', 'n': 1, 'extra': 'x'}, {'os': 'a', 'n': 2, 'extra': 'x'},
                                  {'os': 'b', 'n': 1}, {'os': 'c', 'n': 9}])
        self.assertEqual(C.expand_matrix(None), [{}])
        with self.assertRaises(C.Unsupported):
            C.expand_matrix({'matrix': '${{ fromJSON(needs.a.outputs.m) }}'})
        self.assertEqual(C.job_order({'c': {'needs': ['a', 'b']}, 'b': {'needs': 'a'}, 'a': {}}), ['a', 'b', 'c'])
        with self.assertRaisesRegex(C.RunnerError, 'cycle'):
            C.job_order({'a': {'needs': 'b'}, 'b': {'needs': 'a'}})


PASS = '''
name: Pass
on: [push, workflow_dispatch]
env:
  GREETING: hello
jobs:
  build:
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        n: [1, 2]
    outputs:
      word: ${{ steps.make.outputs.word }}
    steps:
      - uses: actions/checkout@v4
      - id: make
        run: |
          test "$(cat data.txt)" = committed
          echo "word=${GREETING}-${{ matrix.n }}" >> "$GITHUB_OUTPUT"
          echo "LATER=set" >> "$GITHUB_ENV"
      - run: test "$LATER" = set && test "${{ steps.make.outputs.word }}" = "hello-${{ matrix.n }}"
      - name: Host variables stay out
        run: test -z "${CI_LOCAL_TEST_PRIVATE:-}" && test "$CI" = true && test "$LIGHTHOUSE_CI_LOCAL" = 1
      - if: ${{ hashFiles('data.txt') != '' }}
        working-directory: sub
        run: test -f inner.txt
      - name: A background process does not hold the step open
        run: sleep 300 & echo started
      - uses: actions/upload-artifact@v4
        with:
          name: evidence-${{ matrix.n }}
          path: sub
  after:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: test "${{ needs.build.outputs.word }}" = hello-2 && test "${{ needs.build.result }}" = success
'''

RED = '''
on: push
jobs:
  red:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: exit 3
        continue-on-error: true
      - run: test -f missing.txt
      - run: echo never
      - if: always()
        run: echo cleanup
  later:
    needs: red
    runs-on: ubuntu-24.04
    steps:
      - run: echo never
'''

UNKNOWN = '''
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo before
      - uses: someone/deploy@v1
      - run: echo after
'''

DRIFT = '''
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: '1'
      - run: echo checked
'''

SECRET = '''
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: test -z "${{ secrets.NPM_TOKEN }}"
'''

PYTHON = '''
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: '%d.%d'
      - run: python -c "import sys; assert sys.prefix != sys.base_prefix, 'not in a fresh environment'"
'''

DISPATCH = '''
on:
  workflow_dispatch:
    inputs:
      suite:
        required: true
        type: choice
        options: [core, full]
jobs:
  core:
    runs-on: ubuntu-latest
    steps:
      - run: echo core
  full:
    if: ${{ inputs.suite == 'full' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo full
'''

SLOW = '''
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: sleep 30
        timeout-minutes: 0.02
'''

EDGES = '''
on: push
jobs:
  flaky:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: exit 1
  files:
    runs-on: ubuntu-latest
    steps:
      - run: echo "no equals sign" >> "$GITHUB_OUTPUT"
        continue-on-error: true
      - run: echo kept > "$RUNNER_TEMP/inside.txt" && echo host > "$RUNNER_TEMP/../../outside.txt"
      - uses: actions/upload-artifact@v4
        with:
          name: mixed
          path: |
            ${{ runner.temp }}/inside.txt
            ${{ runner.temp }}/../../outside.txt
'''


@unittest.skipUnless(shutil.which('git') and shutil.which('bash'), 'needs git and bash')
class EndToEndTest(unittest.TestCase):
    def repo(self, workflows, files=None):
        d = tempfile.mkdtemp(prefix='ci-local-repo-')
        self.addCleanup(shutil.rmtree, d, True)
        _git(d, 'init', '-q', '-b', 'main')
        _git(d, 'config', 'user.email', 'ci@example.com')
        _git(d, 'config', 'user.name', 'CI test')
        os.makedirs(os.path.join(d, '.github', 'workflows'))
        for name, text in workflows.items():
            with open(os.path.join(d, '.github', 'workflows', name), 'w') as f:
                f.write(text)
        for name, text in (files or {}).items():
            os.makedirs(os.path.dirname(os.path.join(d, name)) or d, exist_ok=True)
            with open(os.path.join(d, name), 'w') as f:
                f.write(text)
        _git(d, 'add', '-A')
        _git(d, 'commit', '-q', '-m', 'fixture')
        return d

    def run_ci(self, repo, *args):
        out = tempfile.mkdtemp(prefix='ci-local-out-')
        self.addCleanup(shutil.rmtree, out, True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = C.main(['run', '--repo', repo, '--out', out, '--quiet'] + list(args))
        path = os.path.join(out, 'receipt.json')
        with open(path) as f:
            return code, json.load(f), path

    def steps(self, record, job=0):
        return [s['result'] for s in record['workflows'][0]['jobs'][job]['steps']]

    def test_a_passing_run_at_the_commit_ignores_uncommitted_changes(self):
        repo = self.repo({'pass.yml': PASS}, {'data.txt': 'committed', 'sub/inner.txt': 'x'})
        with open(os.path.join(repo, 'data.txt'), 'w') as f:
            f.write('uncommitted edit')
        os.environ['CI_LOCAL_TEST_PRIVATE'] = 'host only'
        self.addCleanup(os.environ.pop, 'CI_LOCAL_TEST_PRIVATE', None)
        code, record, path = self.run_ci(repo)
        self.assertEqual((code, record['result']), (0, 'pass'), json.dumps(record, indent=1))
        jobs = record['workflows'][0]['jobs']
        self.assertEqual([(j['id'], j['matrix'], j['result']) for j in jobs],
                         [('build', {'n': 1}, 'success'), ('build', {'n': 2}, 'success'), ('after', {}, 'success')])
        self.assertEqual(jobs[1]['outputs'], {'word': 'hello-2'})
        self.assertEqual(record['repository']['commit'], subprocess.check_output(
            ['git', '-C', repo, 'rev-parse', 'HEAD'], text=True).strip())
        self.assertEqual(record['label'], C.LABEL)
        self.assertNotIn('CI_LOCAL_TEST_PRIVATE', record['runner']['host']['env_passed'])
        self.assertEqual(jobs[0]['steps'][-1]['artifact']['files'], 1)
        self.assertTrue(os.path.isfile(os.path.join(os.path.dirname(path), 'artifacts', 'evidence-1', 'sub',
                                                    'inner.txt')))
        self.assertEqual(C.verify_receipt(path, repo)[0], [])

    def test_a_failure_is_red_and_verify_catches_edits(self):
        repo = self.repo({'red.yml': RED})
        code, record, path = self.run_ci(repo)
        self.assertEqual((code, record['result']), (1, 'fail'))
        self.assertEqual(self.steps(record), ['pass', 'fail', 'fail', 'skip', 'pass'])
        self.assertTrue(record['workflows'][0]['jobs'][0]['steps'][1]['continue_on_error'])
        self.assertEqual(record['workflows'][0]['jobs'][0]['steps'][2]['exit_code'], 1)
        self.assertEqual(record['workflows'][0]['jobs'][1]['result'], 'skipped')
        self.assertEqual(C.verify_receipt(path, repo)[0], [])
        record['result'] = 'pass'
        record['workflows'][0]['jobs'][0]['result'] = 'success'
        with open(path, 'w') as f:
            json.dump(record, f)
        self.assertTrue(any('steps say failure' in p for p in C.verify_receipt(path)[0]))
        record['workflows'][0]['jobs'][0]['result'] = 'failure'
        record['result'] = 'fail'
        with open(path, 'w') as f:
            json.dump(record, f)
        with open(os.path.join(os.path.dirname(path), record['workflows'][0]['jobs'][0]['steps'][2]['log']), 'a') as f:
            f.write('edited')
        self.assertTrue(any('does not match its hash' in p for p in C.verify_receipt(path)[0]))

    def test_an_unknown_action_makes_the_run_incomplete(self):
        code, record, _ = self.run_ci(self.repo({'x.yml': UNKNOWN}))
        self.assertEqual((code, record['result']), (2, 'incomplete'))
        self.assertEqual(self.steps(record), ['pass', 'unsupported', 'not-run'])

    def test_version_drift_blocks_a_pass_unless_accepted(self):
        repo = self.repo({'x.yml': DRIFT})
        code, record, _ = self.run_ci(repo)
        self.assertEqual((code, record['result']), (2, 'incomplete'))
        self.assertEqual([(d['kind'], d['material']) for d in record['differences']], [('version', True)])
        code, record, _ = self.run_ci(repo, '--accept-version-drift')
        self.assertEqual((code, record['result']), (0, 'pass'))
        self.assertEqual([(d['kind'], d['material']) for d in record['differences']], [('version', False)])

    def test_a_secret_this_machine_does_not_have_makes_it_incomplete(self):
        code, record, _ = self.run_ci(self.repo({'x.yml': SECRET}))
        self.assertEqual((record['result'], record['unavailable']), ('incomplete', ['secrets.NPM_TOKEN']))

    def test_setup_python_gives_a_fresh_environment(self):
        code, record, _ = self.run_ci(self.repo({'x.yml': PYTHON % sys.version_info[:2]}))
        self.assertEqual(record['result'], 'pass', json.dumps(record['workflows'][0]['jobs'], indent=1))

    def test_dispatch_inputs_and_triggers(self):
        repo = self.repo({'d.yml': DISPATCH})
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(C.main(['run', '--repo', repo, '--event', 'workflow_dispatch', '--dry-run']), 3)
            self.assertEqual(C.main(['run', '--repo', repo, '--event', 'workflow_dispatch', '--input', 'suite=x',
                                     '--dry-run']), 3)
            out = os.path.join(tempfile.mkdtemp(prefix='ci-local-out-'), 'new')
            self.addCleanup(shutil.rmtree, os.path.dirname(out), True)
            self.assertEqual(C.main(['run', '--repo', repo, '--event', 'workflow_dispatch', '--out', out]), 3)
            self.assertFalse(os.path.exists(out), 'a bad request leaves no receipt folder behind')
        code, record, _ = self.run_ci(repo, '--event', 'workflow_dispatch', '--input', 'suite=core')
        self.assertEqual([j['result'] for j in record['workflows'][0]['jobs']], ['success', 'skipped'])
        self.assertEqual(record['event']['inputs'], {'suite': 'core'})
        code, record, _ = self.run_ci(repo, '--event', 'push')
        self.assertEqual((code, record['result'], record['workflows'][0]['triggered']), (2, 'incomplete', False))

    def test_job_continue_on_error_bad_outputs_and_files_outside_the_job(self):
        repo = self.repo({'x.yml': EDGES})
        code, record, path = self.run_ci(repo)
        jobs = record['workflows'][0]['jobs']
        self.assertEqual((jobs[0]['result'], jobs[0].get('continue_on_error')), ('failure', True))
        self.assertEqual(self.steps(record, 1), ['fail', 'pass', 'pass'])
        self.assertIn('without "="', jobs[1]['steps'][0]['note'])
        self.assertEqual(jobs[1]['steps'][2]['outside_job_folder'], 1)
        kept = os.path.join(os.path.dirname(path), 'artifacts', 'mixed')
        self.assertEqual([os.path.relpath(os.path.join(r, n), kept) for r, _d, ns in os.walk(kept) for n in ns],
                         [os.path.join('_runner', 'temp', 'inside.txt')])
        self.assertEqual((code, record['result']), (0, 'pass'))
        self.assertEqual(C.verify_receipt(path, repo)[0], [])

    def test_a_step_stops_at_its_timeout(self):
        code, record, _ = self.run_ci(self.repo({'x.yml': SLOW}))
        step = record['workflows'][0]['jobs'][0]['steps'][0]
        self.assertEqual((record['result'], step['result'], step['note']), ('fail', 'fail', 'stopped at its timeout'))
        self.assertLess(step['duration_ms'], 10000)


if __name__ == '__main__':
    unittest.main()
