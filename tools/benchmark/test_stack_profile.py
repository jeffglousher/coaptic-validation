import copy
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import stack_profile as sp

IDENTITY = dict(source='sha256:source', tool='sampler 1', workload='w', capture='sha256:capture', platform='Windows', cohort='one')
PERF = ('bench-rust-serv 0/0 0.000000000: PERF_RECORD_COMM: bench-rust-serv:12396/12396\n'
        'bench-rust-serv 12396/12396 400.825079115: 1003009 cpu-clock:\n'
        '\tabcd leaf;<x> ([kernel.kallsyms])\n\t1234 root::λ (/bin/app)\n\n')


def profile():
    return dict(schema=sp.SCHEMA, identity=copy.deepcopy(IDENTITY), measurement=dict(kind='sampled_cpu', unit='samples'),
                quality=dict(lost=None, unresolved=None, refused=None, notes='unknown'),
                scope=dict(pid=1, tid=2, label='process', cpu_mode='unknown'),
                totals=dict(samples=3, weight=6), stacks=[
                    dict(frames=['a', 'b', 'a'], weight=2, samples=1),
                    dict(frames=['a', 'b'], weight=4, samples=2)])


def html_data(p):
    html = sp.render_html(p)
    payload = html.split('const data=JSON.parse(', 1)[1].split(');const p=', 1)[0]
    return json.loads(json.loads(payload))


class ProfileTests(unittest.TestCase):
    def test_aggregate_recursive(self):
        self.assertEqual(sp.aggregate(profile()), {'a': {'self': 2, 'inclusive': 6}, 'b': {'self': 4, 'inclusive': 6}})

    def test_perf_metadata_and_unknowns(self):
        p = sp.parse_perf_script(PERF, IDENTITY, 'service')
        self.assertEqual(p['stacks'][0]['frames'], ['root::λ', 'leaf;<x>'])
        e = p['stacks'][0]['event']
        self.assertEqual((e['timestamp'], e['period'], e['addresses'], e['dsos']), ('400.825079115', 1003009, ['1234', 'abcd'], ['/bin/app', '[kernel.kallsyms]']))
        self.assertEqual(p['scope']['cpu_mode'], 'unknown')
        self.assertIsNone(p['quality']['lost'])
        self.assertEqual(p['totals'], {'samples': 1, 'weight': 1003009})

    def test_perf_refusals(self):
        for text in (PERF.replace('12396/12396 400.', '12396/12397 400.', 1) + PERF,
                     PERF.replace('cpu-clock:', 'cycles:'), PERF + 'strange header\n',
                     PERF.replace('\tabcd leaf;<x> ([kernel.kallsyms])', '\tbroken frame'),
                     'x 1/1 1.0: 3 cpu-clock:\n', PERF.replace('1003009 cpu-clock:', '0 cpu-clock:'), PERF.rstrip()):
            with self.subTest(text=text), self.assertRaises(ValueError): sp.parse_perf_script(text, IDENTITY, 'x')

    def test_canonical_event_measurement_contract(self):
        perf = sp.parse_perf_script(PERF + PERF, IDENTITY, 'service')
        windows = copy.deepcopy(perf)
        windows['measurement'] = dict(kind='sampled_cpu', unit='samples')
        windows['totals']['weight'] = 2
        for s in windows['stacks']:
            s['weight'] = 1
            s['event'].update(name='SampledProfile', period=1)
        for p in (perf, windows):
            self.assertEqual(sp.load_json(json.dumps(p)), p)
            self.assertEqual(html_data(p)['profile'], p)
        cases = []
        p = copy.deepcopy(perf); p['stacks'][1]['event']['name'] = 'cycles'; cases.append(p)
        p = copy.deepcopy(perf)
        for s in p['stacks']: s['event']['name'] = 'cycles'
        cases.append(p)
        for source, measurement in ((perf, dict(kind='elapsed_wall', unit='cpu-clock period')),
                                    (perf, dict(kind='sampled_cpu', unit='samples')),
                                    (windows, dict(kind='elapsed_wall', unit='samples')),
                                    (windows, dict(kind='sampled_cpu', unit='cpu-clock period'))):
            p = copy.deepcopy(source); p['measurement'] = measurement; cases.append(p)
        p = copy.deepcopy(windows); p['stacks'][1]['event']['name'] = 'cpu-clock'; cases.append(p)
        p = copy.deepcopy(windows); p['stacks'][0]['weight'] = 2
        p['stacks'][0]['event']['period'] = 2; p['totals']['weight'] = 3; cases.append(p)
        for p in cases:
            with self.subTest(p=p), self.assertRaises(ValueError): sp.validate_profile(p)

    def test_fractional_elapsed_flame_weights(self):
        p = profile()
        p['measurement'] = dict(kind='elapsed_wall', unit='seconds')
        p['stacks'] = [dict(frames=['root', 'shared', leaf], weight=w, samples=1)
                       for leaf, w in zip(('big', 'small1', 'small2'), (2**52, .5, .5))]
        p['totals'] = dict(samples=3, weight=math.fsum(s['weight'] for s in p['stacks']))
        decoded = html_data(p)
        n = decoded['tree']
        for name in ('All observed', 'root', 'shared'):
            self.assertEqual(n['name'], name)
            self.assertEqual(n['weight'], 2**52 + 1)
            if name != 'shared': n = n['children'][0]
        self.assertEqual([c['weight'] for c in n['children']], [2**52, .5, .5])
        self.assertEqual(decoded['table']['shared']['inclusive'], n['weight'])
        self.assertEqual(decoded['profile'], p)

    def test_flame_call_paths_and_terminal_weights(self):
        tree = html_data(profile())['tree']
        a = tree['children'][0]; b = a['children'][0]; recursive = b['children'][0]
        self.assertEqual([(n['name'], n['weight']) for n in (tree, a, b, recursive)],
                         [('All observed', 6), ('a', 6), ('b', 6), ('a', 2)])
        self.assertEqual(recursive['children'], [])

    def test_invalid_counts_weights_and_scope_fields(self):
        for v in (0, -1, float('nan'), float('inf'), 2**53, 10**400, True):
            p = profile(); p['stacks'][0]['weight'] = v
            with self.subTest(v=v), self.assertRaises(ValueError): sp.validate_profile(p)
        for mutate in (lambda p: p['totals'].update(samples=4), lambda p: p['totals'].update(weight=7),
                       lambda p: p['stacks'][0].update(samples=0), lambda p: p['scope'].update(extra='other'),
                       lambda p: p['measurement'].update(kind='both'), lambda p: p['quality'].update(lost=-1)):
            p = profile(); mutate(p)
            with self.assertRaises(ValueError): sp.validate_profile(p)

    def test_bounds_and_json(self):
        p = profile(); p['stacks'][0]['frames'] = ['a'] * 129
        with self.assertRaises(ValueError): sp.validate_profile(p)
        with self.assertRaises(ValueError): sp.load_json('{"schema":1,"schema":2}')
        with self.assertRaises(ValueError): sp.load_json(' ' * (sp.LIMIT + 1))
        p = profile(); p['quality']['lost'] = 0; p['quality']['unresolved'] = 7
        self.assertEqual(sp.load_json(json.dumps(p))['quality'], p['quality'])

    def test_safe_html_unicode_and_semicolon(self):
        p = profile(); p['stacks'][0]['frames'] = ['</script><script>alert(1)</script>\u2028', 'A;λ<T>']
        html = sp.render_html(p)
        self.assertNotIn('</script><script>alert', html)
        payload = html.split('const data=JSON.parse(', 1)[1].split(');const p=', 1)[0]
        decoded = json.loads(json.loads(payload))
        self.assertEqual(decoded['profile']['stacks'][0]['frames'], p['stacks'][0]['frames'])
        root = decoded['tree']['children'][0]
        self.assertEqual(root['name'], p['stacks'][0]['frames'][0])
        self.assertEqual(root['children'][0]['name'], p['stacks'][0]['frames'][1])
        self.assertNotIn('https://', html)
        self.assertIn('JSON.parse(', html)

    def test_html_output_limit_includes_tree(self):
        p = profile()
        size = len(sp.render_html(p).encode('utf-8'))
        with patch.object(sp, 'LIMIT', size - 1), self.assertRaisesRegex(ValueError, 'output too large'):
            sp.render_html(p)

    def test_fresh_output(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'result'
            sp.write_new(path, 'first')
            with self.assertRaises(FileExistsError): sp.write_new(path, 'second')
            self.assertEqual(path.read_text(), 'first')


if __name__ == '__main__': unittest.main()

