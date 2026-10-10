import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from vex_shadow_audit import InputError, applies, find_verdict, inside_repo, parse_purl, run_audit, main, render_markdown

ROOT = Path(__file__).parents[1]
HIGH = ROOT / 'examples' / 'repo_high'
LOW = ROOT / 'examples' / 'repo_low'
FINDINGS = ROOT / 'examples' / 'findings.json'

class VexAuditTest(unittest.TestCase):
    def check(self):
        return run_audit([f'high={HIGH}', f'low={LOW}'], FINDINGS)

    def test_silent_and_conflict(self):
        report = self.check()
        self.assertEqual(report['findings_checked'], 3)
        self.assertEqual(report['summary'], {'silent_shadow': 1, 'status_conflict_review': 1})
        self.assertEqual(report['observations'][0]['kind'], 'SILENT_SHADOW')
        self.assertIsNone(report['observations'][0]['higher_status'])
        self.assertEqual(report['observations'][1]['kind'], 'STATUS_CONFLICT_REVIEW')
        self.assertIn('Warning', render_markdown(report))

    def test_reverse_priority_safe(self):
        report = run_audit([f'low={LOW}', f'high={HIGH}'], FINDINGS)
        self.assertEqual(report['summary']['silent_shadow'], 0)
        self.assertEqual(report['summary']['status_conflict_review'], 0)

    def test_conservative_purl(self):
        self.assertTrue(applies('pkg:deb/debian/perl-base', 'pkg:deb/debian/perl-base@1?arch=amd64'))
        self.assertTrue(applies('pkg:deb/debian/perl-base@1', 'pkg:deb/debian/perl-base@1?arch=amd64'))
        self.assertFalse(applies('pkg:deb/debian/perl-base@2', 'pkg:deb/debian/perl-base@1'))
        self.assertFalse(applies('pkg:deb/debian/perl-base@1?arch=arm64', 'pkg:deb/debian/perl-base@1?arch=amd64'))
        self.assertFalse(applies('pkg:deb/debian/other', 'pkg:deb/debian/perl-base@1'))
        with self.assertRaises(InputError): parse_purl('http://somewhere')

    def test_missing_repos_and_duplicates(self):
        with self.assertRaises(InputError): run_audit([f'high={HIGH}'], FINDINGS)
        with self.assertRaises(InputError): run_audit([f'high={HIGH}', f'high={LOW}'], FINDINGS)

    def test_json_errors(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'bad.json'
            p.write_text('{', encoding='utf-8')
            with self.assertRaises(InputError): run_audit([f'high={HIGH}', f'low={LOW}'], p)
            p.write_text('{"bad":"shape"}', encoding='utf-8')
            with self.assertRaises(InputError): run_audit([f'high={HIGH}', f'low={LOW}'], p)

    def test_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaises(InputError): inside_repo(root, '../bad.json')
            with self.assertRaises(InputError): inside_repo(root, '/tmp/bad.json')
            (root / 'link').symlink_to('/tmp')
            with self.assertRaises(InputError): inside_repo(root, 'link/foo')

    def test_contradiction(self):
        doc = {'@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'https://example.invalid/contradiction',
               'author': 'Synthetic Fixture', 'version': 1, 'timestamp':'2026-10-09T12:00:00Z', 'statements':[
            {'vulnerability':{'name':'CVE-2026-12345'}, 'products':[{'@id':'pkg:deb/debian/perl-base'}], 'status':'affected', 'action_statement': 'Review synthetic fixture.'},
            {'vulnerability':{'name':'CVE-2026-12345'}, 'products':[{'@id':'pkg:deb/debian/perl-base'}], 'status':'not_affected', 'justification': 'component_not_present'}]}
        with self.assertRaisesRegex(InputError, 'contradictory verdicts at identical timestamps'):find_verdict(doc,'pkg:deb/debian/perl-base@1','CVE-2026-12345')

    def test_cli_writes_both_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            json_file, md_file = Path(td) / 'report.json', Path(td) / 'report.md'
            exit_code = main(['--repo', f'high={HIGH}', '--repo', f'low={LOW}', '--findings', str(FINDINGS), '--json-out', str(json_file), '--markdown-out', str(md_file)])
            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(json_file.read_text())['summary']['silent_shadow'],1)
            self.assertIn('SILENT_SHADOW', md_file.read_text())

if __name__ == '__main__':
    unittest.main()
