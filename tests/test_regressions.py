"""Synthetic regressions derived from independent sources and original failures."""
import itertools
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import vex_shadow_audit as v

P = 'pkg:deb/debian/perl-base@1?arch=amd64'
C = 'CVE-2026-11111'
T = '2026-10-09T12:00:00Z'

def statement(status='not_affected', purl=P, cve=C, **extra):
    s = {'vulnerability': {'name': cve}, 'products': [{'@id': purl}], 'status': status}
    if status == 'not_affected': s['justification'] = 'component_not_present'
    if status == 'affected': s['action_statement'] = 'Upgrade synthetic package.'
    s.update(extra)
    return s

def document(*statements):
    return {'@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'https://example.invalid/vex',
            'author': 'Synthetic', 'timestamp': T, 'version': 1, 'statements': list(statements)}

class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.findings = self.root / 'findings.json'
        self.findings.write_text(json.dumps([{'purl': P, 'vulnerability': C}]))
    def repo(self, name, doc=None, entries=None):
        root = self.root / name
        root.mkdir()
        if entries is None: entries = [{'id': 'pkg:deb/debian/perl-base', 'location': 'vex.json'}]
        (root/'index.json').write_text(json.dumps({'updated_at': T, 'packages': entries}))
        if doc is not None: (root/'vex.json').write_text(json.dumps(doc))
        return f'{name}={root}'
    def audit(self, docs):
        return v.run_audit([self.repo(str(i), doc) for i, doc in enumerate(docs)], self.findings)
    def cli(self, specs, out, md):
        return v.main([*sum((['--repo', r] for r in specs), []), '--findings', str(self.findings), '--json-out', str(out), '--markdown-out', str(md)])

class Semantics(Fixture):
    def test_fixed_is_suppressing(self):
        result = self.audit([document(), document(statement('fixed'))])
        self.assertEqual(result['summary']['silent_shadow'], 1)
        self.assertEqual(result['observations'][0]['lower_status'], 'fixed')
    def test_fixed_high_does_not_conflict_with_not_affected(self):
        self.assertEqual(self.audit([document(statement('fixed')), document(statement())])['observations'], [])
    def test_all_lower_repositories_reported(self):
        result = self.audit([document(), document(statement()), document(statement('fixed'))])
        self.assertEqual(result['summary']['silent_shadow'], 2)
    def test_absence_reasons_distinct(self):
        result = self.audit([document(statement(cve='CVE-2026-99999')), document(statement(purl='pkg:deb/debian/perl-base@2')), document(statement())])
        chain = result['assessments'][0]['chain']
        self.assertEqual([e['reason'] for e in chain], ['NO_VULNERABILITY_STATEMENT', 'NO_APPLICABLE_PRODUCT', 'APPLICABLE_STATEMENT'])
    def test_empty_repositories(self):
        specs = [self.repo('a', entries=[]), self.repo('b', entries=[])]
        result = v.run_audit(specs, self.findings)
        self.assertEqual(result['observations'], [])
        self.assertEqual(result['assessments'][0]['chain'][0]['reason'], 'NOT_INDEXED')
    def test_duplicates_findings_preserve_indices(self):
        self.findings.write_text(json.dumps([{'purl': P, 'vulnerability': C}]*2))
        result = self.audit([document(), document(statement())])
        self.assertEqual([o['finding_index'] for o in result['observations']], [0,1])
        self.assertEqual(result['resources']['work'], 1)
    def test_repository_permutations(self):
        specs = [self.repo('silent', document()), self.repo('suppress', document(statement())), self.repo('affected', document(statement('affected')))]
        for order in itertools.permutations(specs):
            with self.subTest(order=order):
                report = v.run_audit(list(order), self.findings)
                expected = {'silent':(1,0),'suppress':(0,0),'affected':(0,1)}[order[0].split('=')[0]]
                self.assertEqual(tuple(report['summary'].values()), expected)
    def test_latest_status_overrides_old(self):
        doc = document(statement(timestamp='2026-10-01T00:00:00Z'), statement('under_investigation', timestamp=T))
        self.assertEqual(v.find_verdict(doc, P, C), 'under_investigation')
    def test_nanoseconds_not_conflated(self):
        doc = document(statement('affected', timestamp='2026-10-09T12:00:00.123456001Z'), statement(timestamp='2026-10-09T12:00:00.123456999Z'))
        self.assertEqual(v.find_verdict(doc, P, C), 'not_affected')
    def test_offsets_and_invalid_dates(self):
        self.assertEqual(v.date_value(T), v.date_value('2026-10-09T14:00:00+02:00'))
        for t in ('2026-13-01T00:00:00Z','2026-10-09 12:00:00Z','2026-10-09T12:00:00','2026-10-09T12:00:00+25:00'):
            self.assertIsNone(v.date_value(t))
    def test_same_timestamp_conflict_and_duplicate(self):
        with self.assertRaises(v.InputError): v.find_verdict(document(statement(), statement('affected')), P, C)
        self.assertEqual(v.find_verdict(document(statement(), statement()), P, C), 'not_affected')
    def test_alias_and_identifiers_purl(self):
        s = statement(cve='GHSA-synthetic')
        s['vulnerability']['aliases'] = [C]
        s['products'] = [{'@id': 'https://example.invalid/product', 'identifiers': {'purl': P}}]
        self.assertEqual(v.find_verdict(document(s), P, C), 'not_affected')
    def test_alias_ambiguous_histories_rejected(self):
        s = statement(cve='GHSA-synthetic'); s['vulnerability']['aliases']=[C]
        with self.assertRaises(v.InputError): v.find_verdict(document(statement(), s), P, C)
    def test_csaf_not_skipped(self):
        specs=[self.repo('csaf',entries=[{'id':'pkg:deb/debian/perl-base','location':'vex.json','format':'csaf'}]),self.repo('low',document(statement()))]
        with self.assertRaises(v.InputError): v.run_audit(specs,self.findings)
    def test_invalid_nonmatching_statement_rejected(self):
        s=statement(cve='CVE-2026-99999');s['status']=[]
        with self.assertRaises(v.InputError):v.find_verdict(document(s),P,C)
    def test_metadata_and_required_fields(self):
        for field in ('@context','@id','author','timestamp','version','statements'):
            with self.subTest(field=field):
                d=document(statement());del d[field]
                with self.assertRaises(v.InputError):v.find_verdict(d,P,C)
        for status in ([], {}, None, 7, 'bogus'):
            s=statement();s['status']=status
            with self.assertRaises(v.InputError):v.find_verdict(document(s),P,C)
        s=statement();del s['justification']
        with self.assertRaises(v.InputError):v.find_verdict(document(s),P,C)
        s['impact_statement']='Synthetic reason.'
        self.assertEqual(v.find_verdict(document(s),P,C),'not_affected')
    def test_subcomponent_context_rejected(self):
        s=statement();s['products'][0]['subcomponents']=[{'@id':'pkg:generic/other'}]
        with self.assertRaises(v.InputError):v.find_verdict(document(s),P,C)
    def test_subcomponent_field_types_rejected(self):
        for value in ({}, '', None, 1):
            s=statement();s['products'][0]['subcomponents']=value
            with self.assertRaises(v.InputError):v.find_verdict(document(s),P,C)
    def test_observation_budget(self):
        with patch.object(v,'MAX_OBSERVATIONS',0),self.assertRaises(v.InputError):
            self.audit([document(),document(statement())])
    def test_markdown_identifiers_are_inert(self):
        result=self.audit([document(),document(statement())])
        result['observations'][0]['purl']='pkg:generic/![fixture](image.png)<tag>|x'
        rendered=v.render_markdown(result)
        self.assertNotIn('![fixture]',rendered)
        self.assertIn('&lt;tag&gt;',rendered)
        self.assertIn('\\|x',rendered)
    def test_malformed_findings(self):
        specs=[self.repo('high',document()),self.repo('low',document(statement()))]
        for bad in ([{'purl':P}], [{'purl':P,'vulnerability':'GHSA-synthetic'}], [{'purl':P,'vulnerability':C,'subcomponent':'pkg:generic/other'}], [None]):
            self.findings.write_text(json.dumps(bad))
            with self.assertRaises(v.InputError):v.run_audit(specs,self.findings)

class PurlTests(unittest.TestCase):
    def test_maven_case_and_encoding(self):
        self.assertFalse(v.applies('pkg:maven/com.example/Artifact@1','pkg:maven/com.example/artifact@1'))
        self.assertTrue(v.applies('pkg:maven/com.example/%41rtifact@1','pkg:maven/com.example/Artifact@1'))
    def test_plus_is_literal_and_percent_decoded(self):
        self.assertTrue(v.applies('pkg:deb/debian/a@1%2B2','pkg:deb/debian/a@1+2'))
        self.assertFalse(v.applies('pkg:generic/a?tag=1+2','pkg:generic/a?tag=1%202'))
    def test_normalization_and_similar_names(self):
        self.assertTrue(v.applies('pkg:deb/Debian/A','pkg:deb/debian/a@1'))
        self.assertTrue(v.applies('pkg:pypi/My_Package','pkg:pypi/my-package@1'))
        self.assertFalse(v.applies('pkg:deb/debian/perl','pkg:deb/debian/perl-base@1'))
        self.assertTrue(v.applies('pkg:npm/%40scope/name','pkg:npm/@scope/name@1'))
    def test_oci_repository_identity(self):
        a='pkg:oci/image?repository_url=registry.example/a'
        b='pkg:oci/image?repository_url=registry.example/b'
        self.assertNotEqual(v.index_key(a,index=True),v.index_key(b,index=True))
        self.assertEqual(v.index_key(a,index=True),v.index_key(a.replace('image?','image@sha256:abc?')))
    def test_invalid_purls(self):
        for p in ('pkg:deb/','pkg:generic/','pkg:generic/a?arch=amd64&ARCH=arm64','pkg:generic/a%GG','pkg:generic/a@','pkg:generic/a#../b','pkg:unknown/a','pkg:generic/a?x=','pkg:generic/a//b'):
            with self.subTest(p=p), self.assertRaises(v.InputError): v.parse_purl(p)
    def test_lone_surrogates_controlled(self):
        for p in ('pkg:generic/\ud800', 'pkg:generic/a?x=\udfff', 'pkg:generic/%ED%A0%80'):
            with self.assertRaises(v.InputError):v.parse_purl(p)
    def test_subpath_declined(self):
        with self.assertRaises(v.InputError):v.applies('pkg:generic/a#path','pkg:generic/a#path')
    def test_qualifier_and_version_direction_properties(self):
        for version in ('1','2','3'):
            self.assertTrue(v.applies('pkg:generic/a',f'pkg:generic/a@{version}?arch=a'))
        self.assertFalse(v.applies('pkg:generic/a@1','pkg:generic/a'))
        self.assertFalse(v.applies('pkg:generic/a?arch=a','pkg:generic/a?arch=b'))

class IOTests(Fixture):
    def test_bad_json_and_duplicate_keys(self):
        for data in ('{','{"x":1,"x":2}','[NaN]','[Infinity]','['*65+'0'+']'*65):
            self.findings.write_text(data)
            with self.assertRaises(v.InputError):v.read_json(self.findings)
        self.findings.write_bytes(b'\xff')
        with self.assertRaises(v.InputError):v.read_json(self.findings)
    def test_oversized_file_and_aggregate(self):
        self.findings.write_bytes(b' '*(v.MAX_BYTES+1))
        with self.assertRaises(v.InputError):v.read_json(self.findings)
        self.findings.write_text('[]')
        with self.assertRaises(v.InputError):v.read_json(self.findings,v.Budget(bytes_read=v.MAX_TOTAL_BYTES))
    def test_missing_file_and_directory_input(self):
        for path in (self.root/'missing',self.root):
            with self.assertRaises(v.InputError):v.read_json(path)
    def test_fifo_is_rejected_without_block(self):
        p=self.root/'fifo';os.mkfifo(p)
        with self.assertRaises(v.InputError):v.read_json(p)
    def test_symlink_leaf_and_ancestor(self):
        leaf=self.root/'link.json';leaf.symlink_to(self.findings)
        with self.assertRaises(v.InputError):v.read_json(leaf)
        directory=self.root/'linkdir';directory.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(v.InputError):v.read_json(directory/'findings.json')
    def test_paths_rejected(self):
        for location in ('../a','/tmp/a','a/../b','a//b','./a','a\\b','a\x00b'):
            with self.assertRaises(v.InputError):v.inside_repo(self.root,location)
    def test_missing_document_and_duplicate_index(self):
        specs=[self.repo('missing'),self.repo('low',document(statement()))]
        with self.assertRaises(v.InputError):v.run_audit(specs,self.findings)
        root=self.root/'missing';entry={'id':'pkg:deb/debian/perl-base','location':'vex.json'}
        (root/'index.json').write_text(json.dumps({'updated_at':T,'packages':[entry,entry]}))
        with self.assertRaises(v.InputError):v.run_audit(specs,self.findings)
    def test_input_not_overwritten(self):
        before=self.findings.read_bytes()
        specs=[self.repo('high',document()),self.repo('low',document(statement()))]
        self.assertEqual(self.cli(specs,self.findings,self.root/'report.md'),2)
        self.assertEqual(self.findings.read_bytes(),before)
        self.assertFalse((self.root/'report.md').exists())
    def test_existing_second_output_no_partial_first(self):
        second=self.root/'report.md';second.write_text('existing')
        with self.assertRaises(v.InputError):v.write_reports([(self.root/'report.json','{}'),(second,'overwrite')])
        self.assertFalse((self.root/'report.json').exists());self.assertEqual(second.read_text(),'existing')
    def test_same_output_and_symlink_output(self):
        p=self.root/'report'
        with self.assertRaises(v.InputError):v.write_reports([(p,'a'),(p,'b')])
        p.symlink_to(self.findings)
        with self.assertRaises(v.InputError):v.write_reports([(p,'a')])
    def test_output_symlink_ancestor(self):
        (self.root/'link').symlink_to(self.root)
        with self.assertRaises(OSError):v.write_reports([(self.root/'link'/'report','a')])
    def test_write_failure_rolls_back(self):
        p=self.root/'out'
        with patch.object(v.os,'fsync',side_effect=OSError('synthetic write failure')):
            with self.assertRaises(OSError):v.write_reports([(p,'a')])
        self.assertFalse(p.exists())
    def test_permissions_and_nonprivileged_run(self):
        self.assertNotEqual(os.geteuid(),0,'tests should run as unprivileged user')
        self.findings.chmod(0)
        try:
            with self.assertRaises(v.InputError):v.read_json(self.findings)
        finally:self.findings.chmod(0o600)
        d=self.root/'locked';d.mkdir();d.chmod(0o500)
        try:
            with self.assertRaises(OSError):v.write_reports([(d/'out','a')])
        finally:d.chmod(0o700)
    def test_output_mode(self):
        p=self.root/'out';v.write_reports([(p,'a')])
        self.assertEqual(p.stat().st_mode&0o777,0o600)
    def test_comparison_budget(self):
        with patch.object(v,'MAX_WORK',0):
            with self.assertRaises(v.InputError):v.find_verdict(document(statement()),P,C)
    def test_collection_budgets(self):
        for limit in ('MAX_STATEMENTS','MAX_PRODUCTS'):
            with patch.object(v,limit,0),self.assertRaises(v.InputError):v.compile_document(document(statement()))
        specs=[self.repo('high',document()),self.repo('low',document(statement()))]
        for limit in ('MAX_REPOS','MAX_DOCUMENTS','MAX_PACKAGES','MAX_FINDINGS'):
            with patch.object(v,limit,0),self.assertRaises(v.InputError):v.run_audit(specs,self.findings)
    def test_cli_does_not_open_socket(self):
        specs=[self.repo('high',document()),self.repo('low',document(statement()))]
        with patch('socket.socket',side_effect=AssertionError('network forbidden')):
            self.assertEqual(self.cli(specs,self.root/'report.json',self.root/'report.md'),0)
    def test_cli_controlled_error_no_traceback(self):
        specs=[self.repo('high',document(statement(status=[]))),self.repo('low',document(statement()))]
        result=subprocess.run([sys.executable,str(Path(v.__file__)),*sum((['--repo',r] for r in specs),[]),'--findings',str(self.findings),'--json-out',str(self.root/'o.json'),'--markdown-out',str(self.root/'o.md')],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,2);self.assertNotIn('Traceback',result.stderr)

if __name__=='__main__':unittest.main()
