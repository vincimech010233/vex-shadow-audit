#!/usr/bin/env python3
"""Bounded offline diagnostic for a declared OpenVEX/PURL subset on Linux."""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

VERSION = '1.1.0'
MAX_BYTES = 2_000_000
MAX_TOTAL_BYTES = 16_000_000
MAX_FINDINGS = 10_000
MAX_PACKAGES = 20_000
MAX_STATEMENTS = 20_000
MAX_PRODUCTS = 20_000
MAX_REPOS = 16
MAX_DOCUMENTS = 128
MAX_WORK = 1_000_000
MAX_DEPTH = 64
MAX_OBSERVATIONS = 10_000
SUPPRESSING = {'not_affected', 'fixed'}
VALID_STATUSES = SUPPRESSING | {'affected', 'under_investigation'}
JUSTIFICATIONS = {'component_not_present', 'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist'}
SUPPORTED_TYPES = {'deb', 'apk', 'rpm', 'npm', 'maven', 'generic', 'pypi', 'golang', 'oci'}
NAME_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
TIME_RE = re.compile(r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$')

class InputError(ValueError):
    """Invalid, unsupported or over-budget input; never a negative verdict."""

@dataclass
class Budget:
    bytes_read: int = 0
    documents: int = 0
    work: int = 0
    def consume(self, amount: int = 1) -> None:
        self.work += amount
        if self.work > MAX_WORK:
            raise InputError('comparison budget exceeded; split the audit')

def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise InputError(f'{label} requires nonempty text without control characters (<=4096 chars)')
    return value

def open_directory(path: Path) -> int:
    """Walk from / using pinned directory descriptors; reject every symlink."""
    absolute = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

def json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f'duplicate JSON key: {key}')
        result[key] = value
    return result

def check_depth(text: str) -> None:
    depth = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': in_string = False
        elif char == '"': in_string = True
        elif char in '[{':
            depth += 1
            if depth > MAX_DEPTH: raise InputError('JSON nesting limit exceeded')
        elif char in ']}': depth -= 1

def reject_constant(value: str) -> None:
    raise InputError(f'nonstandard JSON number: {value}')

def read_json(path: Path, budget: Budget | None = None) -> Any:
    fd = parent = None
    try:
        parent = open_directory(path.parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        if not stat.S_ISREG(os.fstat(fd).st_mode): raise InputError(f'input must be regular file: {path}')
        if os.fstat(fd).st_size > MAX_BYTES: raise InputError(f'input too large: {path}')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES: raise InputError(f'input too large: {path}')
        if budget:
            budget.bytes_read += len(raw)
            if budget.bytes_read > MAX_TOTAL_BYTES: raise InputError('total input byte budget exceeded')
        text = raw.decode('utf-8')
        check_depth(text)
        return json.loads(text, object_pairs_hook=json_pairs, parse_constant=reject_constant)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise InputError(f'cannot read valid bounded JSON {path}: {exc}') from exc
    finally:
        if fd is not None: os.close(fd)
        if parent is not None: os.close(parent)

def inside_repo(root: Path, location: str) -> Path:
    require_text(location, 'document location')
    if '\\' in location or location.startswith('/') or any(p in ('', '.', '..') for p in location.split('/')):
        raise InputError(f'unsafe document location: {location}')
    # This early diagnostic is supplemented by descriptor-based opens at read time.
    current = root
    for part in location.split('/'):
        current = current / part
        if current.is_symlink(): raise InputError(f'symlink prohibited: {location}')
    return current

def decoded(value: str) -> str:
    if re.search(r'%(?![0-9A-Fa-f]{2})', value): raise InputError('invalid percent encoding in PURL')
    try: result = unquote(value, encoding='utf-8', errors='strict')
    except UnicodeError as exc: raise InputError('invalid encoded UTF-8 in PURL') from exc
    require_text(result, 'PURL segment')
    return result

def parse_purl(purl: str) -> tuple[str, str | None, dict[str, str], str | None]:
    require_text(purl, 'PURL')
    if not purl.startswith('pkg:') or any(c.isspace() for c in purl): raise InputError('invalid PURL scheme/whitespace')
    plain, mark, fragment = purl.partition('#')
    if mark and (not fragment or '#' in fragment): raise InputError('invalid PURL subpath')
    plain, querymark, query = plain.partition('?')
    if querymark and (not query or '?' in query): raise InputError('invalid PURL qualifiers')
    typ, slash, body = plain[4:].partition('/')
    typ = typ.lower()
    if not slash or typ not in SUPPORTED_TYPES: raise InputError(f'unsupported PURL type: {typ}')
    version = None
    if body.rfind('@') > body.rfind('/'):
        body, version = body.rsplit('@', 1)
        version = decoded(version)
    segments = [decoded(s) for s in body.split('/')]
    if any(s in ('.', '..') or '/' in s for s in segments): raise InputError('invalid PURL path segment')
    namespace, name = segments[:-1], segments[-1]
    if typ in {'deb', 'apk', 'rpm', 'golang'}: namespace = [s.lower() for s in namespace]
    if typ in {'deb', 'apk', 'golang'}: name = name.lower()
    if typ == 'pypi': name = name.lower().replace('_', '-')
    if typ in {'deb', 'apk', 'rpm', 'maven'} and not namespace: raise InputError(f'{typ} requires namespace')
    if typ in {'oci', 'pypi'} and namespace: raise InputError(f'{typ} namespace unsupported')
    if typ == 'npm' and (len(namespace) > 1 or (namespace and not namespace[0].startswith('@'))): raise InputError('invalid npm scope')
    if '@' in name: raise InputError('unencoded @ in package name unsupported')
    qualifiers = {}
    if query:
        for pair in query.split('&'):
            key, sep, value = pair.partition('=')
            key = key.lower()
            if not sep or not re.fullmatch(r'[a-z][a-z0-9._-]*', key) or key in qualifiers: raise InputError('invalid/duplicate PURL qualifier')
            qualifiers[key] = decoded(value)
    subpath = None
    if mark:
        parts = [decoded(s) for s in fragment.split('/')]
        if any(s in ('.', '..') or '/' in s for s in parts): raise InputError('invalid PURL subpath')
        subpath = '/'.join(parts)
    base = 'pkg:' + typ + '/' + '/'.join(quote(s, safe=':._~-') for s in namespace + [name])
    return base, version, qualifiers, subpath

def index_key(purl: str, *, index: bool = False) -> str:
    base, version, qualifiers, subpath = parse_purl(purl)
    if base.startswith('pkg:oci/'):
        if 'repository_url' not in qualifiers: raise InputError('OCI requires repository_url for repository audit')
        if index and (version or subpath or set(qualifiers) != {'repository_url'}): raise InputError('invalid OCI index key')
        return base + '?repository_url=' + quote(qualifiers['repository_url'], safe='')
    if index and (version or qualifiers or subpath): raise InputError('index PURL must be versionless/unqualified')
    return base

def applies(statement_purl: str, finding_purl: str) -> bool:
    p_base, p_version, p_qual, p_sub = parse_purl(statement_purl)
    f_base, f_version, f_qual, f_sub = parse_purl(finding_purl)
    # go-vex v0.2.7 PurlMatches ignores subpath. Reject it instead of claiming parity.
    if p_sub or f_sub: raise InputError('PURL subpath matching unsupported in this audit profile')
    return p_base == f_base and (p_version is None or p_version == f_version) and all(f_qual.get(k) == v for k, v in p_qual.items())

def date_value(timestamp: Any) -> int | None:
    if not isinstance(timestamp, str): return None
    match = TIME_RE.fullmatch(timestamp)
    if not match: return None
    day, clock, fraction, offset = match.groups()
    try:
        if offset != 'Z' and (int(offset[1:3]) > 23 or int(offset[4:]) > 59): return None
        d = datetime.fromisoformat(day + 'T' + clock + ('+00:00' if offset == 'Z' else offset))
        delta = d.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int((fraction or '0').ljust(9, '0'))
    except (ValueError, OverflowError): return None

@dataclass
class Statement:
    names: tuple[str, ...]
    primary: str
    timestamp: int
    status: str
    purls: tuple[str, ...]

@dataclass
class Document:
    by_vulnerability: dict[str, list[Statement]] = field(default_factory=dict)
    def verdict(self, purl: str, cve: str, budget: Budget) -> tuple[str | None, str]:
        statements = self.by_vulnerability.get(cve, [])
        if not statements: return None, 'NO_VULNERABILITY_STATEMENT'
        matches = []
        for statement in statements:
            for product in statement.purls:
                budget.consume()
                if applies(product, purl):
                    matches.append(statement)
                    break
        if not matches: return None, 'NO_APPLICABLE_PRODUCT'
        # go-vex sorts aliases by primary name before time; decline ambiguous histories.
        if len({s.primary for s in matches}) > 1: raise InputError('alias histories with different primary names unsupported')
        latest = max(s.timestamp for s in matches)
        statuses = {s.status for s in matches if s.timestamp == latest}
        if len(statuses) != 1: raise InputError('contradictory verdicts at identical timestamps')
        return statuses.pop(), 'APPLICABLE_STATEMENT'

def compile_document(document: Any) -> Document:
    if not isinstance(document, dict): raise InputError('OpenVEX must be object')
    if document.get('@context') != 'https://openvex.dev/ns/v0.2.0': raise InputError('only OpenVEX context v0.2.0 supported')
    for key in ('@id', 'author'): require_text(document.get(key), key)
    if not re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', document['@id']): raise InputError('document @id must be absolute IRI')
    if type(document.get('version')) is not int or document['version'] < 1: raise InputError('positive integer document version required')
    if date_value(document.get('timestamp')) is None: raise InputError('valid RFC3339 document timestamp required')
    statements = document.get('statements')
    if not isinstance(statements, list) or len(statements) > MAX_STATEMENTS: raise InputError('bounded statements array required')
    result = Document()
    count = 0
    for s in statements:
        if not isinstance(s, dict): raise InputError('statement must be object')
        status = s.get('status')
        if not isinstance(status, str) or status not in VALID_STATUSES: raise InputError('invalid VEX status')
        if status == 'not_affected':
            justification = s.get('justification')
            if justification is not None and (not isinstance(justification, str) or justification not in JUSTIFICATIONS): raise InputError('invalid justification')
            if justification is None: require_text(s.get('impact_statement'), 'not_affected impact_statement')
        if status == 'affected': require_text(s.get('action_statement'), 'affected action_statement')
        timestamp = date_value(s.get('timestamp', document['timestamp']))
        if timestamp is None: raise InputError('invalid statement timestamp')
        vuln = s.get('vulnerability')
        if not isinstance(vuln, dict): raise InputError('vulnerability must be object')
        primary = vuln.get('name', vuln.get('@id'))
        require_text(primary, 'vulnerability name or @id')
        aliases = vuln.get('aliases', [])
        if not isinstance(aliases, list): raise InputError('aliases must be array')
        names = [primary] + aliases + ([vuln['@id']] if '@id' in vuln else [])
        for name in names: require_text(name, 'vulnerability identifier')
        products = s.get('products')
        if not isinstance(products, list) or not products: raise InputError('nonempty products required')
        count += len(products)
        if count > MAX_PRODUCTS: raise InputError('document product budget exceeded')
        purls = []
        for prod in products:
            if not isinstance(prod, dict): raise InputError('product must be object')
            if 'subcomponents' in prod and (not isinstance(prod['subcomponents'], list) or prod['subcomponents']):
                raise InputError('subcomponents need scanner context; only empty arrays supported')
            ids = prod.get('identifiers', {})
            if not isinstance(ids, dict): raise InputError('identifiers must be object')
            product_id = prod.get('@id')
            if product_id is not None: require_text(product_id, 'product @id')
            candidates = ([product_id] if isinstance(product_id, str) and product_id.startswith('pkg:') else [])
            if 'purl' in ids: candidates.append(require_text(ids['purl'], 'identifiers.purl'))
            if not candidates: raise InputError('product needs @id PURL or identifiers.purl; CPE/hash-only unsupported')
            for candidate in candidates:
                if parse_purl(candidate)[3]: raise InputError('PURL subpaths unsupported')
                purls.append(candidate)
        statement = Statement(tuple(set(names)), primary, timestamp, status, tuple(purls))
        for name in statement.names: result.by_vulnerability.setdefault(name, []).append(statement)
    return result

def find_verdict(document: Any, purl: str, cve: str) -> str | None:
    return compile_document(document).verdict(purl, cve, Budget())[0]

class Repository:
    def __init__(self, name: str, root: Path, budget: Budget):
        if not NAME_RE.fullmatch(name): raise InputError('invalid repository name')
        self.name, self.root, self.budget = name, root, budget
        index = read_json(root / 'index.json', budget)
        if not isinstance(index, dict) or not isinstance(index.get('packages'), list): raise InputError('index requires packages array')
        if date_value(index.get('updated_at')) is None: raise InputError('index updated_at required')
        if len(index['packages']) > MAX_PACKAGES: raise InputError('too many index entries')
        self.lookup: dict[str, Path] = {}
        for entry in index['packages']:
            if not isinstance(entry, dict): raise InputError('invalid index entry')
            if entry.get('format', 'openvex') != 'openvex': raise InputError('unsupported index format; CSAF cannot be skipped without changing precedence')
            key = index_key(entry.get('id'), index=True)
            path = inside_repo(root, entry.get('location'))
            if key in self.lookup: raise InputError('duplicate indexed PURL')
            self.lookup[key] = path
        self.cache: dict[Path, Document] = {}
    def verdict(self, purl: str, cve: str) -> tuple[bool, str | None, str]:
        path = self.lookup.get(index_key(purl))
        if path is None: return False, None, 'NOT_INDEXED'
        if path not in self.cache:
            self.budget.documents += 1
            if self.budget.documents > MAX_DOCUMENTS: raise InputError('document budget exceeded')
            self.cache[path] = compile_document(read_json(path, self.budget))
        status, reason = self.cache[path].verdict(purl, cve, self.budget)
        return True, status, reason

def run_audit(repo_specs: list[str], findings_path: Path) -> dict[str, Any]:
    if not 2 <= len(repo_specs) <= MAX_REPOS: raise InputError(f'provide 2..{MAX_REPOS} repositories in priority order')
    budget = Budget()
    repos = []
    for spec in repo_specs:
        name, sep, path = spec.partition('=')
        if not sep or not path: raise InputError('use NAME=DIR')
        repos.append(Repository(name, Path(path), budget))
    if len({r.name for r in repos}) != len(repos): raise InputError('duplicate repository names')
    findings = read_json(findings_path, budget)
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS: raise InputError('bounded findings array required')
    observations, assessments = [], []
    verdict_cache = {}
    for idx, finding in enumerate(findings):
        if not isinstance(finding, dict): raise InputError('finding must be object')
        if set(finding) != {'purl', 'vulnerability'}: raise InputError('finding requires exactly purl/vulnerability; scanner context unsupported')
        purl, cve = finding['purl'], finding['vulnerability']
        if parse_purl(purl)[3]: raise InputError('finding PURL subpaths unsupported')
        if not isinstance(cve, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve): raise InputError('only CVE finding identifiers supported')
        cache_key = (purl, cve)
        if cache_key not in verdict_cache:
            chain = []
            for repo in repos:
                indexed, status, reason = repo.verdict(purl, cve)
                chain.append({'repository': repo.name, 'indexed': indexed, 'status': status, 'reason': reason})
            verdict_cache[cache_key] = chain
        chain = verdict_cache[cache_key]
        assessments.append({'finding_index': idx, 'chain': chain})
        indexed_chain = [entry for entry in chain if entry['indexed']]
        if len(indexed_chain) < 2: continue
        first = indexed_chain[0]
        for lower in indexed_chain[1:]:
            if lower['status'] not in SUPPRESSING or first['status'] in SUPPRESSING: continue
            kind = 'SILENT_SHADOW' if first['status'] is None else 'STATUS_CONFLICT_REVIEW'
            if len(observations) >= MAX_OBSERVATIONS: raise InputError('observation budget exceeded; split the audit')
            observations.append({'finding_index': idx, 'purl': purl, 'vulnerability': cve, 'kind': kind,
                'higher_repository': first['repository'], 'higher_status': first['status'], 'higher_reason': first['reason'],
                'lower_repository': lower['repository'], 'lower_status': lower['status'],
                'interpretation': 'Candidate under the supported profile; manually confirm with your scanner version. No suppression recommended.'})
    return {'tool': 'vex-shadow-audit', 'version': VERSION, 'evidence_classification': 'INFERRED',
        'profile': 'OpenVEX-0.2-PURL-subset; package precedence reviewed against Trivy v0.73.0 source; no runtime parity claim',
        'repositories_in_priority_order': [r.name for r in repos], 'findings_checked': len(findings),
        'observations': observations, 'assessments': assessments,
        'summary': {'silent_shadow': sum(o['kind'] == 'SILENT_SHADOW' for o in observations),
            'status_conflict_review': sum(o['kind'] == 'STATUS_CONFLICT_REVIEW' for o in observations)},
        'coverage': 'Only documents referenced by supplied findings are opened; other documents are NOT_VERIFIED.',
        'resources': vars(budget), 'safety': 'Informational only. Never auto-suppress or assert exploitability.'}

def render_markdown(report: dict[str, Any]) -> str:
    lines = ['# Offline VEX shadow audit', '', 'Classification: INFERRED (model candidates).',
        f"Findings checked: {report['findings_checked']}", f"Silent shadows: {report['summary']['silent_shadow']}",
        f"Policy/status conflicts: {report['summary']['status_conflict_review']}", '',
        '| Result | Vulnerability | Higher priority | Lower priority | PURL |', '| --- | --- | --- | --- | --- |']
    def esc(value: Any) -> str:
        text = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', ' ').replace('\r', ' ')
        return re.sub(r'([\\`*_{}\[\]()!|])', r'\\\1', text)
    for obs in report['observations']:
        lines.append('| ' + ' | '.join(obs[k] if k == 'kind' else esc(obs[k]) for k in ('kind', 'vulnerability', 'higher_repository', 'lower_repository', 'purl')) + ' |')
    lines.extend(['', '**Warning:** Review manually; no automatic suppression.', '', report['coverage'], ''])
    return '\n'.join(lines)

def write_reports(outputs: list[tuple[Path, str]]) -> None:
    """Exclusive creation; pinned parents, no overwrites, rollback on ordinary failure."""
    prepared, created = [], []
    try:
        identities = set()
        for path, text in outputs:
            parent = open_directory(path.parent)
            prepared.append((parent, path.name, text))
            parent_stat = os.fstat(parent)
            identity = (parent_stat.st_dev, parent_stat.st_ino, path.name)
            if identity in identities: raise InputError('report destinations must be distinct')
            identities.add(identity)
            try: os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise InputError(f'report destination exists: {path}')
        for parent, name, text in prepared:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            created.append((parent, name))
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        for parent, name in reversed(created): os.unlink(name, dir_fd=parent)
        raise
    finally:
        for parent, _, _ in prepared: os.close(parent)

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description='Bounded offline OpenVEX priority diagnostic (Linux)')
    ap.add_argument('--repo', action='append', required=True, metavar='NAME=DIR')
    ap.add_argument('--findings', required=True, type=Path)
    ap.add_argument('--json-out', required=True, type=Path, help='New file; existing destinations are refused')
    ap.add_argument('--markdown-out', required=True, type=Path, help='New file; existing destinations are refused')
    args = ap.parse_args(argv)
    try:
        report = run_audit(args.repo, args.findings)
        write_reports([(args.json_out, json.dumps(report, indent=2, ensure_ascii=False) + '\n'), (args.markdown_out, render_markdown(report))])
        print(f"Checked {report['findings_checked']} findings; {report['summary']['silent_shadow']} silent shadows; {report['summary']['status_conflict_review']} conflicts")
        return 0
    except (InputError, OSError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
