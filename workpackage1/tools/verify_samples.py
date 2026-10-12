"""Check provenance, line mapping, retained security context and input isolation.

Does not execute PHP, contact a target, or establish vulnerability ground truth.
"""
from pathlib import Path
import csv
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT.parents[1] / "source_projects"


def verify_state(meta):
    assert meta['runtime_validation'] in ('pending', 'validated', 'failed', 'inconclusive')
    if meta['runtime_validation'] == 'validated':
        assert meta.get('runtime_evidence'), 'validated metadata needs evidence'


def verify_complex(row, meta):
    sid = row['sample_id']
    assert meta['sample_kind'] == 'multifile_workflow'
    ids = set()
    total = 0
    for fragment in meta['fragments']:
        fid = fragment['fragment_id']
        assert fid not in ids
        ids.add(fid)
        raw = (ROOT / fragment['raw_file']).read_bytes()
        expected = subprocess.check_output(['git', '-C', str(SOURCES / row['project']), 'show', f"{row['commit']}:{fragment['source_file']}"])
        assert raw == expected
        assert hashlib.sha256(raw).hexdigest() == fragment['raw_sha256']
        normalized = (ROOT / fragment['normalized_file']).read_bytes()
        assert hashlib.sha256(normalized).hexdigest() == fragment['normalized_sha256']
        original_lines = raw.decode('utf-8').splitlines()
        normalized_lines = normalized.decode('utf-8').splitlines()
        mapping = read_csv(ROOT / fragment['line_map'])
        assert len(mapping) == len(normalized_lines) == fragment['normalized_lines']
        assert len(normalized_lines) <= 220
        selected = [n for a, b in fragment['selected_spans'] for n in range(a, b + 1)]
        used = []
        for i, item in enumerate(mapping, 1):
            assert int(item['normalized_line']) == i
            if item['operation'] == 'wrapper':
                assert not item['original_line'] and normalized_lines[i - 1] in ('<?php', '?>')
            else:
                assert item['operation'] == 'retained'
                n = int(item['original_line'])
                used.append(n)
                assert normalized_lines[i - 1] == original_lines[n - 1]
        assert used == selected
        assert all(t in normalized.decode('utf-8') for t in fragment['required_tokens'])
        total += len(normalized_lines)
    assert total == meta['unique_code_lines'] == int(row['normalized_lines'])
    fragment_by_id = {f['fragment_id']: f for f in meta['fragments']}
    seen = set()
    for packet in meta['packets']:
        assert set(packet['fragment_ids']) <= ids
        count = sum(fragment_by_id[f]['normalized_lines'] for f in packet['fragment_ids'])
        assert count == packet['code_lines'] <= 220
        text = (ROOT / packet['input_file']).read_text(encoding='utf-8')
        import re
        blocks = re.findall(r'```(?:php|javascript)\n(.*?)\n```', text, re.S)
        assert len(blocks) == len(packet['fragment_ids'])
        for fid, block in zip(packet['fragment_ids'], blocks):
            expected_code = (ROOT / fragment_by_id[fid]['normalized_file']).read_text(encoding='utf-8')
            assert block + '\n' == expected_code
        assert not any(t in text for t in ('ground_truth', 'candidate_group', '脆弱候选', '防护对照候选', '预期漏洞答案'))
        seen.update(packet['fragment_ids'])
    assert seen == ids, 'some dependency fragments were never provided'
    shared = set(meta['shared_fragments'])
    if len(meta['packets']) > 1:
        assert shared and all(shared <= set(p['fragment_ids']) for p in meta['packets'])
    verify_state(meta)
    return {'sample_id': sid, 'sample_kind': 'multifile_workflow', 'status': 'passed_static_integrity', 'lines': total, 'fragment_count': len(ids), 'packet_count': len(meta['packets']), 'max_packet_lines': meta['max_packet_code_lines'], 'shared_fragments': meta['shared_fragments'], 'declared_semantic_edits': 0}


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def main():
    rows = read_csv(ROOT / "samples.csv")
    assert rows
    assert len({r['sample_id'] for r in rows}) == len(rows)
    assert {'SQL注入', 'XSS', '命令注入', '权限越权'} <= {r['audit_scope'] for r in rows}
    result = []
    for row in rows:
        sid = row['sample_id']
        meta = json.loads((ROOT / row['metadata_file']).read_text(encoding='utf-8'))
        if meta.get('sample_kind') == 'multifile_workflow':
            result.append(verify_complex(row, meta))
            continue
        raw = (ROOT / 'raw_samples' / f'{sid}.php').read_bytes()
        norm = (ROOT / row['normalized_file']).read_bytes()
        source_bytes = subprocess.check_output(['git', '-C', str(SOURCES / row['project']), 'show', f"{row['commit']}:{row['source_file']}"])
        assert raw == source_bytes, f'{sid}: raw differs from Git object'
        assert hashlib.sha256(raw).hexdigest() == meta['raw_sha256']
        assert hashlib.sha256(norm).hexdigest() == meta['normalized_sha256']
        original_lines = raw.decode('utf-8').splitlines()
        normalized_lines = norm.decode('utf-8').splitlines()
        mapping = read_csv(ROOT / row['line_map'])
        assert len(mapping) == len(normalized_lines) == int(row['normalized_lines'])
        assert 0 < len(normalized_lines) <= 220
        edits = 0
        used = []
        for i, m in enumerate(mapping, 1):
            assert int(m['normalized_line']) == i
            current = normalized_lines[i - 1]
            if m['operation'] == 'wrapper':
                assert not m['original_line'] and current in ('<?php', '?>')
            else:
                n = int(m['original_line'])
                used.append(n)
                before = original_lines[n - 1]
                assert m['operation'] == 'retained' and current == before
        assert used == sorted(set(used))
        assert edits == 0
        # Independently identify every original code-body line allowed by the policy.
        selected, inside = [], False
        for n, text in enumerate(original_lines, 1):
            if text.strip() == '<?php':
                inside = True
            elif text.strip() == '?>':
                inside = False
            elif inside and text.strip():
                disposable = text.lstrip().startswith(('//echo', '//print_r'))
                if not disposable:
                    selected.append(n)
        assert used == selected, f'{sid}: an executable/security-relevant line was omitted'
        code = norm.decode('utf-8')
        tokens = ['mysql_query', 'mysql_fetch_array', 'mysql_error', 'include('] if sid.startswith('SQLI') else ['$_GET', '$html', '<pre>'] if sid.startswith('XSS') else ['$_POST', '$_REQUEST', 'shell_exec', 'Windows NT', 'ping  -c 4', '$html']
        extras = {
            'SQLI-001': ["$_GET['id']"],
            'SQLI-002': ["$_POST['uname']", "$_POST['passwd']"],
            'SQLI-003': ['blacklist($id)', 'function blacklist', "'/or/i'", "'/AND/i'", 'Hint:'],
            'XSS-002': ['str_replace'], 'XSS-003': ['preg_replace'],
            'XSS-004': ['htmlspecialchars', 'checkToken', 'generateSessionToken'],
            'CMD-002': ['str_replace', "'&&'", "';'"],
            'CMD-003': ['trim(', 'str_replace', "'| '"],
            'CMD-004': ['checkToken', 'stripslashes', 'explode', 'is_numeric', 'sizeof', 'generateSessionToken'],
        }
        assert all(t in code for t in tokens + extras.get(sid, [])), f'{sid}: missing key context'
        llm = (ROOT / 'llm_inputs' / f'{sid}.md').read_text(encoding='utf-8')
        block = llm.split('```php\n', 1)[1].split('\n```', 1)[0]
        assert block + '\n' == code
        assert not any(t in llm for t in ('source/low.php', 'source/medium.php', 'source/high.php', 'source/impossible.php', '脆弱候选', '防护对照候选', 'candidate_group', 'ground_truth', '整数转换对照版本'))
        verify_state(meta)
        result.append({'sample_id': sid, 'status': 'passed_static_integrity', 'lines': len(normalized_lines), 'mapped_source_lines': len(used), 'declared_semantic_edits': edits})
    labels = read_csv(ROOT / 'evaluation_private' / 'labels.csv')
    assert {r['sample_id'] for r in labels} == {r['sample_id'] for r in rows}
    assert all(r['ground_truth'] in ('待验证', '有漏洞', '无所关注漏洞', '证据不足') for r in labels)
    assert all(r['evidence'] and r['evidence'] != '尚无POC结果' for r in labels if r['ground_truth'] in ('有漏洞', '无所关注漏洞'))
    reviews = read_csv(ROOT / 'review_log.csv')
    assert {r['sample_id'] for r in reviews} == {r['sample_id'] for r in rows}
    assert all(r['sample_id'] in {x['sample_id'] for x in rows} for r in reviews)
    complex_results = [r for r in result if r.get('sample_kind') == 'multifile_workflow']
    report = {'sample_count': len(rows), 'audit_scope_count': len({r['audit_scope'] for r in rows}), 'reviewed_count': len(reviews), 'max_sample_code_lines': max(r['lines'] for r in result), 'max_input_packet_code_lines': max(r.get('max_packet_lines', r['lines']) for r in result), 'workflow_sample_count': len(complex_results), 'fragment_count': sum(r.get('fragment_count', 1) for r in result), 'check_date': '2026-10-12', 'scope': 'Static provenance, mapping, policy coverage, key context and model input isolation only', 'php_lint': 'not_run_no_php_command', 'runtime_validation': 'not_run_by_this_checker', 'samples': result}
    path = ROOT / 'checks' / 'verification.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f"PASS: {len(rows)} parent samples, {report['audit_scope_count']} scopes, {report['fragment_count']} fragments; longest workflow {report['max_sample_code_lines']} lines, max input packet {report['max_input_packet_code_lines']} lines. PHP/POC not run.")


if __name__ == '__main__':
    main()
