#!/usr/bin/env python
"""Self-test for scripts/e1/verify_e1_logs.py on small fake output trees.

    .venv/bin/python scripts/e1/tests/run_cases.py [--work outputs/e1_selftest]
        [--verifier scripts/e1/verify_e1_logs.py] [--cases clean,D1,...]
        [--regenerate]

No model or network call is made. Steps:
  1. a 22dd78f checkout is cloned from this repository into WORK/baseline
     (if missing);
  2. eight fake trees are produced with gen_fake.py (E1 code -> previous_only,
     baseline code -> all_previous; code/math x v1/v2; one task per domain);
  3. the verifier runs on the clean trees and on defect-injected copies, and
     each case's exit code and failing sections are compared with the
     expectation.

Cases
  clean  untouched data                                    -> PASS / exit 0
  D1     solver block injected into a previous_only finalizer prompt -> [treatment]
  D2     previous_only config mode rewritten to all_previous          -> [config]
  D3     finalizer x message raw_response differs by one char         -> [identity]
  D4     one planned run (and its messages) removed                   -> [complete]
  D5     target_invoked missing on an attack run                      -> [complete]
  D6     baseline folders audited with the E1 code                    -> [audit]
  D7     Disruption-only attack_success mismatch          -> PASS (reported)
  D8     one run's final status is model_error                        -> [complete]
  D8a    D8 data with --allow-nonsuccess                  -> PASS (reported)
  D9     one run failed once and succeeded on attempt 2   -> PASS (counted)
  P1     pilot layout (code + math experiments in one folder, one task)
         vs baseline logs holding an extra task, task_ids mapped -> PASS
  P2     P1 + one finalizer x message raw_response changed       -> [identity]
  P3     P1 without task_ids (extra task is unplanned/unpaired)  -> [complete], [identity]
Exit code 0 when every case meets its expectation.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

E1 = Path(__file__).resolve().parents[3]
PY = str(E1 / '.venv/bin/python')
GEN = str(Path(__file__).resolve().parent / 'gen_fake.py')
BASELINE_COMMIT = '22dd78f'
TASKS = {'code': 'code_0000', 'math': 'math_0000'}
TREES = [(cond, domain, rep) for cond in ('previous_only', 'all_previous')
         for domain in ('code', 'math') for rep in (1, 2)]


def tree_name(cond, domain, rep):
    return f'{"prevonly" if cond == "previous_only" else "base"}_{domain}_v{rep}'


def prefix(cond, domain):
    if cond == 'previous_only':
        return 'crewai_prevonly'
    return 'crewai_exp2' if domain == 'math' else 'crewai'     # v1/E2 naming


def ensure_baseline(work):
    baseline = work / 'baseline'
    if not (baseline / '.git').exists():
        subprocess.run(['git', 'clone', '--quiet', '--no-checkout', str(E1), str(baseline)], check=True)
        subprocess.run(['git', '-C', str(baseline), 'checkout', '--quiet', BASELINE_COMMIT], check=True)
    return baseline


def generate(work, baseline, regenerate):
    data = work / 'data'
    if regenerate:
        shutil.rmtree(data, ignore_errors=True)
    for cond, domain, rep in TREES:
        out = data / tree_name(cond, domain, rep)
        if out.exists():
            continue
        root = E1 if cond == 'previous_only' else baseline
        subprocess.run([PY, GEN, str(root), str(out), cond, domain, TASKS[domain], prefix(cond, domain)],
                       check=True, cwd=root, capture_output=True, text=True)
    return data


def mapping(data_dir, document=None):
    if document is not None:
        path = data_dir.parent / f'{data_dir.name}_mapping.json'
        path.write_text(json.dumps(document, indent=1))
        return path
    entries = [{'condition': cond, 'repetition': rep, 'domain': domain,
                'paths': [str(data_dir / tree_name(cond, domain, rep))]} for cond, domain, rep in TREES]
    path = data_dir.parent / f'{data_dir.name}_mapping.json'
    path.write_text(json.dumps({'entries': entries, 'task_ids': {d: [t] for d, t in TASKS.items()}}, indent=1))
    return path


def run(verifier, data_dir, label, reports, baseline, extra=(), document=None):
    out = reports / f'report_{label}.json'
    out.unlink(missing_ok=True)
    start = time.monotonic()
    proc = subprocess.run([PY, str(verifier), '--mapping', str(mapping(data_dir, document)), '--baseline-code-root',
                           str(baseline), '--baseline-python', PY, '--out', str(out), *extra],
                          capture_output=True, text=True, cwd=E1)
    elapsed = time.monotonic() - start
    if out.exists():
        fails = sorted({c['section'] for c in json.loads(out.read_text())['checks'] if not c['ok']})
    else:
        fails = ['<no report>']
    total = re.search(r'TOTAL: (\d+) PASS, (\d+) FAIL', proc.stdout)
    return {'exit': proc.returncode, 'fails': fails, 'elapsed': elapsed,
            'total': f'{total.group(1)} PASS / {total.group(2)} FAIL' if total else proc.stderr[-300:]}


# ----------------------------------------------------- pilot-layout cases
WIDE_TASKS = {'code': 'code_0000,code_0001', 'math': 'math_0000,math_0001'}


def pilot_layout(work, clean, baseline, name, with_task_ids=True):
    """Pilot output (code + math experiments in one folder, one task each) vs
    baseline logs that also hold another task (full-matrix layout)."""
    wide = work / 'data_wide'
    for domain in ('code', 'math'):
        out = wide / f'base_{domain}_v1'
        if not out.exists():
            subprocess.run([PY, GEN, str(baseline), str(out), 'all_previous', domain, WIDE_TASKS[domain],
                            prefix('all_previous', domain)], check=True, cwd=baseline,
                           capture_output=True, text=True)
    data = work / f'defect_{name}'
    shutil.rmtree(data, ignore_errors=True)
    pilot = data / 'e1_pilot'
    for domain in ('code', 'math'):
        for exp in (clean / f'prevonly_{domain}_v1').iterdir():
            shutil.copytree(exp, pilot / exp.name)
        shutil.copytree(wide / f'base_{domain}_v1', data / f'v1_{domain}')
    document = {'entries': [
        {'condition': 'previous_only', 'repetition': 1, 'domain': d, 'paths': [str(pilot)]} for d in ('code', 'math')
    ] + [
        {'condition': 'all_previous', 'repetition': 1, 'domain': d, 'paths': [str(data / f'v1_{d}')]}
        for d in ('code', 'math')]}
    if with_task_ids:
        document['task_ids'] = {d: [t] for d, t in TASKS.items()}
    return data, document


def p2_identity(data):
    f = next(p for p in (data / 'e1_pilot').iterdir() if p.name.endswith('code_finalizer_disc'))
    rows = jsonl(f / 'runs.jsonl')
    next(r for r in rows if r['attack_surface'] == 'message')['raw_response'] += ' '
    write_jsonl(f / 'runs.jsonl', rows)


# ---------------------------------------------------------------- mutations
def jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_jsonl(path, rows):
    path.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows))


def folder(data, tree, exp):
    return next(p for p in (data / tree).iterdir() if p.name.endswith(exp))


def edit_run(data, tree, exp, pred, edit):
    f = folder(data, tree, exp)
    rows = jsonl(f / 'runs.jsonl')
    edit(next(r for r in rows if pred(r)))
    write_jsonl(f / 'runs.jsonl', rows)


def d1_treatment(data):
    f = folder(data, 'prevonly_code_v1', 'solver_hi')
    msgs = jsonl(f / 'messages.jsonl')
    run_id = jsonl(f / 'runs.jsonl')[0]['run_id']
    solver = next(m['content'] for m in msgs
                  if m['run_id'] == run_id and m['sender'] == 'solver' and m['phase'] == 'context')
    for m in msgs:
        if m['run_id'] == run_id and m['sender'] == 'finalizer' and m['phase'] == 'llm_input':
            llm = json.loads(m['content'])
            llm[-1]['content'] = llm[-1]['content'].replace(
                'Review:\n', f'Proposed solution:\n{solver}\n\nReview:\n', 1)
            m['content'] = json.dumps(llm, ensure_ascii=False)
    write_jsonl(f / 'messages.jsonl', msgs)


def d2_config(data):
    for path in (folder(data, 'prevonly_math_v2', 'reviewer_disc') / 'configs').glob('*.json'):
        config = json.loads(path.read_text())
        config['crewai_context_mode'] = 'all_previous'
        path.write_text(json.dumps(config))


def d3_identity(data):
    edit_run(data, 'prevonly_code_v2', 'finalizer_disc', lambda r: r['attack_surface'] == 'message',
             lambda r: r.update(raw_response=r['raw_response'] + ' '))


def d4_missing_run(data):
    f = folder(data, 'prevonly_math_v1', 'solver_disr')
    rows = jsonl(f / 'runs.jsonl')
    drop = rows.pop(0)['run_id']
    write_jsonl(f / 'runs.jsonl', rows)
    write_jsonl(f / 'messages.jsonl', [m for m in jsonl(f / 'messages.jsonl') if m['run_id'] != drop])


def d5_activation(data):
    edit_run(data, 'prevonly_code_v1', 'reviewer_hi', lambda r: True, lambda r: r.update(target_invoked=None))


def d7_disruption_only(data):
    def flip(r):
        r.update(attack_status='valid', attack_success=not bool(r['attack_success']),
                 attack_error_type=None, attack_error_message=None)
    edit_run(data, 'prevonly_math_v1', 'finalizer_disr', lambda r: r['attack_surface'] == 'message', flip)


def d8_nonsuccess(data):
    edit_run(data, 'prevonly_code_v1', 'reviewer_disr', lambda r: True,
             lambda r: r.update(status='model_error', error_type='APIError', error_message='fake failure'))


def d9_retried_success(data):
    f = folder(data, 'prevonly_code_v1', 'reviewer_disc')
    rows = jsonl(f / 'runs.jsonl')
    final = rows[0]
    failed = dict(final, attempt_no=1, status='timeout', error_type='APITimeoutError',   # retryable type
                  error_message='fake transient failure')
    final['attempt_no'] = 2
    write_jsonl(f / 'runs.jsonl', [failed] + rows)
    msgs = jsonl(f / 'messages.jsonl')
    for m in msgs:
        if m['run_id'] == final['run_id']:
            m['attempt_no'] = 2
    write_jsonl(f / 'messages.jsonl', msgs)


CASES = {   # name: (label, mutation, extra verifier args, expected exit, sections that must fail)
    'clean': ('clean data', None, (), 0, set()),
    'D1': ('previous_only finalizer prompt gets solver block', d1_treatment, (), 1, {'treatment'}),
    'D2': ('previous_only config mode rewritten to all_previous', d2_config, (), 1, {'config'}),
    'D3': ('finalizer x message raw_response differs by 1 char', d3_identity, (), 1, {'identity'}),
    'D4': ('one planned run (and its messages) removed', d4_missing_run, (), 1, {'complete'}),
    'D5': ('target_invoked missing on an attack run', d5_activation, (), 1, {'complete'}),
    'D6': ('baseline folders audited with E1 code', 'D6', (), 1, {'audit'}),
    'D7': ('Disruption-only attack_success mismatch', d7_disruption_only, (), 0, set()),
    'D8': ('final status model_error on one run', d8_nonsuccess, (), 1, {'complete'}),
    'D8a': ('D8 data with --allow-nonsuccess', d8_nonsuccess, ('--allow-nonsuccess',), 0, set()),
    'D9': ('failed attempt 1, success on attempt 2', d9_retried_success, (), 0, set()),
    # pilot layout: one shared pilot folder vs baseline logs with an extra task
    'P1': ('pilot layout vs wider baseline, task_ids mapped', 'P1', (), 0, set()),
    'P2': ('P1 + finalizer x message raw_response +1 char', 'P2', (), 1, {'identity'}),
    'P3': ('P1 without task_ids (extra baseline task counted)', 'P3', (), 1, {'complete', 'identity'}),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--work', default=str(E1 / 'outputs/e1_selftest'))
    parser.add_argument('--verifier', default=str(E1 / 'scripts/e1/verify_e1_logs.py'))
    parser.add_argument('--cases', default=','.join(CASES))
    parser.add_argument('--reports', default=None, help='report directory (default WORK/reports)')
    parser.add_argument('--regenerate', action='store_true')
    args = parser.parse_args()
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    reports = Path(args.reports).resolve() if args.reports else work / 'reports'
    reports.mkdir(parents=True, exist_ok=True)
    baseline = ensure_baseline(work)
    clean = generate(work, baseline, args.regenerate)
    print(f'verifier {args.verifier}\nwork {work}')
    ok_all = True
    for name in args.cases.split(','):
        label, mutate, extra, want_exit, want_fail = CASES[name]
        data, base_root, document = clean, baseline, None
        if mutate in ('P1', 'P2', 'P3'):
            data, document = pilot_layout(work, clean, baseline, name, with_task_ids=mutate != 'P3')
            if mutate == 'P2':
                p2_identity(data)
        elif mutate == 'D6':
            base_root = E1
        elif mutate is not None:
            data = work / f'defect_{name}'
            shutil.rmtree(data, ignore_errors=True)
            shutil.copytree(clean, data)
            mutate(data)
        result = run(args.verifier, data, name, reports, base_root, extra, document)
        ok = result['exit'] == want_exit and want_fail <= set(result['fails']) and (bool(want_fail) or not result['fails'])
        ok_all &= ok
        expected = f'exit {want_exit}' + (f' incl. {sorted(want_fail)}' if want_fail else ' no FAIL')
        print(f'{"OK " if ok else "BAD"} {name:5s} {label:52s} expected {expected:32s} '
              f'got exit {result["exit"]} failing={result["fails"]} ({result["total"]}) {result["elapsed"]:.0f}s',
              flush=True)
    print('RESULT', 'PASS' if ok_all else 'FAIL')
    return 0 if ok_all else 1


if __name__ == '__main__':
    sys.exit(main())
