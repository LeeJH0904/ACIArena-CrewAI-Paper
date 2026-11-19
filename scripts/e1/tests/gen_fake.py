"""Produce a small fake E1 output tree through the real benchmark.main path.

    python gen_fake.py CODE_ROOT OUTPUT_DIR CONDITION DOMAIN TASK_ID[,TASK_ID...] PREFIX

Runs benign + every attack of DOMAIN x 3 targets for the given task(s) through
benchmark.main of CODE_ROOT (the E1 repository or a 22dd78f checkout), with the
OpenAI SDK's Completions.create replaced by a deterministic local stub and the
HTTP layer blocked, so no model or network call is made. CONDITION is
previous_only or all_previous; PREFIX is the experiment_id prefix (e.g.
crewai_prevonly, crewai, crewai_exp2). Used by run_cases.py.
"""
import argparse, hashlib, json, os, sys
from pathlib import Path
from types import SimpleNamespace
root, out, condition, domain, task_id, prefix = sys.argv[1:7]
os.chdir(root); sys.path.insert(0, root)
os.environ['OPENAI_API_KEY'] = 'sk-e1-offline-not-a-key'
import openai._base_client as base
from openai.resources.chat import completions as comp
def fake(self, *a, **kw):
    msgs = kw.get('messages')
    text = 'STUB-OUT-' + hashlib.sha256(json.dumps(msgs, sort_keys=True).encode()).hexdigest()[:16]
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text, refusal=None),
                                                    finish_reason='stop')],
                           usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1))
def blocked(self, *a, **kw):
    raise RuntimeError('offline guard: real request attempted')
comp.Completions.create = fake
base.SyncAPIClient.request = blocked
base.AsyncAPIClient.request = blocked
sys.argv = ['benchmark.py']
import benchmark as B
def ns(**kw):
    d = dict(attack_ids=None, experiment_id=None, experiment_config=None, phase='core', repetition=1,
             resume=False, retry_errors=False, execute=True, model_config=None, judge_config=None,
             mas='crewai_seq_nodeleg', suite='benign', attack_mode='continuous', defense='none',
             task_domain=domain, max_workers=1, limit=None, task_ids=task_id.split(','), output_dir=out,
             malicious_agents=[])
    if condition == 'previous_only':
        d['crewai_context_mode'] = 'previous_only'
    d.update(kw)
    return argparse.Namespace(**d)
cells = [('benign', None, 'benign')] + [(g, t, s) for t in ('solver', 'reviewer', 'finalizer')
                                        for g, s in (('hijacking', 'hi'), ('disruption', 'disr'), ('disclosure', 'disc'))]
for goal, target, short in cells:
    eid = f'{prefix}_{domain}_benign' if target is None else f'{prefix}_{domain}_{target}_{short}'
    B.main(ns(suite=goal, malicious_agents=[target] if target else [], experiment_id=eid))
print('done', condition, domain, out)
