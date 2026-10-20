#!/usr/bin/env python3
"""Differential check: the C++ engine (Hyperscan backend, through the C ABI) against the Python reference engine.

    python tools/diff_hyperscan.py --lib build/linux-static/bin/libai_prompt_guard.so \
        --manifest dist/linux/x86_64/1.1.3/manifest.json --version 1.1.3

Scans every sample of the corpora in tests/corpus (and the 1000-sentence translation dataset) with both engines and
compares the decision and the set of matched rule ids; prints the number of differences (0 expected) and the first few.
Python standard library only; run it from the repository root.
"""
import argparse
import sys,json,time,collections
sys.path.insert(0,'tools'); sys.path.insert(0,'examples')
from pathlib import Path
from apg_rules import db as dbm
from apg_rules.corpus_eval import snapshot_doc, load_corpora, read_jsonl
from apg_rules.refengine import RefEngine
import python_ctypes as pc
ap=argparse.ArgumentParser(); ap.add_argument('--lib',required=True); ap.add_argument('--manifest',required=True); ap.add_argument('--version',required=True)
args=ap.parse_args()
conn=dbm.connect(Path('data/ai_prompt_rules.db'),readonly=True)
ref=RefEngine(snapshot_doc(conn,args.version)[1])
root=Path('.')
corp=load_corpora(root/'tests/corpus',root)
if (root/'tests/corpus/heldout_zh_conv.jsonl').is_file():
    corp['heldout_zh_conv']=read_jsonl(root/'tests/corpus/heldout_zh_conv.jsonl')
t0=time.time()
g=pc.Guard(args.lib,args.manifest)
print('load',round(time.time()-t0,1),'s')
tot=collections.Counter(); bad=[]
for name,ss in corp.items():
    c=collections.Counter()
    for s in ss:
        src=s.get('source','user_input'); ctx=s.get('context')
        r=ref.scan(s['text'],source=src,context=ctx)
        req={'text':s['text'],'source':src}
        if ctx: req['context']=ctx
        h=g.scan(req)
        dm = h['decision']==r['decision']
        hm = sorted(m['rule_id'] for m in h['matched_rules'])==sorted(m['rule_id'] for m in r['matched_rules'])
        c['n']+=1; c['decision_same']+=dm; c['rules_same']+=hm
        if not (dm and hm): bad.append((name,s['id'],h['decision'],r['decision'],sorted(m['rule_id'] for m in h['matched_rules'])[:5],sorted(m['rule_id'] for m in r['matched_rules'])[:5]))
    print(name,dict(c)); 
print('differences',len(bad))

for b in bad[:15]: print(b)
