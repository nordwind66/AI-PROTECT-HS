#!/usr/bin/env python3
"""Differential check: a compiled engine (loaded as a shared library through the C ABI, Hyperscan backend or not) against
the Python reference engine of this project.

    python tools/diff_hyperscan.py --lib /path/to/libai_prompt_guard.so \
        --manifest dist/linux/x86_64/1.1.3/manifest.json --version 1.1.3

Scans every sample of the corpora in tests/corpus (and the 1000-sentence translation dataset) with both engines and
compares the decision and the set of matched rule ids; prints the number of differences (0 expected) and the first few.
The engine is used as a black box: only the public C ABI of the shared library is called. Python standard library only.
"""
import argparse
import ctypes
import json
import sys
import time
import collections
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apg_rules import db as dbm
from apg_rules.corpus_eval import snapshot_doc, load_corpora, read_jsonl
from apg_rules.refengine import RefEngine


class Guard:
    """Minimal ctypes binding of apg_create / apg_scan_json (see the engine's include/ai_prompt_guard.h)."""

    def __init__(self, library, manifest):
        lib = ctypes.CDLL(library)
        lib.apg_create.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)]
        lib.apg_scan_json.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)), ctypes.POINTER(ctypes.c_size_t)]
        lib.apg_free_buffer.argtypes = [ctypes.c_void_p]
        lib.apg_last_error.restype = ctypes.c_char_p
        self._lib, self._ctx = lib, ctypes.c_void_p()
        cfg = json.dumps({"manifest_path": manifest}).encode("utf-8")
        st = lib.apg_create(cfg, len(cfg), ctypes.byref(self._ctx))
        if st != 0:
            raise RuntimeError(f"apg_create failed ({st}): {lib.apg_last_error().decode('utf-8', 'replace')}")

    def scan(self, request):
        data = json.dumps(request, ensure_ascii=False).encode("utf-8")
        out, length = ctypes.POINTER(ctypes.c_uint8)(), ctypes.c_size_t()
        st = self._lib.apg_scan_json(self._ctx, data, len(data), ctypes.byref(out), ctypes.byref(length))
        if st != 0:
            raise RuntimeError(f"apg_scan_json failed ({st})")
        try:
            return json.loads(ctypes.string_at(out, length.value).decode("utf-8"))
        finally:
            self._lib.apg_free_buffer(out)


ap=argparse.ArgumentParser(); ap.add_argument('--lib',required=True); ap.add_argument('--manifest',required=True); ap.add_argument('--version',required=True)
args=ap.parse_args()
ROOT = Path(__file__).resolve().parents[1]
conn=dbm.connect(ROOT/'data'/'ai_prompt_rules.db',readonly=True)
ref=RefEngine(snapshot_doc(conn,args.version)[1])
root=ROOT
corp=load_corpora(root/'tests/corpus',root)
if (root/'tests/corpus/heldout_zh_conv.jsonl').is_file():
    corp['heldout_zh_conv']=read_jsonl(root/'tests/corpus/heldout_zh_conv.jsonl')
t0=time.time()
g=Guard(args.lib,args.manifest)
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
