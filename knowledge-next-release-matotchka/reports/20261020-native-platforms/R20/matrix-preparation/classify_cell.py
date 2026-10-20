#!/usr/bin/env python3
"""Classify a completed cell without masking process FAIL or Node TAP skips."""
import argparse,json,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--cell',type=Path,required=True);p.add_argument('--controller-exit-code',type=int,required=True);a=p.parse_args()
collected=a.cell/'COLLECTED.json'
if not collected.is_file(): print('FAIL: strict collection receipt missing');raise SystemExit(1)
r=json.loads(collected.read_text(encoding='utf-8-sig'))
status=r.get('status')
cell_status=a.cell/'CELL_STATUS.json'
if not cell_status.is_file(): print('FAIL: combined cell status missing');raise SystemExit(1)
cell=json.loads(cell_status.read_text(encoding='utf-8-sig'))
if cell.get('installed_10') not in ('pass','partial'): print('FAIL: installed 10-suite replay failed or incomplete');raise SystemExit(1)
if status not in ('pass','partial','fail') or r.get('all_evidence_integrity_checks_hold') is not True:
 print('FAIL: invalid collection status or evidence-integrity result');raise SystemExit(1)
if status=='fail':
 print('FAIL: a process/assertion/controller failure is present');raise SystemExit(1)
if cell.get('native_windows_capability')!='unavailable_separate_release_blocker' or cell.get('process_containment')!='unavailable' or cell.get('overall_status')!='partial':
 print('FAIL: POSIX capability/containment limitation is absent or misclassified');raise SystemExit(1)
if status=='partial' or cell.get('installed_10')=='partial':
 if a.controller_exit_code!=2: print('FAIL: PARTIAL evidence disagrees with controller exit');raise SystemExit(1)
 print('PARTIAL: explicit Node test skip(s); native Windows containment remains unavailable');raise SystemExit(2)
if status!='pass': print(f'FAIL: invalid collected status {status!r}');raise SystemExit(1)
if a.controller_exit_code!=2: print('FAIL: diagnostic PASS must retain overall PARTIAL exit for unavailable containment');raise SystemExit(1)
print('PARTIAL: portable diagnostic replay PASS; native containment unavailable, release certification remains blocked.')
raise SystemExit(2)
