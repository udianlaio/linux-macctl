#!/usr/bin/env python3
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
patterns=[
 ('private-key', re.compile(r'-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----')),
 ('github-token', re.compile(r'gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}')),
 ('aws-access-key', re.compile(r'AKIA[0-9A-Z]{16}')),
 ('google-api-key', re.compile(r'AIza[0-9A-Za-z_-]{30,}')),
 ('slack-token', re.compile(r'xox[baprs]-[A-Za-z0-9-]{10,}')),
 ('bearer-secret', re.compile(r'(?i)authorization\s*[:=]\s*["\']?bearer\s+[A-Za-z0-9._~-]{20,}')),
]
bad=[]
for p in ROOT.rglob('*'):
    if not p.is_file() or '.git' in p.parts or '__pycache__' in p.parts or p.suffix=='.pyc':
        continue
    try: s=p.read_text('utf-8')
    except Exception: continue
    for name,pat in patterns:
        if pat.search(s): bad.append(f'{p.relative_to(ROOT)}: {name}')
if bad:
    print('\n'.join(bad)); raise SystemExit(1)
print('PUBLIC_PRIVACY_SCAN_PASS')
