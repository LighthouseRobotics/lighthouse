#!/usr/bin/env python3
"""Check a STATUS.json against lighthouse-status/v1. Standard library only, Python 3.9+.

  python3 formats/status/status_check.py STATUS.json [--root .]

With --root, startHere must name a file in that folder.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys

SCHEMA = 'lighthouse-status/v1'
FIELDS = ('schema', 'repository', 'status', 'summary', 'lastVerified', 'verifiedBy', 'nextAction', 'blockers',
          'startHere')
STATUSES = ('active', 'blocked', 'paused', 'archived')


def problems(doc, root=None, today=None):
    """Every way `doc` breaks lighthouse-status/v1, as sentences. Empty means it is valid."""
    if not isinstance(doc, dict):
        return ['STATUS.json must hold one JSON object']
    out = []
    missing = [f for f in FIELDS if f not in doc]
    extra = sorted(set(doc) - set(FIELDS))
    if missing:
        out.append('missing ' + ', '.join(missing))
    if extra:
        out.append('unknown field ' + ', '.join(extra))
    if doc.get('schema') != SCHEMA:
        out.append('schema must be %s' % SCHEMA)
    if not re.fullmatch(r'LighthouseRobotics/[A-Za-z0-9_.-]+', str(doc.get('repository', ''))):
        out.append('repository must be LighthouseRobotics/<name>')
    if doc.get('status') not in STATUSES:
        out.append('status must be one of ' + ', '.join(STATUSES))
    for field, limit in (('summary', 400), ('verifiedBy', 400), ('nextAction', 400), ('startHere', 200)):
        value = doc.get(field)
        if field in doc and (not isinstance(value, str) or not value.strip() or len(value) > limit):
            out.append('%s must be text of 1 to %d characters' % (field, limit))
    last = doc.get('lastVerified')
    if last is not None:
        try:
            day = dt.date.fromisoformat(last) if isinstance(last, str) and len(last) == 10 else None
        except ValueError:
            day = None
        if day is None:
            out.append('lastVerified must be YYYY-MM-DD or null')
        elif day > (today or dt.date.today()):
            out.append('lastVerified is in the future')
    blockers = doc.get('blockers')
    if 'blockers' in doc and (not isinstance(blockers, list) or len(blockers) > 10 or any(
            not isinstance(b, str) or not b.strip() or len(b) > 400 for b in blockers)):
        out.append('blockers must be a list of up to 10 sentences')
    if doc.get('status') == 'blocked' and not blockers:
        out.append('a blocked repository must name its blockers')
    start = doc.get('startHere')
    if root is not None and isinstance(start, str) and start.strip():
        base = os.path.realpath(root)
        path = os.path.realpath(os.path.join(base, start))
        if not path.startswith(base + os.sep):
            out.append('startHere must stay inside the repository')
        elif not os.path.isfile(path):
            out.append('startHere names %s, which is not in the repository' % start)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('file')
    ap.add_argument('--root', help='the repository folder; startHere must exist there')
    args = ap.parse_args(argv)
    try:
        with open(args.file, encoding='utf-8') as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        print('%s: %s' % (args.file, e))
        return 1
    found = problems(doc, args.root)
    for p in found:
        print('%s: %s' % (args.file, p))
    if not found:
        print('%s: valid %s (%s, %s)' % (args.file, SCHEMA, doc['repository'], doc['status']))
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main())
