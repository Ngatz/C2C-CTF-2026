#!/bin/bash

grep "user_pass" access.log | python3 -c "
import sys
import urllib.parse
import re
from collections import defaultdict

queries = []
for line in sys.stdin:
    decoded = urllib.parse.unquote(line)
    match = re.search(r'LIMIT 0,1\),(\d+),1\)\)([>!=]+)(\d+)', decoded)
    if match:
        pos = int(match.group(1))
        op = match.group(2)
        val = int(match.group(3))
        queries.append((pos, op, val))

by_pos = defaultdict(list)
for pos, op, val in queries:
    by_pos[pos].append((op, val))

result = {}
for pos in sorted(by_pos.keys()):
    for op, val in by_pos[pos]:
        if op == '!=':
            result[pos] = chr(val)
            break

if result:
    max_pos = max(result.keys())
    password_hash = ''.join(result.get(i, '?') for i in range(1, max_pos+1))
    print(password_hash)
"

