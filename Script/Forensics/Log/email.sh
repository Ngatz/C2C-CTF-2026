!/bin/bash

grep "user_email" access.log | python3 -c "

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

# Find confirmed character (where != is used)
result = {}
for pos in sorted(by_pos.keys()):
    for op, val in by_pos[pos]:
        if op == '!=':
            result[pos] = chr(val)
            break

email = ''.join(result.get(i, '?') for i in range(1, max(result.keys())+1))
print(f'Extracted email: {email}')
