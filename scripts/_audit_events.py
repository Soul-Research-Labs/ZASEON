#!/usr/bin/env python3
"""Find state-changing public/external functions missing events."""
import re, sys, glob

files = glob.glob("contracts/core/*.sol") + glob.glob("contracts/bridge/*.sol") + glob.glob("contracts/primitives/*.sol") + glob.glob("contracts/security/*.sol")

for fpath in sorted(files):
    with open(fpath) as fh:
        lines = fh.readlines()
    in_func = False
    func_name = ''
    func_line = 0
    has_emit = False
    brace_depth = 0
    results = []
    for i, line in enumerate(lines, 1):
        m = re.search(r'function\s+(\w+)', line)
        if m and ('external' in line or 'public' in line) and 'view' not in line and 'pure' not in line:
            if in_func and not has_emit:
                results.append(f"  L{func_line}: {func_name}")
            in_func = True
            func_name = m.group(1)
            func_line = i
            has_emit = False
            brace_depth = 0
        if in_func:
            brace_depth += line.count('{') - line.count('}')
            if 'emit ' in line:
                has_emit = True
            if brace_depth <= 0 and '{' in ''.join(lines[func_line-1:i]):
                if not has_emit:
                    results.append(f"  L{func_line}: {func_name}")
                in_func = False
    if results:
        print(f"--- {fpath} ---")
        for r in results:
            print(r)
