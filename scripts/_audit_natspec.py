#!/usr/bin/env python3
"""Find public/external functions missing NatSpec @notice or @param."""
import re, sys, glob

files = glob.glob("contracts/core/*.sol") + glob.glob("contracts/bridge/*.sol") + glob.glob("contracts/primitives/*.sol") + glob.glob("contracts/security/*.sol")

for fpath in sorted(files):
    with open(fpath) as fh:
        lines = fh.readlines()
    results = []
    for i, line in enumerate(lines, 1):
        m = re.search(r'function\s+(\w+)', line)
        if m and ('external' in line or 'public' in line):
            fname = m.group(1)
            # Check previous lines for NatSpec
            has_natspec = False
            for j in range(max(0, i-8), i-1):
                if '@notice' in lines[j] or '@dev' in lines[j] or '///' in lines[j]:
                    has_natspec = True
                    break
            if not has_natspec:
                results.append(f"  L{i}: {fname}")
    if results:
        print(f"--- {fpath} ({len(results)} missing) ---")
        for r in results:
            print(r)
