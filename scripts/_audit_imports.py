#!/usr/bin/env python3
"""Find unused imports in Solidity files."""
import re, glob

files = (glob.glob("contracts/core/*.sol") + glob.glob("contracts/bridge/*.sol") +
         glob.glob("contracts/primitives/*.sol") + glob.glob("contracts/security/*.sol") +
         glob.glob("contracts/crosschain/*.sol") + glob.glob("contracts/verifiers/*.sol") +
         glob.glob("contracts/privacy/*.sol"))

for fpath in sorted(files):
    with open(fpath) as fh:
        content = fh.read()
        lines = content.split('\n')
    results = []
    for i, line in enumerate(lines, 1):
        m = re.search(r'import\s+\{([^}]+)\}', line)
        if m:
            symbols = [s.strip() for s in m.group(1).split(',')]
            for sym in symbols:
                if not sym:
                    continue
                # Count occurrences (should be >1 since import itself is 1)
                count = len(re.findall(r'\b' + re.escape(sym) + r'\b', content))
                if count <= 1:
                    results.append(f"  L{i}: {sym}")
    if results:
        print(f"--- {fpath} ---")
        for r in results:
            print(r)
