#!/usr/bin/env python3
"""Gap analysis helper script - temporary, delete after use."""
import json, os, glob

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 1. Certora completeness
print("=" * 60)
print("CERTORA COMPLETENESS")
print("=" * 60)

spec_files = set(os.path.basename(f).replace(".spec","") for f in glob.glob("certora/specs/*.spec"))
conf_specs = set()

for cp in sorted(glob.glob("certora/conf/*.conf")):
    with open(cp) as f:
        d = json.load(f)
    v = d.get("verify", "")
    if ":" in v:
        s = v.split(":", 1)[1]
        conf_specs.add(os.path.basename(s).replace(".spec", ""))
        if not os.path.isfile(s):
            print(f"  MISSING SPEC: {os.path.basename(cp)} -> {s}")
    for sol in d.get("files", []):
        if not os.path.isfile(sol):
            print(f"  MISSING SOL: {os.path.basename(cp)} -> {sol}")

orphans = sorted(spec_files - conf_specs)
if orphans:
    print(f"  ORPHAN SPECS (no conf): {orphans}")
else:
    print("  No orphan specs found")

# 2. Test coverage gaps
print("\n" + "=" * 60)
print("CONTRACTS WITHOUT TESTS")
print("=" * 60)

# List all production .sol files (excluding mocks, interfaces, libraries)
prod_contracts = set()
for root, dirs, files in os.walk("contracts"):
    # skip mocks and interfaces
    rel = os.path.relpath(root, "contracts")
    if rel.startswith("mocks") or rel.startswith("interfaces"):
        continue
    for f in files:
        if f.endswith(".sol"):
            name = f.replace(".sol", "")
            prod_contracts.add((name, os.path.join(root, f)))

# List all test files
test_names = set()
for root, dirs, files in os.walk("test"):
    for f in files:
        if f.endswith(".sol") or f.endswith(".ts"):
            # Extract contract names from test file names
            clean = f.replace(".t.sol", "").replace(".test.ts", "").replace(".test.sol", "").replace(".sol", "").replace(".ts", "")
            test_names.add(clean.lower())

# Also check test file contents for contract references
untested = []
for name, path in sorted(prod_contracts):
    name_lower = name.lower()
    found = any(name_lower in t for t in test_names)
    if not found:
        untested.append((name, path))

for name, path in untested:
    print(f"  {path}")

print(f"\nTotal production contracts: {len(prod_contracts)}")
print(f"Potentially untested: {len(untested)}")

# 3. SDK gaps
print("\n" + "=" * 60)
print("SDK GAPS")
print("=" * 60)

for root, dirs, files in os.walk("sdk/src"):
    for f in files:
        if f.endswith(".ts"):
            fp = os.path.join(root, f)
            with open(fp) as fh:
                content = fh.read()
            for i, line in enumerate(content.split("\n"), 1):
                if "TODO" in line or "FIXME" in line or "HACK" in line:
                    print(f"  {fp}:{i}: {line.strip()}")

# 4. Deploy script gaps
print("\n" + "=" * 60)
print("DEPLOY SCRIPT ANALYSIS")
print("=" * 60)

deploy_scripts = glob.glob("scripts/deploy/*")
print(f"  Deploy scripts: {len(deploy_scripts)}")
for ds in sorted(deploy_scripts):
    print(f"    {os.path.basename(ds)}")

# 5. Monitoring config placeholders
print("\n" + "=" * 60)
print("MONITORING PLACEHOLDERS")
print("=" * 60)

for f in glob.glob("monitoring/*.json"):
    with open(f) as fh:
        content = fh.read()
    for placeholder in ["TODO", "FIXME", "YOUR_", "PLACEHOLDER", "REPLACE_ME", "example.com", "0x0000000000000000000000000000000000000000"]:
        if placeholder in content:
            print(f"  {os.path.basename(f)}: contains '{placeholder}'")

print("\n" + "=" * 60)
print("DONE")
print("=" * 60)
