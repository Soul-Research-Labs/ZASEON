
import re

with open('full_lint_output.txt', 'r') as f:
    lines = f.readlines()

current_file = ""
gas_custom_errors = {}

for line in lines:
    line = line.strip()
    if line.startswith('contracts/') and line.endswith('.sol'):
        current_file = line
    elif 'gas-custom-errors' in line:
        match = re.search(r'^(\d+):(\d+)\s+(warning|error)\s+(.*)\s+gas-custom-errors', line)
        if match:
            line_num = match.group(1)
            msg = match.group(4).strip()
            if current_file not in gas_custom_errors:
                gas_custom_errors[current_file] = []
            gas_custom_errors[current_file].append(f"{line_num}: {msg}")

with open('clean_gas_errors.txt', 'w') as f:
    for file, errs in gas_custom_errors.items():
        f.write(f"\nFILE: {file}\n")
        for err in errs:
            f.write(f"  {err}\n")
