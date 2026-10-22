#!/usr/bin/env python3
"""Check unified hunk lengths; GNU patch can silently ignore later bad hunks."""
from pathlib import Path
import re
import sys


def check(path):
    lines = path.read_text().splitlines()
    failures = []
    for index, line in enumerate(lines):
        match = re.match(r'^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@', line)
        if not match:
            continue
        old = new = 0
        for body in lines[index + 1:]:
            if body.startswith(('@@ ', '--- a/', 'diff --git ', '-- ')):
                break
            old += body.startswith((' ', '-'))
            new += body.startswith((' ', '+'))
        declared = (int(match[1] or 1), int(match[2] or 1))
        if declared != (old, new):
            failures.append(f'{path}:{index + 1}: declared {declared}, actual {(old, new)}')
    return failures


if __name__ == '__main__':
    assert len(sys.argv) > 1, 'Pass patch filenames'
    failures = [failure for name in sys.argv[1:] for failure in check(Path(name))]
    if failures:
        raise SystemExit('\n'.join(failures))
    print(f'PASS: hunk lengths in {len(sys.argv) - 1} patches')
