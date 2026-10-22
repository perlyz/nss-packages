"""Utilities for host probes that compile functions from prepared driver sources."""
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
    masked = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m[0]), source, flags=re.S)
    for match in re.finditer(r'\b' + re.escape(name) + r'\s*\(', masked):
        end, depth = match.end(), 1
        while depth:
            depth += (masked[end] == '(') - (masked[end] == ')')
            end += 1
        while masked[end].isspace():
            end += 1
        if masked[end] != '{':
            continue
        start = masked.rfind('\n', 0, match.start()) + 1
        depth, end = 1, end + 1
        while depth:
            depth += (masked[end] == '{') - (masked[end] == '}')
            end += 1
        return source[start:end] + '\n'
    raise AssertionError(f'Function not found: {name}')


def run(source, defines=()):
    with tempfile.TemporaryDirectory(prefix='nss-source-probe-') as directory:
        c, binary = Path(directory) / 'test.c', Path(directory) / 'test'
        c.write_text(source)
        subprocess.run(['cc', '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-Wno-unused-variable', '-Wno-unused-function',
                        '-Wno-int-to-pointer-cast', '-fsanitize=undefined',
                        *defines, str(c), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
