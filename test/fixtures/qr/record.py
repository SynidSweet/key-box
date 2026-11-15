# Records test/fixtures/qr/vectors.json ONCE, from libqrencode 4.1.1 (the `qrencode` binary), and checks every code
# decodes back to its input with zbar 0.23.93 (`zbarimg`) and ZXing-C++ 3.1.1 (`ZXingReader`). Not run by the tests.
# usage: python3 -I record.py <output-dir>
import json, subprocess, sys, tempfile, os

CAP = {1: 14, 2: 26, 3: 42, 4: 62, 5: 84, 6: 106, 7: 122, 8: 152, 9: 180, 10: 213}
HOST = 'keybox.tail09a879.ts.net'  # 24 bytes: setup URL 43 bytes, recover URL 45 bytes


def filler(n: int, tag: str) -> str:
    base = tag + '-' + 'abcdefghijklmnopqrstuvwxyz0123456789/:.?=&%-_ ABC'
    return (base * (n // len(base) + 1))[:n]


cases = []
for name, text in [
    ('setup-url', f'https://{HOST}:8443/setup'),
    ('recover-url', f'https://{HOST}:8443/recover'),
    ('long-host-setup-url', 'https://' + 'a' * 63 + '.' + 'b' * 17 + ':8443/setup'),
    ('utf8', 'café ✓ key box'),
    ('one-byte', 'k'),
]:
    cases.append((name, text))
prev = 0
for v, cap in CAP.items():
    cases.append((f'v{v}-min', filler(prev + 1, f'v{v}')))
    cases.append((f'v{v}-max', filler(cap, f'v{v}')))
    prev = cap


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, **kw)


out = []
with tempfile.TemporaryDirectory() as d:
    for name, text in cases:
        data = text.encode('utf-8')
        ascii_ = run(['qrencode', '-t', 'ASCII', '-m', '0', '-l', 'M', '-8', '-o', '-'], input=data).stdout.decode()
        rows = []
        for line in ascii_.split('\n'):
            if line == '':
                continue
            line = line.ljust(len(line) + (len(line) % 2))
            rows.append(''.join('1' if line[i] == '#' else '0' for i in range(0, len(line), 2)))
        n = len(rows)
        assert all(len(r) == n for r in rows), name
        version = (n - 17) // 4
        png = os.path.join(d, 'q.png')
        run(['qrencode', '-t', 'PNG', '-m', '4', '-s', '8', '-l', 'M', '-8', '-o', png], input=data)
        zb = run(['zbarimg', '--raw', '-q', '--set', 'binary', png]).stdout
        assert zb == data, (name, 'zbar', zb)
        zx = run(['ZXingReader', png]).stdout.decode()
        zbytes = [l.split(':', 1)[1].split() for l in zx.split('\n') if l.startswith('Bytes:')][0]
        assert bytes(int(h, 16) for h in zbytes) == data, (name, 'zxing', zx)
        assert 'ECLevel:    M' in zx and f'Version:    {version}' in zx, (name, 'zxing', zx)
        out.append({'name': name, 'text': text, 'version': version, 'rows': rows})
with open(os.path.join(sys.argv[1], 'vectors.json'), 'w') as f:
    json.dump(out, f, indent=1)
print(len(out), 'vectors')
