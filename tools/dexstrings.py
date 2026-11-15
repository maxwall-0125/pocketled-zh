import sys, struct

def uleb128(b, o):
    r = 0; s = 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7f) << s
        if not (x & 0x80):
            return r, o
        s += 7

def parse(data):
    assert data[:4] == b'dex\n'
    ssize, soff = struct.unpack_from('<II', data, 0x38)
    out = []
    for i in range(ssize):
        off = struct.unpack_from('<I', data, soff + 4 * i)[0]
        n, p = uleb128(data, off)
        end = data.index(b'\x00', p)
        raw = data[p:end]
        out.append((i, off, n, raw))
    return out

if __name__ == '__main__':
    data = open(sys.argv[1], 'rb').read()
    for i, off, n, raw in parse(data):
        try:
            s = raw.decode('utf-8')
        except Exception:
            s = raw.decode('utf-8', 'replace')
        print(f'{i:5d} off={off:6d} u16={n:4d} len={len(raw):4d} {s!r}')
