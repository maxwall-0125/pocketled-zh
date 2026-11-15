import sys, struct
sys.path.insert(0, r'C:\Users\maxwall\Desktop\DSH空间\pocketled\tools')
import dexlib


def dump(fn):
    d = open(fn, 'rb').read()
    dx = dexlib.Dex(d)
    out = {}
    for c in dx.classes:
        for kind in ('direct', 'virtual'):
            for mm in c['data'][kind]:
                mid, acc, ci = mm[0], mm[1], mm[2]
                if ci is None:
                    continue
                off = ci.raw_off
                n = struct.unpack_from('<I', d, off + 12)[0]
                out[(c['class_idx'], mid)] = d[off:off + 16 + n * 2]
    return dx, out


_, A = dump(sys.argv[1])
_, B = dump(sys.argv[2])
print('methods a=%d b=%d' % (len(A), len(B)))
bad = 0
for k in sorted(A):
    if k not in B:
        print('MISSING', k)
        bad += 1
        continue
    if A[k] != B[k]:
        bad += 1
        x, y = A[k], B[k]
        n = min(len(x), len(y))
        first = next((i for i in range(n) if x[i] != y[i]), n)
        print('DIFF cls=%d mid=%d len %d vs %d first_byte=%d' % (k[0], k[1], len(x), len(y), first))
        s = max(0, (first - 8)) & ~1
        print('  a:', x[s:first + 12].hex())
        print('  b:', y[s:first + 12].hex())
        if bad > 12:
            print('...')
            break
print('byte-diff methods:', bad)
