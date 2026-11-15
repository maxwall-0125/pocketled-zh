import sys, struct
sys.path.insert(0, r'C:\Users\maxwall\Desktop\DSH空间\pocketled\tools')
import dexlib

fn = sys.argv[1]
d = open(fn, 'rb').read()
dx = dexlib.Dex(d)
bad = 0
tot = 0
for c in dx.classes:
    for grp in ('direct', 'virtual'):
        for (midx, acc, ci) in c['data'][grp]:
            if ci is None:
                continue
            tot += 1
            enc = bytearray(dexlib.encode_code(ci))
            orig = bytearray(ci.raw_core)
            struct.pack_into('<I', enc, 8, 0)
            struct.pack_into('<I', orig, 8, 0)
            if bytes(enc) != bytes(orig):
                bad += 1
                n = min(len(enc), len(orig))
                first = next((i for i in range(n) if enc[i] != orig[i]), n)
                print('DIFF cls=%d mid=%d len %d vs %d first=%d' % (c['class_idx'], midx, len(enc), len(orig), first))
                s = max(0, first - 8) & ~1
                print('  enc :', bytes(enc[s:first + 12]).hex())
                print('  orig:', bytes(orig[s:first + 12]).hex())
                if bad > 10:
                    print('...')
                    break
print('encoder byte diffs: %d / %d' % (bad, tot))
