# -*- coding: utf-8 -*-
"""Verify dexlib: re-encoding a code item yields an equivalent instruction stream."""
import sys
sys.path.insert(0, r'C:\Users\maxwall\Desktop\DSH空间\pocketled\tools')
import dexlib


def sig(insns):
    out = []
    for i in insns:
        out.append((i.op, i.a, i.b, i.c, i.lit, i.idx, i.target,
                    tuple(i.regs) if i.regs is not None else None,
                    i.raw is not None and tuple(i.raw) if i.raw else None))
    return out


def main(path):
    d = open(path, 'rb').read()
    dx = dexlib.Dex(d)
    ok = bad = 0
    for c in dx.classes:
        for grp in ('direct', 'virtual'):
            for midx, acc, ci in c['data'][grp]:
                if ci is None:
                    continue
                enc = dexlib.encode_code(ci)
                n_units = len(enc) - 16
                # re-decode the try/handler area too
                ci2 = dexlib.parse_code(enc + b'\x00' * 8, 0)
                if sig(ci.insns) == sig(ci2.insns) and ci.tries == ci2.tries \
                        and [list(map(tuple, h)) for h in ci.handlers] == \
                        [list(map(tuple, h)) for h in ci2.handlers] \
                        and ci.registers_size == ci2.registers_size:
                    ok += 1
                else:
                    bad += 1
                    if bad <= 5:
                        print('MISMATCH', dx.mstr(midx))
                        for k, (x, y) in enumerate(zip(ci.insns, ci2.insns)):
                            if sig([x]) != sig([y]):
                                print('  insn', k, repr(x), '->', repr(y))
                        if ci.tries != ci2.tries:
                            print('  tries', ci.tries, ci2.tries)
                        if ci.handlers != ci2.handlers:
                            print('  handlers', ci.handlers, ci2.handlers)
    print('roundtrip ok=%d bad=%d' % (ok, bad))
    return bad


if __name__ == '__main__':
    sys.exit(1 if main(sys.argv[1]) else 0)
