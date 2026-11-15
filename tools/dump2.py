# -*- coding: utf-8 -*-
"""Dump a dex to text (with operands) using dexlib."""
import sys, struct
sys.path.insert(0, r'C:\Users\maxwall\Desktop\DSH空间\pocketled\tools')
import dexlib
from dexlib import MNEM, FMT


def fmt_ins(dx, i):
    op = i.op
    if i.raw is not None:
        return 'payload(0x%x, %d units)' % (op, len(i.raw))
    n = MNEM[op]
    f = FMT[op]
    parts = []
    if f in ('12x',):
        parts = ['v%d' % i.a, 'v%d' % i.b]
    elif f == '11n':
        parts = ['v%d' % i.a, '#%d' % i.lit]
    elif f == '11x':
        parts = ['v%d' % i.a]
    elif f in ('10t',):
        parts = ['->%d' % i.target]
    elif f == '20t':
        parts = ['->%d' % i.target]
    elif f in ('21t',):
        parts = ['v%d' % i.a, '->%d' % i.target]
    elif f in ('21s',):
        parts = ['v%d' % i.a, '#%d' % i.lit]
    elif f in ('21h',):
        parts = ['v%d' % i.a, '#%d' % i.lit]
    elif f == '21c':
        s = val_of(dx, op, i.idx)
        parts = ['v%d' % i.a, s]
    elif f == '23x':
        parts = ['v%d' % i.a, 'v%d' % i.b, 'v%d' % i.c]
    elif f == '22b':
        parts = ['v%d' % i.a, 'v%d' % i.b, '#%d' % i.lit]
    elif f == '22t':
        parts = ['v%d' % i.a, 'v%d' % i.b, '->%d' % i.target]
    elif f == '22s':
        parts = ['v%d' % i.a, 'v%d' % i.b, '#%d' % i.lit]
    elif f == '22c':
        parts = ['v%d' % i.a, 'v%d' % i.b, val_of(dx, op, i.idx)]
    elif f == '22x':
        parts = ['v%d' % i.a, 'v%d' % i.b]
    elif f == '30t':
        parts = ['->%d' % i.target]
    elif f == '32x':
        parts = ['v%d' % i.a, 'v%d' % i.b]
    elif f == '31i':
        parts = ['v%d' % i.a, '#%d' % i.lit]
    elif f == '31t':
        parts = ['v%d' % i.a, '->%d' % i.target]
    elif f == '31c':
        parts = ['v%d' % i.a, val_of(dx, op, i.idx)]
    elif f == '35c':
        parts = ['{%s}' % ', '.join('v%d' % r for r in i.regs), val_of(dx, op, i.idx)]
    elif f == '3rc':
        parts = ['{v%d..v%d}' % (i.start, i.start + len(i.regs) - 1), val_of(dx, op, i.idx)]
    elif f == '45cc':
        parts = ['{%s}' % ', '.join('v%d' % r for r in i.regs), val_of(dx, op, i.idx),
                 'proto#%d' % i.proto]
    elif f == '4rcc':
        parts = ['{v%d..v%d}' % (i.start, i.start + len(i.regs) - 1), val_of(dx, op, i.idx),
                 'proto#%d' % i.proto]
    elif f == '51l':
        parts = ['v%d' % i.a, '#%d' % i.lit]
    return ('%-14s ' % n) + ', '.join(parts)


def val_of(dx, op, idx):
    # guess pool by opcode
    if op in (0x1a, 0x1b):
        return 'str#%d %r' % (idx, dx.strings[idx])
    if op == 0x1c:
        return 'type#%d %s' % (idx, dx.types[idx])
    if op in (0x1f, 0x20, 0x22, 0x23, 0x24, 0x25):
        return 'type#%d %s' % (idx, dx.types[idx])
    if op in (0x52, 0x53, 0x54, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
              0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
              0x6a, 0x6b, 0x6c, 0x6d):
        return 'fld#%d %s' % (idx, dx.fstr(idx))
    if op in (0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
              0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
              0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
              0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
              0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
              0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
              0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
              0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
              0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
              0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1,
              0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
              0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5,
              0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
              0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
              0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff):
        return 'mth#%d %s' % (idx, dx.mstr(idx))
    return '#%d' % idx


def main(path, out):
    dx = dexlib.Dex(open(path, 'rb').read())
    L = []
    L.append('strings=%d types=%d protos=%d fields=%d methods=%d classes=%d'
             % (len(dx.strings), len(dx.types), len(dx.protos), len(dx.fields),
                len(dx.methods), len(dx.classes)))
    for c in dx.classes:
        L.append('CLASS %s  super=%s ifaces=%s' % (
            dx.types[c['class_idx']], dx.types[c['super_idx']],
            [dx.types[t] for t in c['interfaces']]))
        for grp in ('direct', 'virtual'):
            for midx, acc, ci in c['data'][grp]:
                L.append('  METHOD[%s] %s acc=0x%x' % (grp, dx.mstr(midx), acc))
                if ci is None:
                    L.append('    (abstract/native)')
                    continue
                L.append('    regs=%d ins=%d outs=%d' % (ci.registers_size, ci.ins_size,
                                                        ci.outs_size))
                for k, i in enumerate(ci.insns):
                    L.append('    %4d: %s' % (k, fmt_ins(dx, i)))
    open(out, 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('wrote', out, len(L), 'lines')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
