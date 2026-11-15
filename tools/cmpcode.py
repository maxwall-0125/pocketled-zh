# -*- coding: utf-8 -*-
"""Compare decoded instruction streams of two dex files, method by method.

Indices are resolved to names so that pool reordering does not matter.
"""
import sys

import dexlib
from dexlib import Dex, MNEM, FMT


def val_of(dx, op, idx):
    if op in (0x1a, 0x1b):
        return ('s', dx.strings[idx])
    if op in (0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25, 0xfe, 0xff):
        return ('t', dx.types[idx])
    if 0x52 <= op <= 0x6d:
        return ('f', dx.fstr(idx))
    if 0x6e <= op <= 0x8f or 0xfa <= op <= 0xfd:
        return ('m', dx.mstr(idx))
    return ('i', idx)


def sig(dx, i):
    if i.raw is not None:
        return (('payload', i.op), ('raw', tuple(i.raw)))
    f = FMT[i.op]
    out = [MNEM[i.op] if i.raw is None else 'payload']
    for name in ('a', 'b', 'c'):
        v = getattr(i, name)
        if v is not None and f not in ('35c', '3rc', '45cc', '4rcc'):
            out.append((name, v))
    if f in ('35c', '3rc', '45cc', '4rcc'):
        out.append(('a', i.a if f in ('35c', '45cc') else i.start))
        out.append(('regs', tuple(i.regs)))
    if f in ('21c', '22c', '35c', '3rc', '31c', '45cc', '4rcc'):
        out.append(val_of(dx, i.op, i.idx))
    if f in ('45cc', '4rcc'):
        out.append(('p', dx.proto_str(i.proto)))
    if i.lit is not None:
        out.append(('lit', i.lit))
    if i.target is not None:
        out.append(('tgt', i.target))
    if i.raw is not None:
        out.append(('raw', tuple(i.raw)))
    return tuple(out)


def methods(dx):
    out = {}
    for c in dx.classes:
        desc = dx.types[c['class_idx']]
        for grp in ('direct', 'virtual'):
            for midx, acc, ci in c['data'][grp]:
                key = (desc, dx.mstr(midx))
                out[key] = (acc, ci, grp)
    return out


def main(a_path, b_path):
    da = Dex(open(a_path, 'rb').read())
    db = Dex(open(b_path, 'rb').read())
    ma = methods(da)
    mb = methods(db)
    diffs = 0
    for key, (acc, ci_b, grp) in mb.items():
        if key not in ma:
            print('EXTRA method in new: %s' % (key,))
            diffs += 1
            continue
        acc_a, ci_a, grp_a = ma[key]
        if acc != acc_a:
            print('ACCESS %s 0x%x -> 0x%x' % (key, acc_a, acc))
            diffs += 1
        if (ci_a is None) != (ci_b is None):
            print('CODE-PRESENCE %s' % (key,))
            diffs += 1
            continue
        if ci_a is None:
            continue
        if (ci_a.registers_size, ci_a.ins_size, ci_a.outs_size) != \
                (ci_b.registers_size, ci_b.ins_size, ci_b.outs_size):
            print('HEADER %s regs %d/%d ins %d/%d outs %d/%d' % (
                key, ci_a.registers_size, ci_b.registers_size,
                ci_a.ins_size, ci_b.ins_size, ci_a.outs_size, ci_b.outs_size))
            diffs += 1
        sa = [sig(da, i) for i in ci_a.insns]
        sb = [sig(db, i) for i in ci_b.insns]
        if len(sa) != len(sb):
            print('LEN %s %d -> %d' % (key, len(sa), len(sb)))
            diffs += 1
        for k in range(min(len(sa), len(sb))):
            if sa[k] != sb[k]:
                diffs += 1
                print('INSN %s  k=%d\n   orig %r\n   new  %r' % (key, k, sa[k], sb[k]))
                if diffs > 20:
                    print('... too many, stopping')
                    return
    print('methods %d vs %d; differences %d' % (len(ma), len(mb), diffs))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
