# -*- coding: utf-8 -*-
"""Strict sanity validation of a dumped dex: register/index ranges, frame sizes."""
import sys
sys.path.insert(0, r'C:\Users\maxwall\Desktop\DSH空间\pocketled\tools')
import dexlib
from dexlib import FMT

problems = []


def regs_of(i):
    f = FMT[i.op]
    if f in ('12x', '22b', '22t', '22s', '22c'):
        return [i.a, i.b]
    if f in ('11n', '11x', '10t'):
        return [i.a] if i.a is not None else []
    if f in ('21t', '21s', '21h', '21c', '31i', '31t', '31c', '51l'):
        return [i.a]
    if f in ('20t', '30t', '10x'):
        return []
    if f in ('22x', '32x'):
        return [i.a, i.b]
    if f in ('23x',):
        return [i.a, i.b, i.c]
    if f in ('35c', '45cc'):
        return list(i.regs)
    if f in ('3rc', '4rcc'):
        return list(range(i.start, i.start + len(i.regs)))
    return []


def main(path):
    d = open(path, 'rb').read()
    dx = dexlib.Dex(d)
    n_insn = 0
    for c in dx.classes:
        for grp in ('direct', 'virtual'):
            for midx, acc, ci in c['data'][grp]:
                if ci is None:
                    continue
                for k, i in enumerate(ci.insns):
                    n_insn += 1
                    if i.raw is not None:
                        continue
                    rs = regs_of(i)
                    for r in rs:
                        if r is None or r >= ci.registers_size:
                            problems.append('%s insn %d: reg %s >= regs %d (%r)'
                                            % (dx.mstr(midx), k, r, ci.registers_size, i))
                    f = FMT[i.op]
                    if f in ('21c',):
                        if i.idx >= max(len(dx.strings), len(dx.types), len(dx.fields),
                                        len(dx.methods)):
                            problems.append('%s insn %d: idx %d out of range (%r)'
                                            % (dx.mstr(midx), k, i.idx, i))
                    if f in ('22c',):
                        if i.idx >= max(len(dx.fields), len(dx.types)):
                            problems.append('%s insn %d: idx %d out of range (%r)'
                                            % (dx.mstr(midx), k, i.idx, i))
                    if f in ('35c', '3rc', '45cc', '4rcc'):
                        if i.idx >= len(dx.methods):
                            problems.append('%s insn %d: midx %d out of range (%r)'
                                            % (dx.mstr(midx), k, i.idx, i))
                        if len(rs) > ci.outs_size:
                            problems.append('%s insn %d: %d args > outs %d'
                                            % (dx.mstr(midx), k, len(rs), ci.outs_size))
                    if f in ('10t', '20t', '30t', '21t', '22t', '31t'):
                        if not (0 <= (i.target or 0) <= ci.unit_len()):
                            problems.append('%s insn %d: target %s out of range'
                                            % (dx.mstr(midx), k, i.target))
    print('checked %d instructions in %d classes; problems=%d'
          % (n_insn, len(dx.classes), len(problems)))
    for p in problems[:25]:
        print(' ', p)
    return len(problems)


if __name__ == '__main__':
    sys.exit(1 if main(sys.argv[1]) else 0)
