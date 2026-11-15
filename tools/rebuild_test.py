# -*- coding: utf-8 -*-
"""Round trip: parse original -> rebuild -> parse -> compare models."""
import sys
sys.path.insert(0, r'C:\Users\maxwall\Desktop\DSH空间\pocketled\tools')
import dexlib
import dexbuild


def spec_from(dx):
    sp = dexbuild.Spec()
    sp.strings = list(dx.strings)
    sp.types = list(dx.types)
    sp.protos = [(p.ret, tuple(p.params)) for p in dx.protos]
    sp.fields = list(dx.fields)
    sp.methods = list(dx.methods)
    for c in dx.classes:
        cd = c['data']
        sp.classes.append(dict(
            class_idx=c['class_idx'], access=c['access'], super_idx=c['super_idx'],
            interfaces=list(c['interfaces']), source_idx=c['source_idx'],
            static_values=c['static_values'],
            data=dict(static_fields=list(cd['static_fields']),
                      instance_fields=list(cd['instance_fields']),
                      direct=[[m, a, ci] for (m, a, ci) in cd['direct']],
                      virtual=[[m, a, ci] for (m, a, ci) in cd['virtual']])))
    return sp


def sig(ci):
    if ci is None:
        return None
    out = []
    for i in ci.insns:
        out.append((i.op, i.a, i.b, i.c, i.lit, i.idx, i.target,
                    tuple(i.regs) if i.regs is not None else None,
                    i.start, i.proto,
                    tuple(i.raw) if i.raw is not None else None))
    return (ci.registers_size, ci.ins_size, ci.outs_size, tuple(out),
            tuple(ci.tries), tuple(tuple(map(tuple, h)) for h in ci.handlers))


def main(path):
    src = open(path, 'rb').read()
    dx = dexlib.Dex(src)
    sp = spec_from(dx)
    out = dexbuild.build(sp)
    print('rebuilt %d bytes (orig %d)' % (len(out), len(src)))
    open(path + '.rebuilt', 'wb').write(out)
    dy = dexlib.Dex(out)
    ok = True
    if dy.strings != dx.strings:
        ok = False
        for k, (a, b) in enumerate(zip(dy.strings, dx.strings)):
            if a != b:
                print('string diff at', k, repr(a), repr(b))
                break
    if dy.types != dx.types:
        ok = False
        print('types differ')
    if [(p.ret, tuple(p.params)) for p in dy.protos] != [(p.ret, tuple(p.params)) for p in dx.protos]:
        ok = False
        print('protos differ')
    if dy.fields != dx.fields:
        ok = False
        print('fields differ')
    if dy.methods != dx.methods:
        ok = False
        print('methods differ')
    if len(dy.classes) != len(dx.classes):
        ok = False
        print('class count differs')
    for a, b in zip(dy.classes, dx.classes):
        for k in ('class_idx', 'access', 'super_idx', 'interfaces', 'source_idx'):
            if a[k] != b[k]:
                ok = False
                print('class field %s differs for %s' % (k, dy.types[a[k] if k != 'class_idx' else a['class_idx']]))
        for grp in ('static_fields', 'instance_fields'):
            if [tuple(x) for x in a['data'][grp]] != [tuple(x) for x in b['data'][grp]]:
                ok = False
                print('class data %s differs' % grp)
        for grp in ('direct', 'virtual'):
            da = [(m, acc) for (m, acc, ci) in a['data'][grp]]
            db = [(m, acc) for (m, acc, ci) in b['data'][grp]]
            if da != db:
                ok = False
                print('class data %s differs' % grp)
            for (m, acc, ci1), (m2, acc2, ci2) in zip(a['data'][grp], b['data'][grp]):
                if sig(ci1) != sig(ci2):
                    ok = False
                    print('code differs in', dy.mstr(m))
    print('IDENTITY OK' if ok else 'IDENTITY FAILED')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
