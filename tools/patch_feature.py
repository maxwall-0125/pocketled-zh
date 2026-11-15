# -*- coding: utf-8 -*-
"""Add a "turn LED off while screen is off" switch to PocketLED.

Reads the Chinese-translated dex, adds strings / types / methods / code,
remaps every index table, and writes a new dex.
"""
import sys
import struct

sys.path.insert(0, r'C:\Users\maxwall\Desktop\DSH空间\pocketled\tools')
import dexlib
import dexbuild
import rebuild_test

Ins = dexlib.Ins

SRC = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\work\classes.zh.bak'
OUT = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\work\classes.dex'

MA = 'Lcom/pocketblock/led/MainActivity;'
LS = 'Lcom/pocketblock/led/LedService;'
CF = 'Lcom/pocketblock/led/Config;'
SW = 'Landroid/widget/Switch;'
TV = 'Landroid/widget/TextView;'
LL = 'Landroid/widget/LinearLayout;'
LLP = 'Landroid/widget/LinearLayout$LayoutParams;'
V = 'Landroid/view/View;'
PM = 'Landroid/os/PowerManager;'
SP = 'Landroid/content/SharedPreferences;'
SPE = 'Landroid/content/SharedPreferences$Editor;'
OCL = 'Landroid/widget/CompoundButton$OnCheckedChangeListener;'
CB = 'Landroid/widget/CompoundButton;'
HND = 'Landroid/os/Handler;'
RUN = 'Ljava/lang/Runnable;'
LED = 'Lcom/pocketblock/led/Led;'

TEXT_LABEL = '息屏关闭指示灯'
KEY = 'screenOff'
POWER = 'power'

# ---------------------------------------------------------------- instruction helpers

def iget_obj(dst, obj, fidx):
    return Ins(0x54, a=dst, b=obj, idx=fidx)


def iput_obj(src, obj, fidx):
    return Ins(0x5b, a=src, b=obj, idx=fidx)


def mres(dst):
    return Ins(0x0a, a=dst)


def mres_obj(dst):
    return Ins(0x0c, a=dst)


def ret_void():
    return Ins(0x0e)


def ret(dst):
    return Ins(0x0f, a=dst)


def const4(dst, v):
    return Ins(0x12, a=dst, lit=v)


def const_str(dst, sidx):
    return Ins(0x1a, a=dst, idx=sidx)


def const_w16(dst, v):
    return Ins(0x16, a=dst, lit=v)


def check_cast(dst, tidx):
    return Ins(0x1f, a=dst, idx=tidx)


def new_inst(dst, tidx):
    return Ins(0x22, a=dst, idx=tidx)


def branch(op, reg, tgt=None):
    return Ins(op, a=reg, target=tgt)


def inv(kind, regs, midx):
    return Ins(kind, regs=list(regs), idx=midx)


INV_V = 0x6e
INV_D = 0x70
INV_I = 0x72
IF_EQZ = 0x38
IF_NEZ = 0x39
IF_EQ = 0x32


def main():
    src = open(SRC, 'rb').read()
    dx = dexlib.Dex(src)
    sp = rebuild_test.spec_from(dx)

    old_strings = list(sp.strings)
    old_types = list(sp.types)

    def S(t):
        if t in sp.strings:
            return sp.strings.index(t)
        sp.strings.append(t)
        return len(sp.strings) - 1

    def T(desc):
        S(desc)                     # every type descriptor must exist as a string
        if desc in sp.types:
            return sp.types.index(desc)
        sp.types.append(desc)
        return len(sp.types) - 1

    def P(ret_desc, params):
        e = (T(ret_desc), tuple(T(p) for p in params))
        if e in sp.protos:
            return sp.protos.index(e)
        sp.protos.append(e)
        return len(sp.protos) - 1

    def F(cls, typ, name):
        e = (T(cls), T(typ), S(name))
        if e in sp.fields:
            return sp.fields.index(e)
        sp.fields.append(e)
        return len(sp.fields) - 1

    def M(cls, proto, name):
        e = (T(cls), proto, S(name))
        if e in sp.methods:
            return sp.methods.index(e)
        sp.methods.append(e)
        return len(sp.methods) - 1

    def field_by_name(cls, name):
        for k, (c, t, n) in enumerate(sp.fields):
            if sp.types[c] == cls and sp.strings[n] == name:
                return k
        raise KeyError((cls, name))

    def method_by_name(cls, name):
        for k, (c, p, n) in enumerate(sp.methods):
            if sp.types[c] == cls and sp.strings[n] == name:
                return k
        raise KeyError((cls, name))

    def klass(desc):
        for c in sp.classes:
            if sp.types[c['class_idx']] == desc:
                return c
        raise KeyError(desc)

    str_label = S(TEXT_LABEL)
    str_key = S(KEY)
    str_power = S(POWER)
    t_switch = T(SW)
    t_pm = T(PM)
    t_ocl = T(OCL)
    t_cb = T(CB)
    t_view = T(V)

    p_bool = P('Z', [])
    p_setbool = P('V', ['Z'])
    p_init_switch = P('V', ['Landroid/content/Context;'])
    p_onchecked = P('V', ['Landroid/widget/CompoundButton;', 'Z'])
    p_void = P('V', [])
    p_ctxstr = P('Ljava/lang/Object;', ['Ljava/lang/String;'])

    f_prefs = field_by_name(CF, 'prefs')
    f_config = field_by_name(MA, 'config')
    f_root = field_by_name(MA, 'root')
    f_lsconfig = field_by_name(LS, 'config')
    f_handler = field_by_name(LS, 'handler')
    f_tickrun = field_by_name(LS, 'tick')

    m_getbool = method_by_name(SP, 'getBoolean')
    m_edit = method_by_name(SP, 'edit')
    m_putbool = method_by_name(SPE, 'putBoolean')
    m_apply = method_by_name(SPE, 'apply')
    m_getprefs = method_by_name('Landroid/content/Context;', 'getSharedPreferences')
    m_settext = method_by_name(TV, 'setText')
    m_setchecked = method_by_name(SW, 'setChecked')
    m_settextsize = method_by_name(SW, 'setTextSize')
    m_setlistener = method_by_name(SW, 'setOnCheckedChangeListener')
    m_addview2 = M(LL, P('V', ['Landroid/view/View;', 'Landroid/view/ViewGroup$LayoutParams;']), 'addView')
    m_rowparams = method_by_name(MA, 'rowParams')
    m_isinteractive = M(PM, p_bool, 'isInteractive')
    m_getsvc = M('Landroid/content/Context;', p_ctxstr, 'getSystemService')
    m_sw_init = method_by_name(SW, '<init>')
    m_ledoff = method_by_name(LED, 'off')
    m_postdelayed = method_by_name(HND, 'postDelayed')

    # ------------------------------------------------------------ Config.screenOff()Z
    m_cfg_get = M(CF, p_bool, 'screenOff')
    ci_get = dexlib.CodeItem(3, 1, 3, [
        iget_obj(0, 2, f_prefs),
        const_str(1, str_key),
        const4(2, 0),
        inv(INV_I, [0, 1, 2], m_getbool),
        mres(0),
        ret(0),
    ])

    # ------------------------------------------------------- Config.setScreenOff(Z)V
    m_cfg_set = M(CF, p_setbool, 'setScreenOff')
    ci_set = dexlib.CodeItem(4, 2, 3, [
        iget_obj(0, 2, f_prefs),
        inv(INV_I, [0], m_edit),
        mres_obj(0),
        const_str(1, str_key),
        inv(INV_I, [0, 1, 3], m_putbool),
        mres_obj(0),
        inv(INV_I, [0], m_apply),
        ret_void(),
    ])

    # ------------------------------------------------------- LedService.screenOn()Z
    m_ls_interactive = M(LS, p_bool, 'screenOn')
    ci_on = dexlib.CodeItem(2, 1, 2, [
        const_str(0, str_power),
        inv(INV_V, [1, 0], m_getsvc),
        mres_obj(0),
        check_cast(0, t_pm),
        inv(INV_V, [0], m_isinteractive),
        mres(0),
        ret(0),
    ])

    # --------------------------------------------------- MainActivity.onCheckedChanged
    m_ma_onchecked = M(MA, p_onchecked, 'onCheckedChanged')
    ci_oc = dexlib.CodeItem(4, 3, 2, [
        iget_obj(0, 1, f_config),
        inv(INV_V, [0, 3], m_cfg_set),
        ret_void(),
    ])

    # ------------------------------------------------------- MainActivity.screenOffRow()V
    m_ma_row = M(MA, p_void, 'screenOffRow')
    m_cfg_get_call = m_cfg_get
    ci_row = dexlib.CodeItem(4, 1, 4, [
        new_inst(0, t_switch),
        inv(INV_D, [0, 3], m_sw_init),
        const_str(1, str_label),
        inv(INV_V, [0, 1], m_settext),
        Ins(0x15, a=1, lit=0x4190),          # const/high16 v1, 18f (text size)
        inv(INV_V, [0, 1], m_settextsize),
        iget_obj(1, 3, f_config),
        inv(INV_V, [1], m_cfg_get_call),
        mres(1),
        inv(INV_V, [0, 1], m_setchecked),
        inv(INV_V, [0, 3], m_setlistener),
        iget_obj(1, 3, f_root),
        inv(INV_D, [3], m_rowparams),
        mres_obj(2),
        inv(INV_V, [1, 0, 2], m_addview2),
        ret_void(),
    ])

    # ------------------------------------------------------------- add members to classes
    cfg = klass(CF)
    cfg['data']['virtual'].append([m_cfg_get, 0x1, ci_get])
    cfg['data']['virtual'].append([m_cfg_set, 0x1, ci_set])

    ls = klass(LS)
    ls['data']['direct'].append([m_ls_interactive, 0x2, ci_on])

    ma = klass(MA)
    ma['data']['virtual'].append([m_ma_onchecked, 0x1, ci_oc])
    ma['data']['direct'].append([m_ma_row, 0x2, ci_row])
    if t_ocl not in ma['interfaces']:
        ma['interfaces'].append(t_ocl)

    # ------------------------------------------------------------------ patch onCreate
    ci_created = None
    for (midx, acc, ci) in ma['data']['virtual']:
        if sp.strings[sp.methods[midx][2]] == 'onCreate':
            ci_created = ci
    assert ci_created is not None
    ins = ci_created.insns
    # locate the addView(root, main switch, params) call: it is preceded by
    # "invoke-direct rowParams()" + "move-result-object" and by the switch row.
    addview_ids = set()
    for k, (c, p, n) in enumerate(sp.methods):
        if sp.strings[n] == 'addView':
            addview_ids.add(k)
    slot = None
    for k in range(2, len(ins)):
        i = ins[k]
        if i.op == INV_V and i.idx in addview_ids and ins[k - 2].op == 0x70 \
                and ins[k - 2].idx == m_rowparams:
            slot = k + 1
            break
    assert slot is not None
    call_row = inv(INV_D, [6], m_ma_row)
    new_ins = ins[:slot] + [call_row] + ins[slot:]
    _retarget_insert(ins, new_ins, slot, [call_row])
    ci_created.insns = new_ins
    ci_created.outs_size = max(ci_created.outs_size, 4)

    # ------------------------------------------------------------------- patch tick()V
    tick = None
    for (midx, acc, ci) in ls['data']['direct']:
        if sp.strings[sp.methods[midx][2]] == 'tick':
            tick = ci
    assert tick is not None
    old = tick.insns
    # insert point: right after the "enabled()" early-return block (index 6)
    ins6 = 6
    j_normal = len(old)          # index of old[6] after insertion
    j_off = len(old) + 1         # index of the off tail (appended at end)
    mid = [
        iget_obj(0, 7, f_lsconfig),
        inv(INV_V, [0], m_cfg_get),
        mres(0),
        branch(IF_EQZ, 0, j_normal),
        inv(INV_D, [7], m_ls_interactive),
        mres(0),
        branch(IF_EQZ, 0, 0),           # screen off -> jump to the off tail
    ]
    tail = [
        inv(0x71, [], m_ledoff),
        mres(0),
        iget_obj(0, 7, f_handler),
        iget_obj(1, 7, f_tickrun),
        const_w16(2, 1000),
        inv(INV_V, [0, 1, 2, 3], m_postdelayed),
        mres(0),
        ret_void(),
    ]
    new = old[:ins6] + mid + old[ins6:] + tail
    # mid[3] and mid[6] must branch to the first old instruction after the insertion
    mid[3].target = ins6 + len(mid)          # index into new of old[6]
    mid[6].target = len(new) - len(tail)     # index into new of the off tail
    _retarget_insert(old, new, ins6, mid)
    # The original "enabled()" guard jumps straight into the body at old[6];
    # it must enter our new guard block first, otherwise the screen-off check
    # is skipped on every tick.
    units = []
    u = 0
    for i in new:
        units.append(u)
        u += i.size
    for i in old[:ins6]:
        if i.target is not None:
            i.target = units[ins6]
    tick.insns = new
    tick.registers_size = max(tick.registers_size, 8)
    tick.outs_size = max(tick.outs_size, 4)

    # ----------------------------------------------------------------------- remap
    pos_s = {s: i for i, s in enumerate(sorted(sp.strings, key=lambda x: x.encode('utf-16-be')))}
    new_strings = sorted(sp.strings, key=lambda x: x.encode('utf-16-be'))
    pos_t = {d: i for i, d in enumerate(sorted(sp.types, key=lambda d: pos_s[d]))}
    new_types = sorted(sp.types, key=lambda d: pos_s[d])

    def ms(i):
        return pos_s[old_strings[i]] if i < len(old_strings) else pos_s[sp.strings[i]]

    # value based maps (indices may point at appended entries too)
    smap = {i: pos_s[s] for i, s in enumerate(sp.strings)}
    tmap = {i: pos_t[d] for i, d in enumerate(sp.types)}

    protos_new = [(tmap[r], tuple(tmap[p] for p in ps)) for (r, ps) in sp.protos]
    proto_pos = {}
    for e in sorted(set(protos_new)):
        proto_pos[e] = len(proto_pos)
    protos_sorted = sorted(set(protos_new))
    pmap = {i: proto_pos[protos_new[i]] for i in range(len(protos_new))}

    fields_new = [(tmap[c], tmap[t], smap[n]) for (c, t, n) in sp.fields]
    field_pos = {}
    for e in sorted(set(fields_new), key=lambda f: (f[0], f[2], f[1])):
        field_pos[e] = len(field_pos)
    fields_sorted = sorted(set(fields_new), key=lambda f: (f[0], f[2], f[1]))
    fmap = {i: field_pos[fields_new[i]] for i in range(len(fields_new))}

    methods_new = [(tmap[c], pmap[p], smap[n]) for (c, p, n) in sp.methods]
    meth_pos = {}
    for e in sorted(set(methods_new), key=lambda m: (m[0], m[2], m[1])):
        meth_pos[e] = len(meth_pos)
    methods_sorted = sorted(set(methods_new), key=lambda m: (m[0], m[2], m[1]))
    mmap = {i: meth_pos[methods_new[i]] for i in range(len(methods_new))}

    KIND = {}
    for o in range(0x52, 0x6e):
        KIND[o] = 'field'
    for o in (0x1a, 0x1b):
        KIND[o] = 'string'
    for o in (0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25):
        KIND[o] = 'type'
    for o in list(range(0x6e, 0x73)) + list(range(0x74, 0x79)):
        KIND[o] = 'method'
    for o in (0xfa, 0xfb):
        KIND[o] = 'method'
    for o in (0xfc, 0xfd):
        KIND[o] = 'string'

    for c in sp.classes:
        c['class_idx'] = tmap[c['class_idx']]
        if c['super_idx'] is not None:
            c['super_idx'] = tmap[c['super_idx']]
        c['interfaces'] = [tmap[x] for x in c['interfaces']]
        if c.get('source_idx') not in (None, 0xFFFFFFFF):
            c['source_idx'] = smap[c['source_idx']]
        else:
            c['source_idx'] = 0xFFFFFFFF
        if c.get('static_values'):
            c['static_values'] = remap_values(c['static_values'], smap, tmap, fmap, mmap, pmap)
        cd = c['data']
        cd['static_fields'] = sorted([[fmap[f], a] for (f, a) in cd['static_fields']])
        cd['instance_fields'] = sorted([[fmap[f], a] for (f, a) in cd['instance_fields']])
        for grp in ('direct', 'virtual'):
            lst = []
            for (midx, acc, ci) in cd[grp]:
                if ci is not None:
                    for i in ci.insns:
                        k = KIND.get(i.op)
                        if k is None or i.idx is None:
                            continue
                        if k == 'string':
                            i.idx = smap[i.idx]
                        elif k == 'type':
                            i.idx = tmap[i.idx]
                        elif k == 'field':
                            i.idx = fmap[i.idx]
                        elif k == 'method':
                            i.idx = mmap[i.idx]
                lst.append([mmap[midx], acc, ci])
            cd[grp] = sorted(lst, key=lambda x: x[0])
            cd[grp] = [[m, a, ci] for (m, a, ci) in cd[grp]]

    sp.strings = new_strings
    sp.types = new_types
    sp.protos = protos_sorted
    sp.fields = fields_sorted
    sp.methods = methods_sorted

    out = dexbuild.build(sp)
    open(OUT, 'wb').write(out)
    print('wrote %d bytes (source %d)' % (len(out), len(src)))
    print('strings %d -> %d, types %d -> %d, methods %d -> %d'
          % (len(old_strings), len(sp.strings), len(old_types), len(sp.types),
             len(sp.methods), len(sp.methods)))


def _retarget_insert(old, new, ins_off, inserted):
    """Retarget old branch targets after inserting `inserted` at index ins_off."""
    delta = len(inserted)
    old_start = {}
    u = 0
    for k, i in enumerate(old):
        old_start[u] = k
        u += i.size
    new_start = {}
    u = 0
    for k, i in enumerate(new):
        new_start[k] = u
        u += i.size
    for k, i in enumerate(new):
        if i.target is None or i in inserted:
            continue
        t = i.target
        if t not in old_start:
            raise SystemExit('bad target %r in %s' % (t, i))
        oldk = old_start[t]
        newk = oldk + delta if oldk >= ins_off else oldk
        i.target = new_start[newk]
    for i in inserted:
        if i.target is not None:
            i.target = new_start[i.target]


def remap_values(raw, smap, tmap, fmap, mmap, pmap):
    """Re-encode an encoded_array, remapping index payloads."""
    o = 0
    n = 0
    shift = 0
    while True:
        b = raw[o]
        o += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    vals = []
    for _ in range(n):
        b = raw[o]
        vt = b & 0x1F
        assert vt not in (0x1C, 0x1D), 'nested value not supported'
        if vt == 0x1F:
            vals.append((vt, (b >> 5), (b >> 5) != 0))
            o += 1
            continue
        if vt == 0x1E:
            vals.append((vt, 0, None))
            o += 1
            continue
        size = (b >> 5) + 1
        v = int.from_bytes(raw[o + 1:o + 1 + size], 'little')
        if vt == 0x17:
            v = smap[v]
        elif vt == 0x18:
            v = tmap[v]
        elif vt in (0x19, 0x1B):
            v = fmap[v]
        elif vt == 0x1A:
            v = mmap[v]
        elif vt == 0x15:
            v = pmap[v]
        vals.append((vt, size, v))
        o += 1 + size
    assert o == len(raw), (o, len(raw))
    out = bytearray()
    v = n
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | (0x80 if v else 0))
        if not v:
            break
    for (vt, size, val) in vals:
        if vt in (0x1F, 0x1E):
            out.append(((size & 7) << 5) | vt)
            continue
        if val < 0:
            val &= (1 << (8 * size)) - 1
        need = max(1, (val.bit_length() + 7) // 8)
        size = max(size, need)
        if size > 4:
            size = 4
        assert val < (1 << (8 * size))
        out.append(((size - 1) << 5) | vt)
        out += val.to_bytes(size, 'little')
    return bytes(out)


if __name__ == '__main__':
    main()
