# -*- coding: utf-8 -*-
"""Build a dex file from a plain model (all indices already final)."""
import hashlib
import struct
import zlib

import dexlib

# When True, code items are copied verbatim from the source dex (only
# debug_info_off is zeroed). Used to isolate builder bugs from encoder bugs.
RAW_CODE = False


def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def utf16_units(s):
    return len(s.encode('utf-16-be')) // 2


def shorty_char(desc):
    c = desc[0]
    return 'L' if c in 'L[' else c


def shorty_of(params, ret):
    return shorty_char(ret) + ''.join(shorty_char(t) for t in params)


class Spec(object):
    def __init__(self):
        self.strings = []
        self.types = []
        self.protos = []      # (ret_type_idx, params tuple)
        self.fields = []      # (cls, type, name)
        self.methods = []     # (cls, proto, name)
        self.classes = []     # dict


def _align4(buf):
    while len(buf) % 4:
        buf.append(0)


def build(sp):
    ns, nt, np_, nf, nm, nc = (len(sp.strings), len(sp.types), len(sp.protos),
                               len(sp.fields), len(sp.methods), len(sp.classes))
    assert [s.encode('utf-16-be') for s in sp.strings] == \
        sorted(s.encode('utf-16-be') for s in sp.strings), 'strings not sorted'
    assert len(set(sp.strings)) == ns, 'duplicate strings'
    sidx = {s: i for i, s in enumerate(sp.strings)}
    assert sp.types == sorted(sp.types, key=lambda d: sidx[d]), 'types not sorted'
    assert len(set(sp.types)) == nt, 'duplicate types'
    assert sp.protos == sorted(sp.protos, key=lambda p: (p[0], tuple(p[1]))), 'protos unsorted'
    assert sp.fields == sorted(sp.fields, key=lambda f: (f[0], f[2], f[1])), 'fields unsorted'
    assert sp.methods == sorted(sp.methods, key=lambda m: (m[0], m[2], m[1])), 'methods unsorted'

    ids_end = 0x70 + 4 * ns + 4 * nt + 12 * np_ + 8 * nf + 8 * nm + 32 * nc

    data = bytearray()
    data_off = ids_end

    # --- type lists (proto params and class interfaces), 4-byte aligned
    tl_off = {}
    tl_count = 0
    if np_ or any(c.get('interfaces') for c in sp.classes):
        _align4(data)
    for (ret, params) in sp.protos:
        if not params:
            continue
        key = tuple(params)
        if key in tl_off:
            continue
        tl_off[key] = data_off + len(data)
        data += struct.pack('<I', len(params))
        for t in params:
            data += struct.pack('<H', t)
        _align4(data)
        tl_count += 1
    iface_off = []
    for c in sp.classes:
        ifs = tuple(c.get('interfaces') or [])
        if not ifs:
            iface_off.append(0)
            continue
        if ifs in tl_off:
            iface_off.append(tl_off[ifs])
            continue
        tl_off[ifs] = data_off + len(data)
        iface_off.append(tl_off[ifs])
        data += struct.pack('<I', len(ifs))
        for t in ifs:
            data += struct.pack('<H', t)
        _align4(data)
        tl_count += 1
    tl_first = min(tl_off.values()) if tl_off else 0

    # --- code items (4-byte aligned, deduplicated by identity)
    ci_off = {}
    ci_order = []
    blobs = {}
    for c in sp.classes:
        for grp in ('direct', 'virtual'):
            for (midx, acc, ci) in c['data'][grp]:
                if ci is None:
                    continue
                ci.debug_info_off = 0
                key = id(ci)
                if key in blobs:
                    continue
                rf = getattr(ci, 'raw_full', None)
                if RAW_CODE and rf:
                    buf = bytearray(rf)
                    struct.pack_into('<I', buf, 8, 0)
                    blobs[key] = bytes(buf)
                else:
                    blobs[key] = dexlib.encode_code(ci)
                ci_order.append(key)
    if ci_order:
        _align4(data)
    for key in ci_order:
        _align4(data)
        ci_off[key] = data_off + len(data)
        data += blobs[key]
    code_first = ci_off[ci_order[0]] if ci_order else 0

    # --- class data
    def enc_class_data(cd):
        buf = bytearray()
        buf += uleb(len(cd['static_fields']))
        buf += uleb(len(cd['instance_fields']))
        buf += uleb(len(cd['direct']))
        buf += uleb(len(cd['virtual']))
        for grp in ('static_fields', 'instance_fields'):
            last = 0
            for (fi, acc) in cd[grp]:
                buf += uleb(fi - last)
                buf += uleb(acc)
                last = fi
        for grp in ('direct', 'virtual'):
            last = 0
            for (midx, acc, ci) in cd[grp]:
                buf += uleb(midx - last)
                buf += uleb(acc)
                buf += uleb(ci_off[id(ci)] if ci is not None else 0)
                last = midx
        return bytes(buf)

    cd_offs = []
    cd_blobs = [enc_class_data(c['data']) for c in sp.classes]
    cd_start = data_off + len(data)
    pos = cd_start
    for b in cd_blobs:
        cd_offs.append(pos)
        data += b
        pos += len(b)
    cd_count = len(cd_offs)

    # --- static values (encoded arrays, one per class that has them)
    _align4(data)
    sv_off = []
    sv_done = {}
    for c in sp.classes:
        raw = c.get('static_values')
        if not raw:
            sv_off.append(0)
            continue
        if raw in sv_done:
            sv_off.append(sv_done[raw])
            continue
        sv_done[raw] = data_off + len(data)
        sv_off.append(sv_done[raw])
        data += raw
    sv_count = len(sv_done)
    sv_first = min(sv_done.values()) if sv_done else 0

    # --- string data
    _align4(data)
    str_offs = []
    for s in sp.strings:
        str_offs.append(data_off + len(data))
        data += uleb(utf16_units(s))
        data += s.encode('utf-8') + b'\x00'

    # --- id sections
    buf = bytearray(0x70)
    for i in range(ns):
        buf += struct.pack('<I', str_offs[i])
    for i in range(nt):
        buf += struct.pack('<I', sidx[sp.types[i]])
    for (ret, params) in sp.protos:
        buf += struct.pack('<I', sidx[shorty_of([sp.types[t] for t in params], sp.types[ret])])
        buf += struct.pack('<I', ret)
        buf += struct.pack('<I', tl_off[tuple(params)] if params else 0)
    for (cls, typ, name) in sp.fields:
        buf += struct.pack('<I', (cls & 0xFFFF) | ((typ & 0xFFFF) << 16))
        buf += struct.pack('<I', name)
    for (cls, proto, name) in sp.methods:
        buf += struct.pack('<I', (cls & 0xFFFF) | ((proto & 0xFFFF) << 16))
        buf += struct.pack('<I', name)
    for k, c in enumerate(sp.classes):
        super_idx = c.get('super_idx')
        buf += struct.pack('<IIIIIIII', c['class_idx'], c.get('access', 1),
                           0xFFFFFFFF if super_idx is None else super_idx,
                           iface_off[k], c.get('source_idx', 0xFFFFFFFF),
                           0, cd_offs[k], sv_off[k])
    assert len(buf) == ids_end, (len(buf), ids_end)
    out = buf + data

    # --- map list (must be 4-byte aligned)
    while len(out) % 4:
        out.append(0)
    map_off = len(out)
    items = [(0x0000, 1, 0),
             (0x0001, ns, 0x70),
             (0x0002, nt, 0x70 + 4 * ns),
             (0x0003, np_, 0x70 + 4 * ns + 4 * nt),
             (0x0004, nf, 0x70 + 4 * ns + 4 * nt + 12 * np_),
             (0x0005, nm, 0x70 + 4 * ns + 4 * nt + 12 * np_ + 8 * nf),
             (0x0006, nc, 0x70 + 4 * ns + 4 * nt + 12 * np_ + 8 * nf + 8 * nm)]
    if tl_count:
        items.append((0x1001, tl_count, tl_first))
    if cd_count:
        items.append((0x2000, cd_count, cd_start))
    if sv_count:
        items.append((0x2005, sv_count, sv_first))

    if ci_order:
        items.append((0x2001, len(ci_order), code_first))
    if ns:
        items.append((0x2002, ns, str_offs[0]))
    items = [it for it in items if it[1]]
    items.append((0x1000, 1, map_off))
    items.sort(key=lambda x: x[2])
    mb = bytearray(struct.pack('<I', len(items)))
    for (t, cnt, off) in items:
        mb += struct.pack('<HHII', t, 0, cnt, off)
    out += mb
    file_len = len(out)

    # --- header
    hdr = bytearray(0x70)
    hdr[0:8] = b'dex\n038\x00'
    struct.pack_into('<IIIIIIII', hdr, 32, file_len, 0x70, 0x12345678, 0, 0,
                     map_off, ns, 0x70)
    struct.pack_into('<IIIIIIII', hdr, 64, nt, 0x70 + 4 * ns,
                     np_, 0x70 + 4 * ns + 4 * nt,
                     nf, 0x70 + 4 * ns + 4 * nt + 12 * np_,
                     nm, 0x70 + 4 * ns + 4 * nt + 12 * np_ + 8 * nf)
    struct.pack_into('<IIII', hdr, 96, nc,
                     0x70 + 4 * ns + 4 * nt + 12 * np_ + 8 * nf + 8 * nm,
                     file_len - data_off, data_off)
    hdr[12:32] = hashlib.sha1(bytes(out[32:])).digest()
    out[0:0x70] = hdr
    struct.pack_into('<I', out, 8, zlib.adler32(bytes(out[12:])))
    return bytes(out)
