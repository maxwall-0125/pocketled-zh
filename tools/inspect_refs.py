import struct, sys

p = r"C:\Users\maxwall\Desktop\DSH空间\pocketled\work\classes.dex"
d = bytearray(open(p, 'rb').read())


def u16(o): return struct.unpack_from('<H', d, o)[0]
def u32(o): return struct.unpack_from('<I', d, o)[0]


str_n, str_off = u32(0x38), u32(0x3C)
typ_n, typ_off = u32(0x40), u32(0x44)
pro_n, pro_off = u32(0x48), u32(0x4C)
fld_n, fld_off = u32(0x50), u32(0x54)
mth_n, mth_off = u32(0x58), u32(0x5C)
cls_n, cls_off = u32(0x60), u32(0x64)


def uleb(o):
    r = s = 0
    while True:
        b = d[o]
        r |= (b & 0x7f) << s
        s += 7
        o += 1
        if not b & 0x80:
            return r, o


def get_str(i):
    o = u32(str_off + 4 * i)
    n, o = uleb(o)
    end = d.index(b'\x00', o)
    return bytes(d[o:end]).decode('utf-8', 'replace')


def parse_ann_item(o):
    """返回 (type_idx, [(name_idx, value)], 结束偏移)；value 只记录 string 引用"""
    strings = []
    vis = d[o]; o += 1
    tid, o = uleb(o)
    sz, o = uleb(o)
    for _ in range(sz):
        nidx, o = uleb(o)
        strings.append(('elem_name', nidx))
        val, o = parse_val(o, strings)
    return o, strings


def parse_val(o, out, depth=0):
    t = d[o]; o += 1
    if t == 0x17:
        idx, o = uleb(o)
        out.append(('str_val', idx))
    elif t == 0x18:
        o += 4
    elif t in (0x19, 0x1a, 0x1b, 0x1c):
        pass
    elif t == 0x1d:
        _, o = uleb(o)
    elif t in (0x1e,):
        pass
    elif t == 0x1f:
        pass
    elif t == 0x00:
        out.append(('byte', o)); o += 1
    elif t in (0x02, 0x03):
        o += 2
    elif t == 0x04:
        o += 4
    elif t == 0x06:
        o += 8
    elif t in (0x10, 0x11):
        o += 4
    elif t == 0x15:
        o += 2
    elif t == 0x16:
        o += 4
    elif t == 0x1c:
        o += 8
    elif t == 0x1a:
        pass
    elif t == 0x1b:
        pass
    elif t == 0x23:
        o += 4
    elif t == 0x24:
        o += 8
    elif t == 0x25:
        o += 4
    elif t == 0x26:
        o += 8
    elif t == 0x28:
        pass
    elif t == 0x29:
        o += 8
    elif t == 0x2a:
        pass
    elif t == 0x2b:
        o += 4
    elif t == 0x2c:
        o += 8
    elif t == 0x1d:
        pass
    else:
        raise SystemExit(f'unknown value type 0x{t:02x} at {o - 1}')
    return o, out


print('counts: strings', str_n, 'types', typ_n, 'protos', pro_n, 'fields', fld_n,
      'methods', mth_n, 'classes', cls_n)
print()
for c in range(cls_n):
    o = cls_off + 32 * c
    cidx = u32(o)
    acc = u32(o + 4)
    sup = u32(o + 8)
    ifaces = u32(o + 12)
    src = u32(o + 16)
    ann = u32(o + 20)
    cdata = u32(o + 24)
    sval = u32(o + 28)
    print(f'class[{c}] {get_str(u32(typ_off + 4 * cidx))!r} src={src} ann={ann} cdata={cdata} sval={sval}')
    if sval:
        t = d[sval]
        print('   static values head:', ' '.join(f'{x:02x}' for x in d[sval:sval + 40]))
    if ann:
        print('   ann head:', ' '.join(f'{x:02x}' for x in d[ann:ann + 40]))
