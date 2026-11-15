import struct

p = r"C:\Users\maxwall\Desktop\DSH空间\pocketled\work\classes.dex"
d = bytearray(open(p, 'rb').read())


def u32(o): return struct.unpack_from('<I', d, o)[0]
def u16(o): return struct.unpack_from('<H', d, o)[0]

str_n, str_off = u32(0x38), u32(0x3C)
typ_off = u32(0x44)
fld_off, fld_n = u32(0x54), u32(0x50)
mth_off = u32(0x5C)
cls_off = u32(0x64)


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


def get_type(i):
    return get_str(u32(typ_off + 4 * i))


print('--- 19762..19880 ---')
for a in range(19762, 19880, 16):
    print(f'{a}: ' + ' '.join(f'{x:02x}' for x in d[a:a + 16]))

# Config 的 static 字段
c = 1
o = cls_off + 32 * c
cdata = u32(o + 24)
sf, o2 = uleb(cdata)
inf, o2 = uleb(o2)
mf, o2 = uleb(o2)
print('\nConfig static_fields=', sf, 'instance=', inf, 'direct_methods=', mf)
pos = o2
for i in range(sf):
    fidx, pos = uleb(pos)
    acc, pos = uleb(pos)
    f = fld_off + 8 * fidx
    cls, typ = u16(f), u16(f + 2)
    nm = get_str(u32(f + 4))
    print(f'  static field {get_type(typ)} {nm} acc=0x{acc:x}')
