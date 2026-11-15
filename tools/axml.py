import struct, sys, json

def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]
def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

def parse_pool(b, off):
    typ, hsz, sz = u16(b, off), u16(b, off + 2), u32(b, off + 4)
    count, stylecount, flags, strstart, stycount = struct.unpack_from('<IIIII', b, off + 8)
    utf8 = (flags & 0x100) != 0
    offs = [u32(b, off + hsz + 4 * i) for i in range(count)]
    base = off + strstart
    out = []
    for o in offs:
        p = base + o
        if utf8:
            # utf16 length
            n = b[p]; p += 1
            if n & 0x80:
                p += 1
            n = b[p]; p += 1
            if n & 0x80:
                n = ((n & 0x7f) << 8) | b[p]; p += 1
            out.append(bytes(b[p:p + n]).decode('utf-8', 'replace'))
        else:
            n = u16(b, p); p += 2
            if n & 0x8000:
                n = ((n & 0x7fff) << 16) | u16(b, p); p += 2
            out.append(bytes(b[p:p + 2 * n]).decode('utf-16-le', 'replace'))
    return out

def attr_val(vtype, vdata, pool):
    T_REF = 0x01; T_STR = 0x03; T_INT = 0x10; T_HEX = 0x11; T_BOOL = 0x12
    if vtype == T_STR:
        return pool[vdata]
    if vtype == T_INT:
        return vdata - (1 << 32) if vdata & 0x80000000 else vdata
    if vtype == T_HEX:
        return hex(vdata)
    if vtype == T_BOOL:
        return bool(vdata)
    if vtype == T_REF:
        return f'@res/{vdata:#x}'
    return f'{vtype:#x}:{vdata:#x}'

def dump(path):
    b = open(path, 'rb').read()
    pool = None
    out = []
    off = 8
    depth = 0
    while off < len(b):
        typ, hsz, sz = u16(b, off), u16(b, off + 2), u32(b, off + 4)
        if sz == 0:
            break
        if typ == RES_STRING_POOL_TYPE:
            pool = parse_pool(b, off)
        elif typ == RES_XML_RESOURCE_MAP:
            pass
        elif typ == RES_XML_START_ELEMENT:
            ns = u32(b, off + 16); name = u32(b, off + 20)
            attr_start = u16(b, off + 24); attr_size = u16(b, off + 26); attr_count = u16(b, off + 28)
            attrs = []
            ap = off + 16 + attr_start
            for i in range(attr_count):
                a = ap + i * attr_size
                ans = u32(b, a); an = u32(b, a + 4); araw = u32(b, a + 8)
                vt = b[a + 15] if isinstance(b[a + 15], int) else b[a + 15]
                vd = u32(b, a + 16)
                nm = pool[an] if an != 0xFFFFFFFF else (pool[araw] if araw != 0xFFFFFFFF else '?')
                attrs.append((nm, attr_val(vt, vd, pool)))
            out.append('  ' * depth + '<' + pool[name] + ''.join(f' {k}="{v}"' for k, v in attrs) + '>')
            depth += 1
        elif typ == RES_XML_END_ELEMENT:
            depth -= 1
            name = u32(b, off + 20)
            if depth >= 0:
                out.append('  ' * depth + '</' + pool[name] + '>')
        off += sz
    return out

if __name__ == '__main__':
    print('\n'.join(dump(sys.argv[1])))
