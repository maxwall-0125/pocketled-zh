import struct, sys, io

SZ = {}
for o in list(range(0x00, 0x0a)) + [0x0e, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x73, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed]:
    SZ[o] = 1
for o in list(range(0x0a, 0x0e)) + list(range(0x0f, 0x12)) + [0x1d, 0x1e, 0x21, 0x27, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f] + list(range(0x80, 0x90)) + list(range(0xb0, 0xc0)):
    SZ[o] = 1
for o in [0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x20, 0x22, 0x23, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f] + list(range(0x60, 0x6e)) + list(range(0x74, 0x7b)) + [0xfe, 0xff]:
    SZ[o] = 2
for o in [0x03, 0x06, 0x09, 0x1b, 0x24, 0x25, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0xfd]:
    SZ[o] = 3
for o in [0x14, 0x17, 0x1a, 0x1c, 0x1f, 0x26, 0x2b, 0x2c, 0xfa, 0xfb]:
    SZ[o] = 2
SZ[0x14] = 3; SZ[0x17] = 3; SZ[0x1b] = 3; SZ[0x26] = 3; SZ[0x2b] = 3; SZ[0x2c] = 3; SZ[0xfa] = 4; SZ[0xfb] = 4
for o in range(0x2d, 0x32): SZ[o] = 2
for o in range(0x32, 0x38): SZ[o] = 2
for o in range(0x38, 0x3e): SZ[o] = 2
for o in range(0x44, 0x52): SZ[o] = 2
for o in range(0x90, 0xa0): SZ[o] = 2
for o in range(0xa0, 0xb0): SZ[o] = 2
for o in range(0xc0, 0xd8): SZ[o] = 2
for o in range(0xd8, 0xe3): SZ[o] = 2
for o in range(0xee, 0xfa): SZ[o] = 2
SZ[0x18] = 5
SZ[0x1a] = 2
SZ[0x1b] = 3

def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]

def uleb(b, o):
    r = 0; s = 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7f) << s
        if not x & 0x80: return r, o
        s += 7

class Dex:
    def __init__(self, data):
        self.d = data
        self.strs_off, self.strs_n = struct.unpack_from('<II', data, 0x3C)[0], struct.unpack_from('<II', data, 0x38)[0]
        self.types_off = u32(data, 0x44); self.types_n = u32(data, 0x40)
        self.protos_off = u32(data, 0x4C); self.protos_n = u32(data, 0x48)
        self.fields_off = u32(data, 0x54); self.fields_n = u32(data, 0x50)
        self.methods_off = u32(data, 0x5C); self.methods_n = u32(data, 0x58)
        self.classes_off = u32(data, 0x64); self.classes_n = u32(data, 0x60)
    def string(self, i):
        off = u32(self.d, self.strs_off + 4 * i)
        n, p = uleb(self.d, off)
        e = self.d.index(b'\x00', p)
        return self.d[p:e].decode('utf-8', 'replace')
    def type(self, i):
        return self.string(u32(self.d, self.types_off + 4 * i))
    def method(self, i):
        o = self.methods_off + 8 * i
        cls = u16(self.d, o); proto = u16(self.d, o + 2); name = u32(self.d, o + 4)
        return f'{self.type(cls)}->{self.string(name)}'

def dump_code(dex, code_off, out):
    d = dex.d
    regs = u16(d, code_off); ins = u16(d, code_off + 2); tries = u16(d, code_off + 6)
    insn_size = u32(d, code_off + 12)
    start = code_off + 16
    end = start + insn_size * 2
    p = start
    while p < end:
        op = d[p]
        n = SZ.get(op, 1)
        raw = d[p:p + 2 * n]
        txt = ''
        if op == 0x1a:
            idx = u16(d, p + 2)
            txt = f'const-string v{d[p+1] >> 4}, "{dex.string(idx)}"'
        elif op == 0x1b:
            idx = u32(d, p + 2)
            txt = f'const-string/jumbo v{d[p+1]}, "{dex.string(idx)}"'
        elif op in (0x6e, 0x6f, 0x70, 0x71, 0x72):
            idx = u16(d, p + 2)
            txt = f'invoke-* {{...}}, {dex.method(idx)}'
        elif op == 0x24:
            idx = u16(d, p + 2)
            txt = f'invoke-virtual/range, {dex.method(idx)}'
        elif op in (0x6c, 0x6d):
            idx = u16(d, p + 2)
            txt = f'invoke-static/range, {dex.method(idx)}'
        out.append(f'    {p - start:5d}: {op:02x} {txt}')
        p += 2 * n
    if tries:
        out.append(f'    (tries={tries})')

def main(path, only_strings=None):
    data = open(path, 'rb').read()
    dex = Dex(data)
    out = []
    for ci in range(dex.classes_n):
        o = dex.classes_off + 32 * ci
        cls_idx = u32(data, o)
        cdata_off = u32(data, o + 24)
        cname = dex.type(cls_idx)
        out.append(f'CLASS {cname} class_data={cdata_off}')
        if not cdata_off:
            continue
        p = cdata_off
        sf, p = uleb(data, p); inf, p = uleb(data, p)
        dm, p = uleb(data, p); vm, p = uleb(data, p)
        for _ in range(sf):
            _, p = uleb(data, p); _, p = uleb(data, p)
        for _ in range(inf):
            _, p = uleb(data, p); _, p = uleb(data, p)
        for kind, cnt in (('direct', dm), ('virtual', vm)):
            idx = 0
            for _ in range(cnt):
                diff, p = uleb(data, p)
                idx += diff
                acc, p = uleb(data, p)
                code_off, p = uleb(data, p)
                name = dex.method(idx)
                if code_off:
                    out.append(f'  METHOD[{kind}] {name} off={code_off}')
                    dump_code(dex, code_off, out)
    s = '\n'.join(out)
    sys.stdout.write(s)

if __name__ == '__main__':
    main(sys.argv[1])
