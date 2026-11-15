# -*- coding: utf-8 -*-
"""打印 AXML 字符串池（UTF-8 池）条目：偏移、长度前缀、内容。"""
import struct, sys

p = sys.argv[1] if len(sys.argv) > 1 else \
    r'C:\Users\maxwall\Desktop\DSH空间\pocketled\orig\AndroidManifest.xml'
d = open(p, 'rb').read()
print('total len', len(d), 'magic', d[:4].hex())
# 查找 RES_STRING_POOL_TYPE 0x0001
off = 8
while off < len(d):
    t, hs, size = struct.unpack_from('<HHI', d, off)
    print(f'chunk @{off} type=0x{t:04x} header={hs} size={size}')
    if t == 0x0001:
        cnt, styc, flags, sstart, stystart = struct.unpack_from('<IIIII', d, off + 8)
        print('  strings', cnt, 'styles', styc, 'flags', hex(flags), 'strstart', sstart)
        base = off + sstart
        o = base
        for i in range(cnt):
            start = o
            # u16 长度（UTF-16 单元数）
            b0 = d[o]
            if b0 & 0x80:
                u16l = ((b0 & 0x7f) << 8) | d[o + 1]
                o += 2
            else:
                u16l = b0
                o += 1
            b1 = d[o]
            if b1 & 0x80:
                bl = ((b1 & 0x7f) << 8) | d[o + 1]
                o += 2
            else:
                bl = b1
                o += 1
            s = d[o:o + bl]
            o += bl + 1
            print(f'  [{i}] @{start} u16len={u16l} bytes={bl} size={o-start} {s.decode("utf-8", "replace")!r}')
        break
    off += size
