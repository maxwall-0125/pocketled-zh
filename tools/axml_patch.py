# -*- coding: utf-8 -*-
"""把 AndroidManifest 字符串池里的应用名改成中文（UTF-16 池，重建池后整体后移后续 chunk）。"""
import struct

SRC = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\orig\AndroidManifest.xml'
DST = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\work\AndroidManifest.xml'
OLD = 'Pocket LED'
NEW = '口袋 LED'

d = open(SRC, 'rb').read()
assert d[:4] == b'\x03\x00\x08\x00', d[:4].hex()
total = struct.unpack_from('<I', d, 4)[0]
assert total == len(d)

t, hs, size = struct.unpack_from('<HHI', d, 8)
assert t == 0x0001 and hs == 28
cnt, styc, flags, sstart, stystart = struct.unpack_from('<IIIII', d, 16)
assert flags == 0, 'expect UTF-16 pool'
assert stystart == 0, stystart
base = 8 + sstart
print('pool: count', cnt, 'size', size, 'data start', base)

entries = []
o = base
for i in range(cnt):
    st = o
    # UTF-16 池：长度前缀为 2 字节（0x8000 标志表示 4 字节）
    n = struct.unpack_from('<H', d, o)[0]
    o += 2
    if n & 0x8000:
        n = ((n & 0x7fff) << 16) | struct.unpack_from('<H', d, o)[0]
        o += 2
    s = d[o:o + 2 * n].decode('utf-16-le')
    o += 2 * n + 2
    entries.append(s)
    print(f'  [{i}] @{st} len={n} {s!r}')

assert entries.count(OLD) == 1, entries.count(OLD)
print('found', repr(OLD), 'at index', entries.index(OLD))
entries[entries.index(OLD)] = NEW

data = bytearray()
offs = []
for s in entries:
    offs.append(len(data))
    u = s.encode('utf-16-le')
    n = len(u) // 2
    if n > 0x7fff:
        raise SystemExit('too long')
    data += struct.pack('<H', n) + u + b'\x00\x00'
while len(data) % 4:
    data += b'\x00'

hdr = struct.pack('<HHI', 0x0001, 28, 28 + 4 * cnt + len(data))
hdr += struct.pack('<IIIII', cnt, 0, 0, 28 + 4 * cnt, 0)
hdr += b''.join(struct.pack('<I', x) for x in offs)
pool = hdr + bytes(data)
print('old pool chunk', size, 'new', len(pool))

rest = d[8 + size:]
out = bytearray(d[:8]) + pool + rest
struct.pack_into('<I', out, 4, len(out))
open(DST, 'wb').write(bytes(out))
print('written', DST, len(out), '(orig', len(d), ')')
