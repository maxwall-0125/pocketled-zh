# -*- coding: utf-8 -*-
"""校验改写后的 dex：header 校验和、区域外字节一致、译文可读。"""
import struct, hashlib, zlib, sys

ORIG = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\orig\classes.dex'
NEW = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\work\classes.dex'
A, B = 12782, 19078

o = open(ORIG, 'rb').read()
n = open(NEW, 'rb').read()
assert len(o) == len(n)

# header
magic, checksum, sig = n[:8], struct.unpack_from('<I', n, 8)[0], n[12:32]
print('magic', magic)
print('checksum ok', checksum == (zlib.adler32(n[12:]) & 0xffffffff))
print('sha1 ok', sig == hashlib.sha1(n[32:]).digest())
print('file_size field', struct.unpack_from('<I', n, 0x20)[0], 'actual', len(n))

print('tail region identical:', o[B:] == n[B:])
print('string_ids table changed:', o[0x70:0x70+4*357] != n[0x70:0x70+4*357])

# string dump for translated ids
ids = [25, 1, 2, 5, 15, 16, 17, 19, 20, 21, 22, 23, 31, 33, 34, 35, 36, 37,
       54, 148, 151, 152, 153, 154, 157, 158, 159, 160, 162, 181, 182]
str_n = struct.unpack_from('<I', n, 0x38)[0]
str_off = struct.unpack_from('<I', n, 0x3C)[0]
def rd(b, off):
    r = s = 0
    while True:
        x = b[off]; off += 1; r |= (x & 0x7f) << s
        if not x & 0x80: return r, off
        s += 7
print('string count', str_n)
for i in ids:
    off = struct.unpack_from('<I', n, str_off + 4 * i)[0]
    ln, p = rd(n, off)
    end = n.index(b'\x00', p)
    s = n[p:end].decode('utf-8')
    print(f'{i:4d} len={ln:3d} {s!r}')
