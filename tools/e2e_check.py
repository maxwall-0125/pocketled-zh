# -*- coding: utf-8 -*-
"""端到端检查：从成品 APK 内解出 dex/manifest，确认中文文本与对齐。"""
import zipfile, struct, os

APK = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\PocketLED-1.5-zh.apk'
OUT = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\work\check'

os.makedirs(OUT, exist_ok=True)
z = zipfile.ZipFile(APK)
print('entries:', len(z.infolist()))
for i in z.infolist():
    print(f'  {i.filename:45s} method={i.compress_type} size={i.file_size} '
          f'local_off={i.header_offset} crc={i.CRC:08x}')

z.extractall(OUT)

# ---- resources.arsc 对齐 ----
d = open(APK, 'rb').read()
i = z.getinfo('resources.arsc')
local = i.header_offset
nlen, elen = struct.unpack_from('<HH', d, local + 26)
data_off = local + 30 + nlen + elen
print('resources.arsc data offset', data_off, 'align4', data_off % 4 == 0, 'method', i.compress_type)

# ---- dex 字符串 ----
dex = open(os.path.join(OUT, 'classes.dex'), 'rb').read()
str_n = struct.unpack_from('<I', dex, 0x38)[0]
str_off = struct.unpack_from('<I', dex, 0x3C)[0]


def rd(b, o):
    r = s = 0
    while True:
        x = b[o]; o += 1; r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, o
        s += 7


def s_of(k):
    off = struct.unpack_from('<I', dex, str_off + 4 * k)[0]
    ln, p = rd(dex, off)
    end = dex.index(b'\x00', p)
    return dex[p:end].decode('utf-8')


zh = [(k, s_of(k)) for k in range(str_n) if any('\u4e00' <= ch <= '\u9fff' for ch in s_of(k))]
print(f'\n中文条目 {len(zh)} 条:')
for k, s in zh:
    print(f'  {k:3d} {s}')
