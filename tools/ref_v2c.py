import struct, re
TAIL = r"C:\Users\maxwall\Desktop\DSH空间\pocketled\work\ref_tail.bin"
FILE_SIZE = 71413971
d = open(TAIL, 'rb').read()
base = FILE_SIZE - len(d)
i = d.rfind(b'PK\x05\x06')
cd_off = struct.unpack_from('<I', d, i + 16)[0]
cd_off_t = cd_off - base
size2 = struct.unpack_from('<Q', d, cd_off_t - 24)[0]
bs = cd_off_t - (size2 + 8)
blk = d[bs:cd_off_t]
print('block at', bs, 'len', len(blk))

for pat, name in [(b'\x1a\x87\x09\x71', 'v2 0x7109871a'),
                  (b'\x77\x65\x72\x42', 'verity pad 0x42726577'),
                  (b'\xc0\x68\x53\xf0', 'source stamp 0xf05368c0'),
                  (b'\x61\xad\x93\x1b', 'v3 0x1b93ad61')]:
    for m in re.finditer(re.escape(pat), blk):
        print(f'  {name} at {m.start()} (id field starts {m.start()-8})')

print()
# 从 8 开始按 (u64 len, u32 id) 走，遇到异常就打印上下文
o = 8
while o + 12 <= len(blk) - 24:
    ln, pid = struct.unpack_from('<QI', blk, o)
    if ln == 0 or o + 12 + ln > len(blk):
        print(f'o={o} BREAK len={ln} id=0x{pid:08x}')
        seg = blk[o:o + 48]
        print('   ctx:', ' '.join(f'{x:02x}' for x in seg))
        break
    print(f'o={o} len={ln} id=0x{pid:08x} end={o + 12 + ln}')
    o += 12 + ln
