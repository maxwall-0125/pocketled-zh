import struct
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
print('len', len(blk), 'head', struct.unpack_from('<Q', blk, 0)[0], 'tail', struct.unpack_from('<Q', blk, len(blk) - 24)[0])
def hx(a, b):
    return ' '.join(f'{x:02x}' for x in blk[a:b])
print('0..24:', hx(0, 24))
print('1760..1800:', hx(1760, 1800))
print('end-40..end:', hx(len(blk) - 40, len(blk)))
# 精确定位 pair 边界：从 8 开始，读 len/id
o = 8
while o < len(blk) - 24:
    ln, pid = struct.unpack_from('<QI', blk, o)
    print(f'o={o} len={ln} id=0x{pid:08x}')
    if pid == 0x7109871a:
        val = blk[o + 12:o + 12 + ln]
        print('   value first u32:', struct.unpack_from('<I', val, 0)[0], 'value len', len(val),
              'trailing4:', val[-4:].hex())
    o += 12 + ln
    if o > len(blk):
        break
