import struct, sys

apk = sys.argv[1]
d = open(apk, 'rb').read()
i = d.rfind(b'PK\x05\x06')
cd_size, cd_off = struct.unpack_from('<II', d, i + 12)
assert d[cd_off - 16:cd_off] == b'APK Sig Block 42'
size2 = struct.unpack_from('<Q', d, cd_off - 24)[0]
bs = cd_off - (size2 + 8)
blk = d[bs:cd_off]
assert struct.unpack_from('<Q', blk, 0)[0] == len(blk) - 8
o = 8
pairs = []
while o < len(blk) - 24:
    ln, pid = struct.unpack_from('<QI', blk, o)
    assert o + 8 + ln <= len(blk) - 24, (o, ln, len(blk))
    pairs.append((pid, ln - 4))
    o += 8 + ln
assert o == len(blk) - 24, (o, len(blk) - 24)
print('block ok:', len(blk), 'pairs:', [(hex(p), n) for p, n in pairs])
print('cd_off in eocd ok:', (cd_off == bs + len(blk)))
