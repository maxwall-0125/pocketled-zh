import struct, sys, hashlib

TAIL = r"C:\Users\maxwall\Desktop\DSH空间\pocketled\work\ref_tail.bin"
FILE_SIZE = 71413971
d = open(TAIL, 'rb').read()
base = FILE_SIZE - len(d)

# EOCD
i = d.rfind(b'PK\x05\x06')
cd_size, cd_off = struct.unpack_from('<II', d, i + 12)
print('EOCD at', base + i, 'cd_off', cd_off, 'cd_size', cd_size)
cd_off_t = cd_off - base
assert cd_off_t > 0

# signing block 紧邻 CD 之前
magic = d[cd_off_t - 16:cd_off_t]
print('magic:', magic)
size2 = struct.unpack_from('<Q', d, cd_off_t - 24)[0]
block_start_t = cd_off_t - (size2 + 8)
block = d[block_start_t:cd_off_t]
print('block size', len(block), 'declared', size2 + 8)
print('head size', struct.unpack_from('<Q', block, 0)[0])

o = 8
while o < len(block) - 24:
    ln, pid = struct.unpack_from('<QI', block, o)
    print(f'  pair id=0x{pid:08x} len={ln}')
    val = block[o + 12:o + 12 + ln]
    if pid == 0x7109871a:
        def rlp(b, off):
            n = struct.unpack_from('<I', b, off)[0]
            return b[off + 4:off + 4 + n], off + 4 + n
        signers, _ = rlp(val, 0)
        signer, _ = rlp(signers, 0)
        print('   signer len', len(signer), 'signers seq', len(signers))
        sd, o2 = rlp(signer, 0)
        sigs, o3 = rlp(signer, o2)
        pk, o4 = rlp(signer, o3)
        print('   signed_data', len(sd), 'sigs', len(sigs), 'pk', len(pk), 'end', o4)
        print('   sigs hex:', sigs.hex())
        dg, o5 = rlp(sd, 0)
        print('   digests seq len', len(dg), 'hex head:', dg.hex()[:120])
        # 逐层检查：digests seq 的第一个元素是否是 LP 记录
        first = struct.unpack_from('<I', dg, 0)[0]
        print('   first u32 in digests seq:', first, hex(first))
        certs, o6 = rlp(sd, o5)
        print('   certs seq', len(certs), 'attrs', len(rlp(sd, o6)[0]))
    o += 12 + ln
print('trailing uint64:', struct.unpack_from('<Q', block, len(block) - 24)[0])
