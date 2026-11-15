# -*- coding: utf-8 -*-
"""校验产出的 APK：zip 完整性 + APK Signature Scheme v2 签名 + 内容摘要。"""
import struct, hashlib, zipfile, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsa_sign import verify_sha256

APK = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\PocketLED-1.5-zh.apk'
CHUNK = 1024 * 1024


def find_eocd(d):
    i = d.rfind(b'PK\x05\x06')
    assert i >= 0
    return i


def main():
    d = open(APK, 'rb').read()
    print('size', len(d))
    e = find_eocd(d)
    (sig, dsk, cdsk, cnt_disk, cnt, cd_size, cd_off, clen) = struct.unpack_from('<IHHHHIIH', d, e)
    print(f'EOCD: entries={cnt} cd_size={cd_size} cd_off={cd_off} comment={clen}')
    assert cd_off + cd_size == e, (cd_off + cd_size, e)

    # ---- APK Signing Block ----
    magic = b'APK Sig Block 42'
    assert d[cd_off - 16:cd_off] == magic, d[cd_off - 16:cd_off]
    size2 = struct.unpack_from('<Q', d, cd_off - 24)[0]
    block_start = cd_off - 8 - size2
    size1 = struct.unpack_from('<Q', d, block_start)[0]
    print('signing block:', block_start, 'to', cd_off, 'sizes', size1, size2)
    assert size1 == size2

    pairs = d[block_start + 8:cd_off - 24]
    pairs_len = struct.unpack_from('<Q', pairs, 0)[0] if False else None
    o = 0
    found = None
    while o < len(pairs):
        ln = struct.unpack_from('<Q', pairs, o)[0]
        pid = struct.unpack_from('<I', pairs, o + 8)[0]
        val = pairs[o + 12:o + 8 + ln]
        print(f'  pair id=0x{pid:08x} len={ln}')
        if pid == 0x7109871a:
            found = val
        o += 8 + ln
    assert found is not None, 'no v2 block'
    assert o == len(pairs), (o, len(pairs))

    # ---- v2 结构 ----
    def read_lp(b, o):
        n = struct.unpack_from('<I', b, o)[0]
        return b[o + 4:o + 4 + n], o + 4 + n

    signers, _ = read_lp(found, 0)
    signer, _ = read_lp(signers, 0)
    signed_data, o = read_lp(signer, 0)
    sigs, o = read_lp(signer, o)
    pubkey, o = read_lp(signer, o)
    assert o == len(signer)

    digests_seq, o = read_lp(signed_data, 0)
    certs_seq, o = read_lp(signed_data, o)
    attrs_seq, o = read_lp(signed_data, o)
    assert o == len(signed_data), (o, len(signed_data))
    assert attrs_seq == b''

    digests = []
    o = 0
    while o < len(digests_seq):
        rec, o = read_lp(digests_seq, o)  # 每条记录自身也带长度前缀
        aid = struct.unpack_from('<I', rec, 0)[0]
        dg, ro = read_lp(rec, 4)
        assert ro == len(rec), (ro, len(rec))
        digests.append((aid, dg))
    print('  digest algos:', [(hex(a), g.hex()[:16]) for a, g in digests])

    certs = []
    o = 0
    while o < len(certs_seq):
        c, o = read_lp(certs_seq, o)
        certs.append(c)
    print('  certs:', [len(c) for c in certs])

    sigs_list = []
    o = 0
    while o < len(sigs):
        rec, o = read_lp(sigs, o)  # 每条签名记录自身也带长度前缀
        aid = struct.unpack_from('<I', rec, 0)[0]
        sg, ro = read_lp(rec, 4)
        assert ro == len(rec), (ro, len(rec))
        sigs_list.append((aid, sg))
    print('  sig algos:', [(hex(a), len(s)) for a, s in sigs_list])

    # ---- 重算内容摘要（模拟 signing block 不存在）----
    sec1 = d[:block_start]
    sec2 = d[cd_off:cd_off + cd_size]
    eocd_patched = bytearray(d[e:])
    struct.pack_into('<I', eocd_patched, 16, block_start)
    sec3 = bytes(eocd_patched)
    chunk_digests = []
    for sec in (sec1, sec2, sec3):
        for i in range(0, len(sec), CHUNK):
            c = sec[i:i + CHUNK]
            h = hashlib.sha256()
            h.update(b'\xa5' + struct.pack('<I', len(c)) + c)
            chunk_digests.append(h.digest())
    h = hashlib.sha256()
    h.update(b'\x5a' + struct.pack('<I', len(chunk_digests)))
    for x in chunk_digests:
        h.update(x)
    calc = h.digest()
    print('  recomputed digest:', calc.hex())
    ok_digest = any(g == calc for a, g in digests)
    print('  DIGEST MATCH:', ok_digest)

    # ---- 用公钥验签 ----
    print('  cert bytes:', [len(c) for c in certs],
          'pubkey in cert:', all(pubkey in c for c in certs))
    import subprocess, json
    # 从 SPKI DER 里取 n、e（RSA 2048→ n 256 字节, e 3 字节）
    n_part, e_part = rsa_parts(pubkey)
    sig = [s for a, s in sigs_list if a == 0x0103][0]
    ok_sig = verify_sha256(signed_data, sig, n_part, e_part)
    print('  SIGNATURE VALID:', ok_sig)

    # ---- zip 完整性 ----
    z = zipfile.ZipFile(APK)
    print('  zip test (None=ok):', z.testzip())
    for i in z.infolist():
        print(f'   {i.filename:45s} {i.compress_type} {i.file_size} {i.compress_size} '
              f'offset={i.header_offset} extra={len(i.extra)}')

    assert ok_digest and ok_sig and z.testzip() is None
    print('ALL CHECKS PASSED')


def rsa_parts(spki):
    """DER 解析 SubjectPublicKeyInfo，取出 RSA 的 modulus / exponent。"""
    def tlv(b, o):
        tag = b[o]
        o += 1
        ln = b[o]
        o += 1
        if ln & 0x80:
            k = ln & 0x7f
            ln = int.from_bytes(b[o:o + k], 'big')
            o += k
        return tag, o, ln

    tag, o, ln = tlv(spki, 0)
    assert tag == 0x30
    # 第一项 AlgorithmIdentifier
    t1, o1, l1 = tlv(spki, o)
    o2 = o1 + l1
    # 第二项 BIT STRING
    t2, o3, l2 = tlv(spki, o2)
    assert t2 == 0x03, hex(t2)
    assert spki[o3] == 0x00
    o3 += 1
    t3, o4, l3 = tlv(spki, o3)
    assert t3 == 0x30
    t4, o5, l4 = tlv(spki, o4)
    assert t4 == 0x02
    n = int.from_bytes(spki[o5:o5 + l4], 'big')
    o6 = o5 + l4
    t5, o7, l5 = tlv(spki, o6)
    assert t5 == 0x02
    e = int.from_bytes(spki[o7:o7 + l5], 'big')
    print(f'  pubkey: n={n.bit_length()} bits, e={e}')
    return n, e


if __name__ == '__main__':
    main()
