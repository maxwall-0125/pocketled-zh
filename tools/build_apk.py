# -*- coding: utf-8 -*-
"""重新打包 APK 并做 APK Signature Scheme v2 签名（纯 Python）。"""
import struct, zlib, os, hashlib, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rsa_sign import load_key, sign_sha256

ROOT = r'C:\Users\maxwall\Desktop\DSH空间\pocketled'
ORIG = os.path.join(ROOT, 'orig')
WORK = os.path.join(ROOT, 'work')
OUT = os.path.join(ROOT, 'PocketLED-1.5-zh.apk')
KEYDIR = os.path.join(ROOT, 'key')

# (zip 内名称, 源目录, 是否强制 stored+4 对齐)
ENTRIES = [
    ('AndroidManifest.xml', WORK, False),
    ('res/drawable/ic_launcher_background.xml', ORIG, False),
    ('res/drawable/ic_launcher_foreground.xml', ORIG, False),
    ('res/mipmap-anydpi-v26/ic_launcher.xml', ORIG, False),
    ('resources.arsc', ORIG, True),
    ('classes.dex', WORK, False),
]

DOS_TIME = (15 << 11) | (30 << 5) | 0
DOS_DATE = ((2026 - 1980) << 9) | (11 << 5) | 15


def deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def build_entries():
    buf = bytearray()
    cdir = []
    for name, srcdir, stored in ENTRIES:
        raw = open(os.path.join(srcdir, name), 'rb').read()
        crc = zlib.crc32(raw) & 0xffffffff
        if stored:
            method, payload = 0, raw
        else:
            method, payload = 8, deflate(raw)
            assert len(payload) < len(raw)
        nb = name.encode('utf-8')
        off = len(buf)
        extra = b''
        if stored:
            base = 30 + len(nb)
            pad = (4 - (off + base) % 4) % 4
            if pad:
                pad += 4
                extra = struct.pack('<HH', 0x0000, pad - 4) + b'\x00' * (pad - 4)
        hdr = struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, method, DOS_TIME, DOS_DATE,
                          crc, len(payload), len(raw), len(nb), len(extra))
        buf += hdr + nb + extra + payload
        if stored:
            assert (off + base + len(extra)) % 4 == 0
        cdir.append((nb, method, crc, len(payload), len(raw), off))
        print(f'  {name:45s} method={method} size={len(raw)} -> {len(payload)} @{off}')
    return bytes(buf), cdir


def build_cd(cdir):
    out = bytearray()
    for nb, method, crc, csize, usize, off in cdir:
        out += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, method,
                           DOS_TIME, DOS_DATE, crc, csize, usize, len(nb),
                           0, 0, 0, 0, 0, off)
        out += nb
    return bytes(out)


def eocd(n, cd_size, cd_off, comment=b''):
    return struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, n, n, cd_size, cd_off, len(comment)) + comment


CHUNK = 1024 * 1024


def content_digest(sections):
    chunk_digests = []
    for sec in sections:
        for i in range(0, len(sec), CHUNK):
            c = sec[i:i + CHUNK]
            h = hashlib.sha256()
            h.update(b'\xa5' + struct.pack('<I', len(c)) + c)
            chunk_digests.append(h.digest())
    h = hashlib.sha256()
    h.update(b'\x5a' + struct.pack('<I', len(chunk_digests)))
    for d in chunk_digests:
        h.update(d)
    return h.digest(), len(chunk_digests)


def lp(b):
    return struct.pack('<I', len(b)) + b


def main():
    print('entries:')
    entries_bytes, cdir = build_entries()
    cd_bytes = build_cd(cdir)
    n = len(cdir)
    block_off = len(entries_bytes)

    # 摘要所用的 EOCD：CD 偏移写成「没有 signing block 时」的位置
    eocd_for_digest = eocd(n, len(cd_bytes), block_off)
    digest, chunks = content_digest([entries_bytes, cd_bytes, eocd_for_digest])
    print(f'content digest = {digest.hex()} over {chunks} chunks')

    cert = open(os.path.join(KEYDIR, 'cert.der'), 'rb').read()
    spki = open(os.path.join(KEYDIR, 'pub.spki'), 'rb').read()
    key = load_key(os.path.join(KEYDIR, 'key.txt'))

    SIG_ALGO = 0x0103  # RSASSA-PKCS1-v1_5 with SHA-256
    # 每个记录（算法 ID + 长度前缀值）自身也要长度前缀，序列再整体长度前缀
    digest_record = struct.pack('<I', SIG_ALGO) + lp(digest)
    digests_seq = lp(digest_record)
    signed_data = lp(digests_seq) + lp(lp(cert)) + lp(b'')
    sig = sign_sha256(signed_data, key)
    sig_record = struct.pack('<I', SIG_ALGO) + lp(sig)
    sigs_seq = lp(sig_record)
    signer = lp(signed_data) + lp(sigs_seq) + lp(spki)
    # value = LP(sequence of LP(signer))，单个签名者时即 lp(lp(signer))
    value = lp(lp(signer))

    pair = struct.pack('<Q', 4 + len(value)) + struct.pack('<I', 0x7109871a) + value
    block_size = len(pair) + 8 + 16
    block = (struct.pack('<Q', block_size) + pair +
             struct.pack('<Q', block_size) + b'APK Sig Block 42')
    assert len(block) == block_size + 8, (len(block), block_size)

    cd_off_final = block_off + len(block)
    eocd_final = eocd(n, len(cd_bytes), cd_off_final)
    out = entries_bytes + block + cd_bytes + eocd_final
    open(OUT, 'wb').write(out)
    print(f'written {OUT} ({len(out)} bytes), signing block {len(block)} bytes at {block_off}')


if __name__ == '__main__':
    main()
