# -*- coding: utf-8 -*-
"""改 AndroidManifest.xml（二进制 AXML）里的 versionName / versionCode。

只重写文件开头的 string pool（保留原编码 utf-8 / utf-16、保留 style 段），
其余 chunk 原样后移；元素块内的字符串索引不变，因此不需要改任何引用。

用法：python bump_version.py <manifest.xml> <新 versionName> <新 versionCode> [--dry]
"""
import struct, sys, os

POOL = 0x0001
XML = 0x0003
START_ELEMENT = 0x0102
ATTR_VERSION_CODE = 0x0101021b
ATTR_VERSION_NAME = 0x0101021c
T_STR, T_INT = 0x03, 0x10


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def decode_pool(b, off):
    """返回 (info, strings)。info 里带 flags/样式区间，用于原样重编码。"""
    hsz = u16(b, off + 2)
    size = u32(b, off + 4)
    count, stylecount, flags, strstart, stycount = struct.unpack_from('<IIIII', b, off + 8)
    utf8 = bool(flags & 0x100)
    offs = [u32(b, off + hsz + 4 * i) for i in range(count)]
    styoffs = [u32(b, off + hsz + 4 * count + 4 * i) for i in range(stylecount)]
    base = off + strstart
    strings = []
    for o in offs:
        p = base + o
        if utf8:
            p += 1 if not (b[p] & 0x80) else 2          # 跳过 UTF-16 长度
            n = b[p]; p += 1
            if n & 0x80:
                n = ((n & 0x7f) << 8) | b[p]; p += 1
            strings.append(bytes(b[p:p + n]).decode('utf-8'))
        else:
            n = u16(b, p); p += 2
            if n & 0x8000:
                n = ((n & 0x7fff) << 16) | u16(b, p); p += 2
            strings.append(bytes(b[p:p + 2 * n]).decode('utf-16-le'))
    sty_end = u32(b, off + 12)  # stylesStart，无样式时为 0
    styles = b[off + sty_end: off + size] if sty_end else b''
    return dict(hsz=hsz, size=size, count=count, stylecount=stylecount, flags=flags,
                utf8=utf8, styoffs=styoffs, styles=styles), strings


def _len_utf16(n):
    """UTF-16 码元数（UTF-8 字符串头里的那个长度）。"""
    return len(n)  # 调用方传的是已解码 str，长度即码元数（BMP 文本足够）


def encode_pool(info, strings):
    utf8 = info['utf8']
    data = bytearray()
    offs = []
    for s in strings:
        offs.append(len(data))
        if utf8:
            u16len = len(s.encode('utf-16-le')) // 2
            payload = s.encode('utf-8')
            if u16len > 0x7f:
                data += bytes([0x80 | (u16len >> 8), u16len & 0xff])
            else:
                data.append(u16len)
            if len(payload) > 0x7f:
                data += bytes([0x80 | (len(payload) >> 8), len(payload) & 0xff])
            else:
                data.append(len(payload))
            data += payload + b'\x00'
        else:
            payload = s.encode('utf-16-le')
            n = len(payload) // 2
            if n > 0x7fff:
                data += struct.pack('<HH', 0x8000 | (n >> 16), n & 0xffff)
            else:
                data += struct.pack('<H', n)
            data += payload + b'\x00\x00'
    while len(data) % 4:
        data += b'\x00'

    hsz = 28
    strstart = hsz + 4 * len(strings) + 4 * info['stylecount']
    styblob = info['styles']
    # 有样式时样式偏移是相对 stylesStart 的，原本就在 styblob 内，长度不变 → 无需改
    while len(styblob) % 4:
        styblob += b'\x00'
    size = strstart + len(data) + len(styblob)
    head = struct.pack('<HHIIIIII', POOL, hsz, size, len(strings), info['stylecount'],
                       info['flags'], strstart, strstart + len(data) if info['stylecount'] else 0)
    out = head + b''.join(struct.pack('<I', o) for o in offs)
    if info['stylecount']:
        out += b''.join(struct.pack('<I', o) for o in info['styoffs'])
    return out + bytes(data) + styblob


def patch(path, new_name, new_code, dry):
    b = open(path, 'rb').read()
    assert u16(b, 0) == XML, 'not AXML'
    assert u16(b, 8) == POOL, 'first chunk is not a string pool'
    info, strings = decode_pool(b, 8)
    pool_off, pool_size = 8, info['size']
    rest = b[pool_off + pool_size:]

    # 先在 manifest 元素里定位两个属性（此时仍用旧 pool，字符串索引不变）
    scan = rest
    off = 0
    vname_idx = vcode_off = None
    vcode_old = None
    while off < len(scan):
        typ, hsz, sz = u16(scan, off), u16(scan, off + 2), u32(scan, off + 4)
        if sz == 0:
            break
        if typ == START_ELEMENT:
            name = u32(scan, off + 20)
            if strings[name] == 'manifest':
                astart, asize, acount = u16(scan, off + 24), u16(scan, off + 26), u16(scan, off + 28)
                ap = off + 16 + astart
                for i in range(acount):
                    a = ap + i * asize
                    resid = u32(scan, a + 8)
                    an = u32(scan, a + 4)
                    nm = strings[an] if an != 0xFFFFFFFF else None
                    if resid == ATTR_VERSION_NAME or nm == 'versionName':
                        assert scan[a + 15] == T_STR, f'versionName not string: {scan[a+15]:#x}'
                        vname_idx = u32(scan, a + 16)
                    elif resid == ATTR_VERSION_CODE or nm == 'versionCode':
                        assert scan[a + 15] == T_INT, f'versionCode not int: {scan[a+15]:#x}'
                        vcode_off = pool_off + pool_size + a
                        vcode_old = u32(scan, a + 16)
        off += sz
    assert vname_idx is not None and vcode_off is not None, 'manifest version attrs not found'

    old_name = strings[vname_idx]
    strings[vname_idx] = new_name
    print(f'  string pool: {info["count"]} strings, utf8={info["utf8"]}, styles={info["stylecount"]}')
    print(f'  versionName {old_name!r} -> {new_name!r} (string idx {vname_idx})')
    print(f'  versionCode {vcode_old} -> {new_code}')

    new_pool = encode_pool(info, strings)
    patched = bytearray(b[:pool_off] + new_pool + rest)
    shift = len(new_pool) - pool_size
    struct.pack_into('<I', patched, vcode_off + shift + 16, new_code)

    struct.pack_into('<I', patched, 4, len(patched))  # AXML 总长度
    if dry:
        print('  [dry run] not written')
        return
    open(path, 'wb').write(patched)
    print(f'  written {path} ({len(patched)} bytes, was {len(b)})')


if __name__ == '__main__':
    dry = '--dry' in sys.argv
    args = [a for a in sys.argv[1:] if a != '--dry']
    patch(args[0], args[1], int(args[2]), dry)
