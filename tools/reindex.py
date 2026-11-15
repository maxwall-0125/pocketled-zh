# -*- coding: utf-8 -*-
"""重排 string_ids（保持 UTF-16 排序）+ 全量重写字符串索引引用。

ART 的 DexFileVerifier 要求 string_ids 严格按 UTF-16 排序，翻译破坏了顺序
（"Out-of-order string_ids"），所以必须做一次真正的重编号：
  1. 按译文重建字符串表，按 UTF-16 排序得到 new_index(old_index)
  2. 重写 string_ids 偏移表
  3. 重写所有字符串索引引用：type_ids / proto_ids(shorty) / field_ids(name) /
     method_ids(name) / class_defs(source_file) / code 里的 const-string
  4. 无法安全重写的可选区（debug_info、annotations）直接置 0 —— 二者都是可选的
"""
import struct, sys, hashlib, zlib, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexpatch import TRANS, uleb, uleb_read
from opformat import SIZE as SZ

ORIG = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\orig\classes.dex'
OUT = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\work\classes.dex'
STR_LIMIT_END = 19078   # string_data 之后第一个 map 段（annotation）


def sort_key(s):
    return s.encode('utf-16-be')


def main():
    d = bytearray(open(ORIG, 'rb').read())
    u32 = lambda o: struct.unpack_from('<I', d, o)[0]

    str_n, str_off = u32(0x38), u32(0x3C)
    typ_n, typ_off = u32(0x40), u32(0x44)
    pro_n, pro_off = u32(0x48), u32(0x4C)
    fld_n, fld_off = u32(0x50), u32(0x54)
    mth_n, mth_off = u32(0x58), u32(0x5C)
    cls_n, cls_off = u32(0x60), u32(0x64)

    # ---- 原字符串 ----
    offs = [u32(str_off + 4 * i) for i in range(str_n)]
    raw = {}
    for i, off in enumerate(offs):
        n, p = uleb_read(d, off)
        end = d.index(b'\x00', p)
        raw[i] = bytes(d[p:end])
    trans = {i: (old, new) for i, old, new in TRANS}
    new_text = {}
    for i in range(str_n):
        if i in trans:
            old_e, new_s = trans[i]
            assert raw[i].decode('utf-8') == old_e, f'idx {i}: {raw[i]!r} != {old_e!r}'
            new_text[i] = new_s
        else:
            new_text[i] = raw[i].decode('utf-8')

    # ---- 新顺序（必须严格递增，无重复）----
    order = sorted(range(str_n), key=lambda i: sort_key(new_text[i]))
    keys = [sort_key(new_text[i]) for i in order]
    for a, b in zip(keys, keys[1:]):
        assert a < b, f'重复/乱序: {a!r} {b!r}'
    newpos = {old: k for k, old in enumerate(order)}
    print(f'strings {str_n}: 重排完成，{len(trans)} 条被翻译')

    # ---- 重建 string_data（按新顺序紧凑排列）----
    region_start = min(offs)
    out = bytearray()
    new_off = {}
    for k, old in enumerate(order):
        s = new_text[old]
        units = len(s.encode('utf-16-le')) // 2
        new_off[old] = region_start + len(out)
        out += uleb(units) + s.encode('utf-8') + b'\x00'
    total = len(out)
    cap = STR_LIMIT_END - region_start
    print(f'string_data: {region_start}..{region_start + total} / 容量 {cap}')
    assert total <= cap, f'超出容量 {total} > {cap}'
    d[region_start:STR_LIMIT_END] = out + b'\x00' * (cap - total)

    # ---- string_ids 偏移（按新索引 = k）----
    for k, old in enumerate(order):
        struct.pack_into('<I', d, str_off + 4 * k, new_off[old])
    assert all(new_off[order[k]] < new_off[order[k + 1]] for k in range(str_n - 1))

    # ---- 各类索引引用 ----
    def rep32(o):
        struct.pack_into('<I', d, o, newpos[u32(o)])
    for i in range(typ_n):
        rep32(typ_off + 4 * i)              # descriptor_idx
    for i in range(pro_n):
        rep32(pro_off + 12 * i)             # shorty_idx
    for i in range(fld_n):
        rep32(fld_off + 8 * i + 4)          # name_idx
    for i in range(mth_n):
        rep32(mth_off + 8 * i + 4)          # name_idx

    # class_defs: source_file_idx → NO_INDEX，annotations_off → 0
    for c in range(cls_n):
        base = cls_off + 32 * c
        struct.pack_into('<I', d, base + 16, 0xFFFFFFFF)
        struct.pack_into('<I', d, base + 20, 0)

    # ---- 代码里的 const-string ----
    sites = []
    for c in range(cls_n):
        cdata = u32(cls_off + 32 * c + 24)
        if not cdata:
            continue
        o = cdata
        sf, o = uleb_read(d, o)
        inf, o = uleb_read(d, o)
        dm, o = uleb_read(d, o)
        vm, o = uleb_read(d, o)
        for _ in range(sf + inf):           # encoded_field
            _, o = uleb_read(d, o)
            _, o = uleb_read(d, o)
        for _ in range(dm + vm):            # encoded_method
            _, o = uleb_read(d, o)
            _, o = uleb_read(d, o)
            code_off, o = uleb_read(d, o)
            if not code_off:
                continue
            struct.pack_into('<I', d, code_off + 8, 0)   # debug_info_off = 0
            insns_size = struct.unpack_from('<I', d, code_off + 12)[0]
            ins = code_off + 16
            end = ins + insns_size * 2
            while ins < end:
                op = d[ins]
                size = SZ.get(op)
                assert size, f'unknown opcode 0x{op:02x} at {ins}'
                if op == 0x1a:
                    idx = struct.unpack_from('<H', d, ins + 2)[0]
                    sites.append((ins + 2, 2, idx))
                elif op == 0x1b:
                    idx = struct.unpack_from('<I', d, ins + 2)[0]
                    sites.append((ins + 2, 4, idx))
                ins += size * 2
            assert ins == end, (ins, end)

    for pos, width, idx in sites:
        nv = newpos[idx]
        assert nv < str_n
        if width == 2:
            struct.pack_into('<H', d, pos, nv)
        else:
            struct.pack_into('<I', d, pos, nv)
    print(f'const-string 站点: {len(sites)} 处')

    # ---- 头校验：先 signature 再 checksum ----
    struct.pack_into('<I', d, 8, 0)
    d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
    struct.pack_into('<I', d, 8, zlib.adler32(bytes(d[12:])) & 0xffffffff)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, 'wb').write(bytes(d))
    print('written', OUT, len(d))

    # ---- 自检：重新解析，确认新表有序 & 每条字符串解析正确 ----
    d2 = open(OUT, 'rb').read()
    o2 = lambda o: struct.unpack_from('<I', d2, o)[0]
    prev = None
    for k in range(str_n):
        off = o2(str_off + 4 * k)
        n, p = uleb_read(d2, off)
        end = d2.index(b'\x00', p)
        s = d2[p:end].decode('utf-8')
        assert len(s.encode('utf-16-le')) // 2 == n, (k, s, n)
        key = sort_key(s)
        assert prev is None or prev < key, f'ORDER FAIL at {k}: {s!r}'
        prev = key
    print('自检通过：string_ids 严格升序，共', str_n, '条')


if __name__ == '__main__':
    main()
