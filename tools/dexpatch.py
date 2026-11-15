# -*- coding: utf-8 -*-
"""按字符串索引重写 classes.dex 的 string_data 区（保持所有其它偏移不变）。"""
import struct, sys, hashlib, zlib

ORIG = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\orig\classes.dex'
OUT = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\work\classes.dex'

# 每项: (索引, 原文, 译文)
TRANS = [
    (1,  ' % o menos', '% 及以下'),
    (2,  ' %)', ' %)'),
    (5,  ' – 0 %)', ' – 0 %)'),
    (25, 'Brillo: ', '亮度：'),
    (15, 'Amarillo', '黄色'),
    (16, 'Apagado', '关闭'),
    (17, 'Azul', '蓝色'),
    (19, 'Baja', '低电量'),
    (20, 'Baja (', '低电量 ('),
    (21, 'Batería baja: ', '低电量阈值：'),
    (22, 'Batería crítica: ', '危急电量阈值：'),
    (23, 'Blanco', '白色'),
    (31, 'Cian', '青色'),
    (33, 'Control del LED', '指示灯控制'),
    (34, 'Controlando el LED de batería', '正在控制电量指示灯'),
    (35, 'Controlar el LED de batería', '控制电量指示灯'),
    (36, 'Crítica', '危急'),
    (37, 'Crítica (', '危急 ('),
    (54, 'LED de batería detectado.', '已检测到电量指示灯。'),
    (148, 'Mientras la consola carga, el LED lo controla el sistema; "Probar" sigue funcionando.',
     '界面加载期间，指示灯由系统控制；“测试”仍然可用。'),
    (151, 'Naranja', '橙色'),
    (152, 'No se puede escribir en el LED: esta consola no es compatible.',
     '无法写入指示灯：此设备不受支持。'),
    (153, 'Normal', '正常'),
    (154, 'Normal (100 – ', '正常 (100 – '),
    (157, 'Parpadear', '闪烁'),
    (159, 'Pocket LED activo', '正在运行'),
    (160, 'Probar', '测试'),
    (162, 'Rojo', '红色'),
    (181, 'Verde', '绿色'),
    (182, 'Violeta', '紫色'),
]


def uleb(v):
    out = b''
    while True:
        b = v & 0x7f
        v >>= 7
        out += bytes([b | (0x80 if v else 0)])
        if not v:
            return out


def uleb_read(b, o):
    r = 0
    s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, o
        s += 7


def main():
    d = bytearray(open(ORIG, 'rb').read())
    str_n = struct.unpack_from('<I', d, 0x38)[0]
    str_off = struct.unpack_from('<I', d, 0x3C)[0]

    # 解析所有 string_data_item，按偏移排序
    items = []
    for i in range(str_n):
        off = struct.unpack_from('<I', d, str_off + 4 * i)[0]
        n, p = uleb_read(d, off)
        end = d.index(b'\x00', p)
        items.append((off, i, n, bytes(d[p:end])))

    items.sort()
    region_start = items[0][0]
    last = items[-1]
    region_end = last[0] + len(uleb(last[2])) + len(last[3]) + 1
    # 区域到下一 map 段（annotation, 19078）为止，可含零填充
    limit_end = 19078
    print(f'string_data region: {region_start}..{region_end} (next section at {limit_end}, '
          f'capacity {limit_end - region_start}, used {region_end - region_start})')

    trans = {i: (old, new) for i, old, new in TRANS}
    # 校验原文
    by_index = {i: (n, raw) for off, i, n, raw in items}
    blobs = {}
    for i, (old, new) in trans.items():
        n, raw = by_index[i]
        cur = raw.decode('utf-8')
        assert cur == old, f'idx {i}: 期望 {old!r}, 实际 {cur!r}'
        b = new.encode('utf-8')
        blobs[i] = (len(new), b)

    # 重新排布，同时记录每个索引的新偏移
    out = bytearray()
    new_off = {}
    for off, i, n, raw in items:
        new_off[i] = region_start + len(out)
        if i in blobs:
            nu, b = blobs[i]
        else:
            nu, b = n, raw
        out += uleb(nu) + b + b'\x00'
    total = len(out)
    print(f'new string_data size = {total}, capacity = {limit_end - region_start}')
    assert total <= limit_end - region_start, '译文过长，超出 string_data 区容量'

    d[region_start:region_start + total] = out
    # 其余补零
    d[region_start + total:limit_end] = b'\x00' * (limit_end - region_start - total)

    # 重写 string_ids 的偏移表（原地，尺寸不变）
    for i in range(str_n):
        struct.pack_into('<I', d, str_off + 4 * i, new_off[i])
    assert new_off[0] == region_start and max(new_off.values()) < limit_end
    assert all(new_off[k] < new_off[k + 1] for k in range(str_n - 1)), '偏移非单调'

    # 修正 header: 先写 SHA-1 signature(12..32)，再算 adler32 checksum(8)（checksum 覆盖 signature）
    import os
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    struct.pack_into('<I', d, 8, 0)
    d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
    struct.pack_into('<I', d, 8, zlib.adler32(bytes(d[12:])) & 0xffffffff)
    open(OUT, 'wb').write(bytes(d))
    print('written', OUT, len(d))


if __name__ == '__main__':
    main()
