# -*- coding: utf-8 -*-
"""Dump static_values encoded arrays with resolved values."""
import sys
import struct
sys.path.insert(0, r'C:\Users\maxwall\Desktop\DSH空间\pocketled\tools')
import dexlib

VK = {0x00: 'byte', 0x02: 'short', 0x03: 'char', 0x04: 'int', 0x06: 'long',
      0x10: 'float', 0x11: 'double', 0x15: 'method_type', 0x16: 'method_handle',
      0x17: 'string', 0x18: 'type', 0x19: 'field', 0x1a: 'method', 0x1b: 'enum',
      0x1c: 'array', 0x1d: 'annotation', 0x1e: 'null', 0x1f: 'boolean'}


def dec(d, o):
    b = d[o]
    vt = b & 0x1F
    size = (b >> 5) + 1
    if vt == 0x1f:
        return vt, (b >> 5) != 0, o + 1
    if vt == 0x1e:
        return vt, None, o + 1
    v = int.from_bytes(d[o + 1:o + 1 + size], 'little', signed=True)
    return vt, v, o + 1 + size


def main(path):
    d = open(path, 'rb').read()
    dx = dexlib.Dex(d)
    for c in dx.classes:
        raw = c.get('static_values')
        name = dx.types[c['class_idx']]
        print('=== %s raw=%d' % (name, len(raw) if raw else 0))
        if not raw:
            continue
        print('   hex', raw.hex())
        o = 0
        while o < len(raw):
            vt, v, o = dec(raw, o)
            extra = ''
            if vt == 0x17:
                extra = ' "%s"' % dx.strings[v]
            elif vt == 0x18:
                extra = ' ' + dx.types[v]
            elif vt == 0x1a:
                extra = ' ' + dx.mstr(v)
            elif vt == 0x19:
                extra = ' ' + dx.fldstr(v)
            elif vt == 0x1b:
                extra = ' ' + dx.fldstr(v)
            elif vt == 0x10:
                extra = ' %r' % struct.unpack('<f', struct.pack('<I', v & 0xFFFFFFFF))[0]
            print('   %s = %r%s' % (VK.get(vt, hex(vt)), v, extra))


if __name__ == '__main__':
    main(sys.argv[1])
