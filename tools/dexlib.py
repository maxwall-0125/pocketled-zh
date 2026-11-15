# -*- coding: utf-8 -*-
"""Minimal DEX parser / assembler / rewriter (pure Python, no external tools).
  * parse dex into a model (strings/types/protos/fields/methods/classes/code)
  * instruction-level decode / encode; whole-file offsets are recomputed
  * append-only remap keeps existing indices stable
"""
import struct, hashlib, zlib

NO_INDEX = 0xFFFFFFFF

# ---------------------------------------------------------------- uleb / sleb


def uleb_read(d, o):
    r = s = 0
    while True:
        b = d[o]
        o += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            return r, o
        s += 7


def sleb_read(d, o):
    r = s = 0
    while True:
        b = d[o]
        o += 1
        r |= (b & 0x7F) << s
        s += 7
        if not (b & 0x80):
            if b & 0x40:
                r -= 1 << s
            return r, o


def uleb(v):
    out = bytearray()
    v &= 0xFFFFFFFF
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if (v == 0 and not (b & 0x40)) or (v == -1 and (b & 0x40)):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def mutf8_len_units(s):
    return len(s.encode('utf-16-le')) // 2


# ---------------------------------------------------------------- opcode tables
FMT = {}
MNEM = {}


def _f(fmt, ops, names):
    for o, n in zip(ops, names):
        assert o not in FMT, hex(o)
        FMT[o] = fmt
        MNEM[o] = n


_f('10x', [0x00, 0x0e, 0x73], ['nop', 'return-void', 'unused-73'])
_f('10x', list(range(0x3e, 0x44)), ['unused-3e', 'unused-3f', 'unused-40', 'unused-41',
                                    'unused-42', 'unused-43'])
_f('10x', list(range(0xe3, 0xfa)), ['unused-%02x' % i for i in range(0xe3, 0xfa)])
_f('12x', [0x01, 0x04, 0x07, 0x21], ['move', 'move-wide', 'move-object', 'array-length'])
_f('12x', [0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83],
   ['neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double',
    'int-to-long', 'int-to-float', 'int-to-double'])
_f('12x', list(range(0x84, 0x8a)),
   ['long-to-int', 'long-to-float', 'long-to-double', 'float-to-int', 'float-to-long',
    'float-to-double'])
_f('12x', list(range(0x8a, 0x90)), ['double-to-int', 'double-to-long', 'double-to-float',
                                   'int-to-byte', 'int-to-char', 'int-to-short'])
_f('12x', list(range(0xb0, 0xc0)),
   ['add-int/2addr', 'sub-int/2addr', 'mul-int/2addr', 'div-int/2addr', 'rem-int/2addr',
    'and-int/2addr', 'or-int/2addr', 'xor-int/2addr', 'shl-int/2addr', 'shr-int/2addr',
    'ushr-int/2addr', 'add-long/2addr', 'sub-long/2addr', 'mul-long/2addr',
    'div-long/2addr', 'rem-long/2addr'])
_f('12x', list(range(0xc0, 0xd0)),
   ['and-long/2addr', 'or-long/2addr', 'xor-long/2addr', 'shl-long/2addr', 'shr-long/2addr',
    'ushr-long/2addr', 'add-float/2addr', 'sub-float/2addr', 'mul-float/2addr',
    'div-float/2addr', 'rem-float/2addr', 'add-double/2addr', 'sub-double/2addr',
    'mul-double/2addr', 'div-double/2addr', 'rem-double/2addr'])
_f('22x', [0x02, 0x05, 0x08], ['move/from16', 'move-wide/from16', 'move-object/from16'])
_f('32x', [0x03, 0x06, 0x09], ['move/16', 'move-wide/16', 'move-object/16'])
_f('11x', [0x0a, 0x0b, 0x0c, 0x0d, 0x0f, 0x10, 0x11, 0x1d, 0x1e, 0x27],
   ['move-result', 'move-result-wide', 'move-result-object', 'move-exception', 'return',
    'return-wide', 'return-object', 'monitor-enter', 'monitor-exit', 'throw'])
_f('11n', [0x12], ['const/4'])
_f('21s', [0x13, 0x16], ['const/16', 'const-wide/16'])
_f('21h', [0x15, 0x19], ['const/high16', 'const-wide/high16'])
_f('31i', [0x14, 0x17], ['const', 'const-wide/32'])
_f('51l', [0x18], ['const-wide'])
_f('21c', [0x1a, 0x1c, 0x1f, 0x22], ['const-string', 'const-class', 'check-cast', 'new-instance'])
_f('21c', list(range(0x60, 0x6e)),
   ['sget', 'sget-wide', 'sget-object', 'sget-boolean', 'sget-byte', 'sget-char',
    'sget-short', 'sput', 'sput-wide', 'sput-object', 'sput-boolean', 'sput-byte',
    'sput-char', 'sput-short'])
_f('21c', [0xfe, 0xff], ['const-method-handle', 'const-method-type'])
_f('31c', [0x1b], ['const-string/jumbo'])
_f('22c', [0x20, 0x23], ['instance-of', 'new-array'])
_f('22c', list(range(0x52, 0x60)),
   ['iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char',
    'iget-short', 'iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte',
    'iput-char', 'iput-short'])
_f('35c', [0x24], ['filled-new-array'])
_f('35c', list(range(0x6e, 0x73)),
   ['invoke-virtual', 'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface'])
_f('35c', [0xfc], ['invoke-custom'])
_f('3rc', [0x25], ['filled-new-array/range'])
_f('3rc', list(range(0x74, 0x79)),
   ['invoke-virtual/range', 'invoke-super/range', 'invoke-direct/range',
    'invoke-static/range', 'invoke-interface/range'])
_f('3rc', [0xfd], ['invoke-custom/range'])
_f('31t', [0x26, 0x2b, 0x2c], ['fill-array-data', 'packed-switch', 'sparse-switch'])
_f('10t', [0x28], ['goto'])
_f('20t', [0x29], ['goto/16'])
_f('30t', [0x2a], ['goto/32'])
_f('23x', list(range(0x2d, 0x32)), ['cmpl-float', 'cmpg-float', 'cmpl-double', 'cmpg-double',
                                   'cmp-long'])
_f('23x', list(range(0x44, 0x52)),
   ['aget', 'aget-wide', 'aget-object', 'aget-boolean', 'aget-byte', 'aget-char',
    'aget-short', 'aput', 'aput-wide', 'aput-object', 'aput-boolean', 'aput-byte',
    'aput-char', 'aput-short'])
_f('23x', list(range(0x90, 0xb0)),
   ['add-int', 'sub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int',
    'shl-int', 'shr-int', 'ushr-int', 'add-long', 'sub-long', 'mul-long', 'div-long',
    'rem-long', 'and-long', 'or-long', 'xor-long', 'shl-long', 'shr-long', 'ushr-long',
    'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float', 'add-double',
    'sub-double', 'mul-double', 'div-double', 'rem-double'])
_f('22t', list(range(0x32, 0x38)), ['if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le'])
_f('21t', list(range(0x38, 0x3e)), ['if-eqz', 'if-nez', 'if-ltz', 'if-gez', 'if-gtz', 'if-lez'])
_f('22s', list(range(0xd0, 0xd8)),
   ['add-int/lit16', 'rsub-int', 'mul-int/lit16', 'div-int/lit16', 'rem-int/lit16',
    'and-int/lit16', 'or-int/lit16', 'xor-int/lit16'])
_f('22b', list(range(0xd8, 0xe3)),
   ['add-int/lit8', 'rsub-int/lit8', 'mul-int/lit8', 'div-int/lit8', 'rem-int/lit8',
    'and-int/lit8', 'or-int/lit8', 'xor-int/lit8', 'shl-int/lit8', 'shr-int/lit8',
    'ushr-int/lit8'])
_f('45cc', [0xfa], ['invoke-polymorphic'])
_f('4rcc', [0xfb], ['invoke-polymorphic/range'])

SIZE = {}
for o, fmt in FMT.items():
    SIZE[o] = {'10x': 1, '12x': 1, '11n': 1, '11x': 1, '10t': 1,
               '20t': 2, '22x': 2, '21t': 2, '21s': 2, '21h': 2, '21c': 2,
               '23x': 2, '22b': 2, '22t': 2, '22s': 2, '22c': 2,
               '30t': 3, '32x': 3, '31i': 3, '31t': 3, '31c': 3,
               '35c': 3, '3rc': 3, '51l': 5, '45cc': 4, '4rcc': 4}[fmt]


MNEM[0x0100] = 'packed-switch-payload'
MNEM[0x0200] = 'sparse-switch-payload'
MNEM[0x0300] = 'fill-array-data-payload'
SIZE[0x0100] = SIZE[0x0200] = SIZE[0x0300] = 0


class Ins(object):
    """A single instruction; fields depend on the instruction format."""
    __slots__ = ('op', 'a', 'b', 'c', 'lit', 'idx', 'target', 'regs', 'start', 'proto', 'raw')

    def __init__(self, op, **kw):
        self.op = op
        for k in self.__slots__[1:]:
            setattr(self, k, kw.get(k))

    @property
    def size(self):
        if self.raw is not None:
            return len(self.raw)
        return SIZE[self.op]

    def __repr__(self):
        n = MNEM[self.op]
        parts = []
        for k in ('a', 'b', 'c', 'regs', 'start', 'lit', 'idx', 'proto', 'target'):
            v = getattr(self, k)
            if v is not None:
                parts.append('%s=%r' % (k, v))
        return '%s(%s)' % (n, ' '.join(parts))


def decode(d, start, count):
    """Decode code units into Ins list; returns (insns, unit offsets)."""
    end = start + count * 2
    ins = []
    offs = []
    p = start
    while p < end:
        offs.append((p - start) // 2)
        op = d[p]
        w1 = struct.unpack_from('<H', d, p)[0]
        if op == 0x00 and (w1 >> 8) in (0x01, 0x02, 0x03):
            ident = w1 >> 8
            if ident == 0x01:                      # packed-switch-payload
                n = struct.unpack_from('<H', d, p + 2)[0]
                units = 4 + 2 * n
                code = 0x0100
            elif ident == 0x02:                    # sparse-switch-payload
                n = struct.unpack_from('<H', d, p + 2)[0]
                units = 2 + 4 * n
                code = 0x0200
            else:                                  # fill-array-data-payload
                ew = struct.unpack_from('<H', d, p + 2)[0]
                n = struct.unpack_from('<I', d, p + 4)[0]
                units = 4 + (ew * n + 1) // 2
                code = 0x0300
            raw = list(struct.unpack_from('<%dH' % units, d, p))
            assert p + units * 2 <= end, 'payload overruns code item'
            ins.append(Ins(code, raw=raw))
            p += units * 2
            continue
        fmt = FMT[op]
        nm = SIZE[op]
        if fmt == '10x':
            i = Ins(op)
        elif fmt == '12x':
            i = Ins(op, a=w1 >> 8 & 0xF, b=w1 >> 12)
        elif fmt == '11n':
            sn = w1 >> 12
            i = Ins(op, a=w1 >> 8 & 0xF, lit=sn - 16 if sn >= 8 else sn)
        elif fmt == '11x':
            i = Ins(op, a=w1 >> 8)
        elif fmt == '10t':
            # target is stored as an absolute unit offset from insns start
            i = Ins(op, target=(p - start) // 2 + struct.unpack_from("<b", d, p + 1)[0])
        elif fmt in ('20t', '21t', '31t'):
            t = struct.unpack_from('<i' if fmt == '31t' else '<h', d, p + 2)[0]
            i = Ins(op, a=((w1 >> 8) & 0xF) if fmt != '20t' else None,
                    target=(p - start) // 2 + t)
        elif fmt == '22x':
            i = Ins(op, a=w1 >> 8, b=struct.unpack_from('<H', d, p + 2)[0])
        elif fmt in ('21s', '21h'):
            i = Ins(op, a=w1 >> 8, lit=struct.unpack_from('<h', d, p + 2)[0])
        elif fmt == '21c':
            i = Ins(op, a=w1 >> 8, idx=struct.unpack_from('<H', d, p + 2)[0])
        elif fmt == '23x':
            w2 = struct.unpack_from('<H', d, p + 2)[0]
            i = Ins(op, a=w1 >> 8, b=w2 & 0xFF, c=w2 >> 8)
        elif fmt == '22b':
            w2 = struct.unpack_from('<H', d, p + 2)[0]
            i = Ins(op, a=w1 >> 8, b=w2 & 0xFF,
                    lit=struct.unpack_from('<b', d, p + 3)[0])
        elif fmt in ('22t', '22s', '22c'):
            w2 = struct.unpack_from('<h' if fmt == '22s' else '<H', d, p + 2)[0]
            if fmt == '22t':
                i = Ins(op, a=(w1 >> 8) & 0xF, b=w1 >> 12, target=(p - start) // 2 + w2)
            elif fmt == '22s':
                i = Ins(op, a=(w1 >> 8) & 0xF, b=w1 >> 12, lit=w2)
            else:
                i = Ins(op, a=(w1 >> 8) & 0xF, b=w1 >> 12, idx=w2)
        elif fmt == '30t':
            i = Ins(op, target=struct.unpack_from('<i', d, p + 2)[0])
        elif fmt == '32x':
            i = Ins(op, a=struct.unpack_from('<H', d, p + 2)[0],
                    b=struct.unpack_from('<H', d, p + 4)[0])
        elif fmt == '31i':
            i = Ins(op, a=w1 >> 8, lit=struct.unpack_from('<i', d, p + 2)[0])
        elif fmt == '31c':
            i = Ins(op, a=w1 >> 8, idx=struct.unpack_from('<I', d, p + 2)[0])
        elif fmt == '35c':
            w2, w3 = struct.unpack_from('<HH', d, p + 2)
            cnt = w1 >> 12
            regs = [w3 & 0xF, w3 >> 4 & 0xF, w3 >> 8 & 0xF, w3 >> 12]
            if cnt == 5:
                regs.append(w1 >> 8 & 0xF)
            i = Ins(op, regs=regs[:cnt], idx=w2)
        elif fmt == '3rc':
            w2, w3 = struct.unpack_from('<HH', d, p + 2)
            i = Ins(op, idx=w2, start=w3, regs=list(range(w3, w3 + (w1 >> 8))))
        elif fmt == '51l':
            i = Ins(op, a=w1 >> 8, lit=struct.unpack_from('<q', d, p + 2)[0])
        elif fmt == '45cc':
            w2, w3, w4 = struct.unpack_from('<HHH', d, p + 2)
            cnt = w1 >> 12
            regs = [w3 & 0xF, w3 >> 4 & 0xF, w3 >> 8 & 0xF, w3 >> 12]
            if cnt == 5:
                regs.append(w1 >> 8 & 0xF)
            i = Ins(op, regs=regs[:cnt], idx=w2, proto=w4)
        elif fmt == '4rcc':
            w2, w3, w4 = struct.unpack_from('<HHH', d, p + 2)
            i = Ins(op, idx=w2, start=w3, regs=list(range(w3, w3 + (w1 >> 8))), proto=w4)
        else:
            raise ValueError(fmt)
        ins.append(i)
        p += nm * 2
    assert p == end
    return ins, offs


class CodeItem(object):
    def __init__(self, registers_size, ins_size, outs_size, insns, tries=None,
                 handlers=None, debug_info_off=0, raw_units=None):
        self.registers_size = registers_size
        self.ins_size = ins_size
        self.outs_size = outs_size
        self.insns = insns                 # list[Ins]
        self.tries = tries or []           # [(start_idx, end_idx, handler_idx)]
        self.handlers = handlers or []     # [{'type_idx':.., 'addr_idx':..}] or {'catch_all':idx}
        self.debug_info_off = debug_info_off
        self.raw_units = raw_units

    def unit_len(self):
        return sum(i.size for i in self.insns)


def encode_ins(i, cur_unit, ins_index_to_target_unit):
    """Encode one Ins into code units (may be a placeholder)."""
    if i.raw is not None:
        return list(i.raw)
    op = i.op
    fmt = FMT[op]
    if fmt == '10x':
        return [op]
    if fmt == '12x':
        return [op | (i.a << 8) | (i.b << 12)]
    if fmt == '11n':
        lit = i.lit & 0xF
        return [op | (i.a << 8) | (lit << 12)]
    if fmt == '11x':
        return [op | (i.a << 8)]
    if fmt == '10t':
        tgt = ins_index_to_target_unit(i.target)
        rel = tgt - cur_unit
        assert -128 <= rel <= 127, rel
        return [op | ((rel & 0xFF) << 8)]
    if fmt == '21t':
        tgt = ins_index_to_target_unit(i.target)
        return [op | (i.a << 8), (tgt - cur_unit) & 0xFFFF]
    if fmt == '20t':
        tgt = ins_index_to_target_unit(i.target)
        return [op, (tgt - cur_unit) & 0xFFFF]
    if fmt == '30t':
        tgt = ins_index_to_target_unit(i.target)
        v = tgt - cur_unit
        return [op, v & 0xFFFF, (v >> 16) & 0xFFFF]
    if fmt == '22x':
        return [op | (i.a << 8), i.b & 0xFFFF]
    if fmt == '32x':
        return [op, i.a & 0xFFFF, i.b & 0xFFFF]
    if fmt == '21s':
        return [op | (i.a << 8), i.lit & 0xFFFF]
    if fmt == '21h':
        return [op | (i.a << 8), i.lit & 0xFFFF]
    if fmt == '21c':
        return [op | (i.a << 8), i.idx & 0xFFFF]
    if fmt == '31c':
        return [op | (i.a << 8), i.idx & 0xFFFF, (i.idx >> 16) & 0xFFFF]
    if fmt == '23x':
        return [op | (i.a << 8), (i.b & 0xFF) | ((i.c & 0xFF) << 8)]
    if fmt == '22b':
        return [op | (i.a << 8), (i.b & 0xFF) | ((i.lit & 0xFF) << 8)]
    if fmt == '22s':
        return [op | (i.a << 8) | (i.b << 12), i.lit & 0xFFFF]
    if fmt == '22t':
        tgt = ins_index_to_target_unit(i.target)
        return [op | (i.a << 8) | (i.b << 12), (tgt - cur_unit) & 0xFFFF]
    if fmt == '22c':
        return [op | (i.a << 8) | (i.b << 12), i.idx & 0xFFFF]
    if fmt == '31i':
        v = i.lit & 0xFFFFFFFF
        return [op | (i.a << 8), v & 0xFFFF, (v >> 16) & 0xFFFF]
    if fmt == '31t':
        tgt = ins_index_to_target_unit(i.target)
        v = (tgt - cur_unit) & 0xFFFFFFFF
        return [op | (i.a << 8), v & 0xFFFF, (v >> 16) & 0xFFFF]
    if fmt == '35c':
        regs = list(i.regs) + [0] * (5 - len(i.regs))
        w1 = op | (len(i.regs) << 12) | (regs[4] << 8)
        w3 = regs[0] | (regs[1] << 4) | (regs[2] << 8) | (regs[3] << 12)
        return [w1, i.idx & 0xFFFF, w3]
    if fmt == '3rc':
        regs = i.regs if i.regs else list(range(i.start, i.start + i.a))
        return [op | (len(regs) << 8), i.idx & 0xFFFF, regs[0] & 0xFFFF]
    if fmt == '51l':
        v = i.lit & 0xFFFFFFFFFFFFFFFF
        return [op | (i.a << 8), v & 0xFFFF, (v >> 16) & 0xFFFF,
                (v >> 32) & 0xFFFF, (v >> 48) & 0xFFFF]
    if fmt == '45cc':
        regs = list(i.regs) + [0] * (5 - len(i.regs))
        w1 = op | (len(i.regs) << 12) | (regs[4] << 8)
        w3 = regs[0] | (regs[1] << 4) | (regs[2] << 8) | (regs[3] << 12)
        return [w1, i.idx & 0xFFFF, w3, i.proto & 0xFFFF]
    if fmt == '4rcc':
        regs = i.regs if i.regs else list(range(i.start, i.start + i.a))
        return [op | (len(regs) << 8), i.idx & 0xFFFF, regs[0] & 0xFFFF, i.proto & 0xFFFF]
    raise ValueError(fmt)


def encode_code(ci):
    """CodeItem -> bytes (tries/handlers converted back to unit addresses)."""
    starts = []
    u = 0
    for i in ci.insns:
        starts.append(u)
        u += i.size
    words = []
    cur = 0
    for i in ci.insns:
        words.extend(encode_ins(i, cur, lambda t: t))
        cur += i.size
    assert cur == len(words)
    body = bytearray()
    body += struct.pack('<HHHHII', ci.registers_size, ci.ins_size, ci.outs_size,
                        len(ci.tries), ci.debug_info_off, len(words))
    for w in words:
        body += struct.pack('<H', w & 0xFFFF)
    if ci.tries and len(words) % 2:
        body += b'\x00\x00'
    if ci.tries:
        hlist = bytearray()
        hoff = []
        hlist += uleb(len(ci.handlers))
        base = len(hlist)
        for h in ci.handlers:
            hoff.append(base + len(hlist) - base)
            typed = [(t, a) for (t, a) in h if t is not None]
            call = [a for (t, a) in h if t is None]
            hlist += sleb(len(typed))
            for t, a in typed:
                hlist += uleb(t) + uleb(starts[a])
            if call:
                hlist += uleb(starts[call[0]])
        for (s, e, hi) in ci.tries:
            body += struct.pack('<IHH', starts[s], starts[e] - starts[s], hoff[hi])
        body += hlist
    return bytes(body)


# ---------------------------------------------------------------- encoded_value

def parse_encoded_value(d, o):
    start = o
    b = d[o]
    vtype = b & 0x1F
    o += 1
    if vtype == 0x1C:
        _, o = parse_encoded_array(d, o)
    elif vtype == 0x1D:
        _, o = parse_encoded_annotation(d, o)
    elif vtype in (0x1E, 0x1F):
        pass
    else:
        o += (b >> 5) + 1
    return bytes(d[start:o]), o


def parse_encoded_array(d, o):
    start = o
    n, o = uleb_read(d, o)
    for _ in range(n):
        _, o = parse_encoded_value(d, o)
    return bytes(d[start:o]), o


def parse_encoded_annotation(d, o):
    start = o
    _, o = uleb_read(d, o)
    n, o = uleb_read(d, o)
    for _ in range(n):
        _, o = uleb_read(d, o)
        _, o = parse_encoded_value(d, o)
    return bytes(d[start:o]), o


# ---------------------------------------------------------------- code item

def parse_code(d, off):
    rs, ins, outs, tries_size, dbg, insns_size = struct.unpack_from('<HHHHII', d, off)
    insns, _ = decode(d, off + 16, insns_size)
    units, u = [], 0
    for i in insns:
        units.append(u)
        u += i.size
    idx_of = {unit: k for k, unit in enumerate(units)}
    tries, handlers = [], []
    if tries_size:
        p = off + 16 + insns_size * 2
        if insns_size % 2:
            p += 2
        raw = [struct.unpack_from('<IHH', d, p + 8 * k) for k in range(tries_size)]
        list_off = p + 8 * tries_size
        n, q = uleb_read(d, list_off)
        hoff_of = []
        for _ in range(n):
            hoff_of.append(q - list_off)
            cnt, q = sleb_read(d, q)
            pairs = []
            for _ in range(abs(cnt)):
                ti, q = uleb_read(d, q)
                addr, q = uleb_read(d, q)
                pairs.append((ti, addr))
            if cnt <= 0:
                addr, q = uleb_read(d, q)
                pairs.append((None, addr))
            handlers.append(pairs)

        def to_idx(addr):
            if addr not in idx_of:
                raise ValueError('try/handler address not on insn boundary: %d' % addr)
            return idx_of[addr]

        hidx = {o: k for k, o in enumerate(hoff_of)}
        tries = [(to_idx(s), to_idx(s + cnt), hidx[hoff]) for (s, cnt, hoff) in raw]
        handlers = [[(t, to_idx(a)) for (t, a) in h] for h in handlers]
    ci = CodeItem(rs, ins, outs, insns, tries, handlers, 0)
    ci.raw_off = off
    end = off + 16 + insns_size * 2
    if tries_size:
        if insns_size % 2:
            end += 2
        end += 8 * tries_size
        if 'q' in locals():
            end = q
    ci.raw_core = bytes(d[off:end])
    while end % 4:
        end += 1
    ci.raw_full = bytes(d[off:end])
    return ci


# ---------------------------------------------------------------- model

class Proto(object):
    __slots__ = ('shorty', 'ret', 'params')

    def __init__(self, shorty, ret, params):
        self.shorty = shorty
        self.ret = ret
        self.params = list(params)

    def key(self):
        return (self.shorty, self.ret, tuple(self.params))

    def __eq__(self, o):
        return isinstance(o, Proto) and self.key() == o.key()

    def __hash__(self):
        return hash(self.key())


class Dex(object):
    """Parsed dex. Indices in a Dex are the *original* ones."""

    def __init__(self, data):
        d = bytes(data)
        self.raw = d
        u = lambda o: struct.unpack_from('<I', d, o)[0]
        assert d[:8] == b'dex\n038\x00', d[:8]
        n_str, o_str = u(0x38), u(0x3C)
        n_typ, o_typ = u(0x40), u(0x44)
        n_pro, o_pro = u(0x48), u(0x4C)
        n_fld, o_fld = u(0x50), u(0x54)
        n_mth, o_mth = u(0x58), u(0x5C)
        n_cls, o_cls = u(0x60), u(0x64)
        self.strings = []
        for i in range(n_str):
            off = u(o_str + 4 * i)
            _ln, p = uleb_read(d, off)
            end = d.index(b'\x00', p)
            self.strings.append(d[p:end].decode('utf-8'))
        self.types = [self.strings[u(o_typ + 4 * i)] for i in range(n_typ)]
        self.protos = []
        for i in range(n_pro):
            base = o_pro + 12 * i
            shorty = self.strings[u(base)]
            ret = u(base + 4)
            poff = u(base + 8)
            params = []
            if poff:
                params = [struct.unpack_from('<H', d, poff + 4 + 2 * k)[0]
                          for k in range(u(poff))]
            self.protos.append(Proto(shorty, ret, params))
        self.fields = []
        for i in range(n_fld):
            base = o_fld + 8 * i
            w = u(base)
            self.fields.append((w & 0xFFFF, (w >> 16) & 0xFFFF, u(base + 4)))
        self.methods = []
        for i in range(n_mth):
            base = o_mth + 8 * i
            w = u(base)
            self.methods.append((w & 0xFFFF, (w >> 16) & 0xFFFF, u(base + 4)))
        self.classes = []
        for i in range(n_cls):
            base = o_cls + 32 * i
            cls_idx, access, super_idx = struct.unpack_from('<III', d, base)
            iface_off, source_idx, ann_off, cdata_off, sv_off = struct.unpack_from(
                '<IIIII', d, base + 12)
            ifaces = []
            if iface_off:
                ifaces = [struct.unpack_from('<H', d, iface_off + 4 + 2 * k)[0]
                          for k in range(u(iface_off))]
            cd = dict(static_fields=[], instance_fields=[], direct=[], virtual=[])
            if cdata_off:
                o = cdata_off
                sf, o = uleb_read(d, o)
                inf, o = uleb_read(d, o)
                dm, o = uleb_read(d, o)
                vm, o = uleb_read(d, o)
                fidx = 0
                for _ in range(sf):
                    diff, o = uleb_read(d, o)
                    acc, o = uleb_read(d, o)
                    fidx += diff
                    cd['static_fields'].append((fidx, acc))
                fidx = 0
                for _ in range(inf):
                    diff, o = uleb_read(d, o)
                    acc, o = uleb_read(d, o)
                    fidx += diff
                    cd['instance_fields'].append((fidx, acc))
                for name, cnt in (('direct', dm), ('virtual', vm)):
                    midx = 0
                    for _ in range(cnt):
                        diff, o = uleb_read(d, o)
                        acc, o = uleb_read(d, o)
                        code_off, o = uleb_read(d, o)
                        midx += diff
                        ci = parse_code(d, code_off) if code_off else None
                        cd[name].append([midx, acc, ci])
            sv = None
            if sv_off:
                sv, _ = parse_encoded_array(d, sv_off)
            self.classes.append(dict(class_idx=cls_idx, access=access,
                                     super_idx=super_idx, interfaces=ifaces,
                                     source_idx=source_idx, static_values=sv,
                                     data=cd))

    # ---------------- helpers
    def tstr(self, ti):
        return self.types[ti]

    def proto_str(self, pi):
        p = self.protos[pi]
        return '(%s)%s' % (''.join(self.types[t] for t in p.params), self.types[p.ret])

    def mstr(self, mi):
        cls, proto, name = self.methods[mi]
        return '%s->%s%s' % (self.types[cls], self.strings[name], self.proto_str(proto))

    def fstr(self, fi):
        cls, typ, name = self.fields[fi]
        return '%s->%s:%s' % (self.types[cls], self.strings[name], self.types[typ])

    def find_class(self, desc):
        for i, c in enumerate(self.classes):
            if self.types[c['class_idx']] == desc:
                return i
        return -1

    def find_method(self, cls_desc, name, proto_str=None):
        for mi, (cls, proto, nm) in enumerate(self.methods):
            if self.types[cls] == cls_desc and self.strings[nm] == name:
                if proto_str is None or self.proto_str(proto) == proto_str:
                    return mi
        return -1

    def find_type(self, desc):
        try:
            return self.types.index(desc)
        except ValueError:
            return -1

    def methods_of(self, cls_idx):
        out = []
        for i, c in enumerate(self.classes):
            if c['class_idx'] != cls_idx:
                continue
            for grp in ('direct', 'virtual'):
                for rec in c['data'][grp]:
                    out.append(rec[0])
        return out
