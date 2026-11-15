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
    hb = bytearray()
    hoff = []
    for h in ci.handlers:
        hoff.append(len(hb))
        typed = [(t, a) for (t, a) in h if t is not None]
        call = [a for (t, a) in h if t is None]
        hb += sleb(len(typed))
        for t, a in typed:
            hb += uleb(t) + uleb(starts[a] if ci.tries else a)
        if call:
            hb += uleb(starts[call[0]] if ci.tries else call[0])
    body = bytearray()
    body += struct.pack('<HHHHII', ci.registers_size, ci.ins_size, ci.outs_size,
                        len(ci.tries), ci.debug_info_off, len(words))
    for w in words:
        body += struct.pack('<H', w & 0xFFFF)
    if ci.tries and len(words) % 2:
        body += b'\x00\x00'
    if ci.tries:
        body += struct.pack('<I', len(hb))
        body += hb
        for (s, e, hi) in ci.tries:
            body += struct.pack('<IHH', starts[s], starts[e] - starts[s], hoff[hi])
    return bytes(body)


# ---------------------------------------------------------------- encoded_value

def parse_encoded_value(d, o):
    start = o
    arg = d[o] & 0x1F
    o += 1
    if arg == 0x1C:
        _, o = parse_encoded_array(d, o)
    elif arg == 0x1D:
        _, o = parse_encoded_annotation(d, o)
    elif arg in (0x1E, 0x1F):
        pass
    else:
        o += ((arg & 0xE0) >> 5) + 1
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
        for _ in range(n):
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

        tries = [(to_idx(s), to_idx(s + cnt), hoff) for (s, cnt, hoff) in raw]
        handlers = [[(t, to_idx(a)) for (t, a) in h] for h in handlers]
    return CodeItem(rs, ins, outs, insns, tries, handlers, 0)


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
                params = [u(poff + 4 * k) for k in range(u(poff))]
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
                ifaces = [u(iface_off + 4 * k) for k in range(u(iface_off))]
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
