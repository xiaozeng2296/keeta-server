#!/usr/bin/env python3
"""Read-only ObjC metadata and outlined ARM64 listings for Keeta login."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.a9_unflatten import Image
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG


class ObjCImage(Image):
    def __init__(self, path):
        super().__init__(path)
        self.sections = [(s.virtual_address-self.base, s.virtual_address-self.base+s.size, s.name)
                         for s in self.binary.sections]
        self.classes = {}
        self.methods = {}
        self.stub_names = {}
        sec = self.binary.get_section('__objc_classlist')
        for offset in range(sec.virtual_address-self.base, sec.virtual_address-self.base+sec.size, 8):
            cls = self.ptr(offset)
            if not cls:
                continue
            ro = self.ptr(cls + 32) & ~7
            name = self.cstring(self.ptr(ro + 24))
            self.classes[cls] = name
            for sign, obj in [('-', cls), ('+', self.ptr(cls))]:
                info = self.ptr(obj+32) & ~7
                table = self.ptr(info+32)
                if not table:
                    continue
                flags, count = struct.unpack('<II', self.read(table, 8))
                stride = flags & 0xffff
                if flags & 0x80000000:
                    continue
                for i in range(count):
                    at = table+8+i*stride
                    sel, imp = self.ptr(at), self.ptr(at+16)
                    self.methods.setdefault(imp, []).append(f'{sign}[{name} {self.cstring(sel)}]')

    def ptr(self, rva):
        value = struct.unpack('<Q', self.read(rva, 8))[0]
        return value-self.base if value >= self.base else value

    def cstring(self, rva):
        try:
            raw = self.read(rva, 768).split(b'\0', 1)[0]
            return raw.decode('utf-8')
        except (ValueError, UnicodeError):
            return ''

    def section(self, rva):
        return next((name for start, end, name in self.sections if start <= rva < end), '')

    def describe(self, rva):
        try:
            sec = self.section(rva)
            if sec == '__cfstring':
                flags = self.u32(rva+8)
                data, count = self.ptr(rva+16), self.ptr(rva+24)
                if flags & 0x10:
                    return 'CF ' + repr(self.read(data, count*2).decode('utf-16le'))
                return 'CF ' + repr(self.read(data, count).decode('utf-8'))
            if sec in ('__objc_selrefs', '__objc_classrefs', '__objc_superrefs'):
                pointer = self.ptr(rva)
                return self.classes.get(pointer) or self.cstring(pointer)
            if sec in ('__cstring', '__objc_methname', '__objc_classname'):
                return repr(self.cstring(rva))
            if rva in self.methods:
                return ' | '.join(self.methods[rva])
        except (ValueError, UnicodeError, OverflowError):
            pass
        return ''

    def stub(self, rva):
        if rva in self.stub_names:
            return self.stub_names[rva]
        name = self.describe(rva)
        if self.section(rva) == '__objc_stubs':
            regs = {}
            for i in self.cs.disasm(self.read(rva, 24), rva):
                ops = i.operands
                if i.mnemonic == 'adrp':
                    regs[ops[0].reg] = ops[1].imm
                elif i.mnemonic == 'ldr' and ops[1].type == ARM64_OP_MEM:
                    mem = ops[1].mem
                    if mem.base in regs:
                        val = self.describe(regs[mem.base]+mem.disp)
                        if i.reg_name(ops[0].reg) == 'x1' and val:
                            name = 'objc_msgSend: ' + val
                            break
        self.stub_names[rva] = name
        return name

    def render(self, rva, depth=0, seen=None):
        seen = set() if seen is None else seen
        start, end = self.bounds(rva)
        seen = seen | {start}
        lines = [f'{"  "*depth}; {start:#x}..{end:#x} {self.stub(start)}']
        regs = {}
        for i in self.cs.disasm(self.read(start, end-start), start):
            if i.id == 0:  # Capstone skipdata records have no operand detail.
                regs.clear()
                lines.append(f'{"  "*depth}{i.address:08x}: {i.mnemonic} {i.op_str}')
                continue
            ops, note = i.operands, ''
            if not ops:
                lines.append(f'{"  "*depth}{i.address:08x}: {i.mnemonic}')
                continue
            if i.mnemonic == 'adrp':
                regs[ops[0].reg] = ops[1].imm
            elif i.mnemonic == 'add' and len(ops) == 3 and ops[2].type == ARM64_OP_IMM:
                if ops[1].reg in regs:
                    regs[ops[0].reg] = regs[ops[1].reg]+ops[2].imm
                    note = self.describe(regs[ops[0].reg])
            elif i.mnemonic in ('ldr', 'ldur') and ops[1].type == ARM64_OP_MEM:
                mem = ops[1].mem
                if mem.base in regs:
                    note = self.describe(regs[mem.base]+mem.disp)
                regs.pop(ops[0].reg, None)
            elif i.mnemonic in ('mov', 'movz', 'movk'):
                regs.pop(ops[0].reg, None)
            target = None
            if i.mnemonic in ('bl', 'b') and ops[0].type == ARM64_OP_IMM:
                target = ops[0].imm
                note = self.stub(target)
            lines.append(f'{"  "*depth}{i.address:08x}: {i.mnemonic} {i.op_str}' + (f' ; {note}' if note else ''))
            if target is not None and not note and self.section(target) == '__text' and depth < 3:
                lo, hi = self.bounds(target)
                if target == lo and hi-lo <= 192 and lo not in seen:
                    lines.extend(self.render(target, depth+1, seen))
        return lines


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('rva', nargs='*', type=lambda x:int(x,0))
    p.add_argument('--class-filter', default='SOA(?:EmailVerify|EmailRegister|UserRiskCheck)')
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    if a.out.exists():
        p.error("--out must be a new directory")
    im = ObjCImage(a.image)
    import re
    chosen = {hex(k):v for k,v in im.methods.items() if any(re.search(a.class_filter,s) for s in v)}
    a.out.mkdir(parents=True, exist_ok=False)
    (a.out/'methods.json').write_text(json.dumps({'binary_sha256':hashlib.sha256(im.data).hexdigest(),
                                               'methods':chosen},indent=2)+'\n')
    for rva in a.rva:
        (a.out/f'{rva:08x}.asm').write_text('\n'.join(im.render(rva))+'\n')
    print('methods',len(chosen),'listings',len(a.rva),'out',a.out)


if __name__ == '__main__':
    main()
