"""Offline exploratory runner for the provider VM using synthetic inputs only.

The original image is unchanged. Imported allocation/string/time services are
implemented locally; unsupported imports stop the run instead of faking success.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from unicorn import UC_HOOK_CODE, UcError
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X30
from tools.a9_native_verify import NativeTwofish
from mtgsig.a9_codec import DEFAULT_SALT


class ProviderVM(NativeTwofish):
    def __init__(self, path):
        super().__init__(path)
        self.heap = 0x230000000
        self.uc.mem_map(self.heap, 0x1000000)
        self.heap_end = self.heap + 0x1000000
        self.imports = {b.address: b.symbol.name for b in self.image.binary.bindings if b.has_symbol}
        self.stub_names = {}
        self.events = []
        self.allocations = {}
        stubs = next(s for s in self.image.binary.sections if s.name == '__stubs')
        self.uc.hook_add(UC_HOOK_CODE, self._import,
                         begin=stubs.virtual_address, end=stubs.virtual_address + stubs.size - 1)

    def alloc(self, size):
        address = self.heap
        self.heap += (max(size, 1) + 15) & ~15
        if self.heap >= self.heap_end:
            raise RuntimeError('synthetic heap exhausted')
        self.allocations[address] = size
        return address

    def cstring(self, address, limit=65536):
        raw = bytearray()
        while len(raw) < limit:
            b = self.uc.mem_read(address + len(raw), 1)[0]
            if not b:
                return bytes(raw)
            raw.append(b)
        raise RuntimeError('unterminated synthetic string')

    def _import(self, uc, address, size, user_data):
        name = self.stub_names.get(address)
        if name is None:
            ins = list(self.image.cs.disasm(self.image.read(address - self.image.base, 12), address))
            if len(ins) != 3 or ins[0].mnemonic != 'adrp' or ins[1].mnemonic != 'ldr':
                raise RuntimeError(f'unexpected import entry {address-self.image.base:#x}')
            got = ins[0].operands[1].imm + ins[1].operands[1].mem.disp
            name = self.imports.get(got, f'unknown import at {got:#x}')
            self.stub_names[address] = name
        a = [uc.reg_read(r) for r in self.ARG_REGS]
        self.events.append(dict(name=name, callsite=hex(uc.reg_read(UC_ARM64_REG_X30)-self.image.base)))
        if name == '__ZNSt3__111__call_onceERVmPvPFvS2_E':
            if bytes(uc.mem_read(a[0], 8)) != b'\xff' * 8:
                uc.mem_write(a[0], b'\xff' * 8)
                uc.reg_write(UC_ARM64_REG_X0, a[1])
                uc.reg_write(UC_ARM64_REG_PC, a[2])
                return
            value = 0
        elif name in ('_malloc', '__Znwm', '__Znam'):
            value = self.alloc(a[0])
        elif name == '_calloc':
            value = self.alloc(a[0] * a[1])
        elif name == '_realloc':
            value = self.alloc(a[1])
            if a[0]:
                uc.mem_write(value, bytes(uc.mem_read(a[0], min(self.allocations.get(a[0], 0), a[1]))))
        elif name in ('_free', '__ZdlPv', '__ZdaPv', '_srand', '_srandom',
                      '__ZNSt3__15mutex4lockEv', '__ZNSt3__15mutex6unlockEv'):
            value = 0
        elif name in ('_memcpy', '_memmove'):
            uc.mem_write(a[0], bytes(uc.mem_read(a[1], a[2])))
            value = a[0]
        elif name == '_bzero':
            uc.mem_write(a[0], bytes(a[1]))
            value = 0
        elif name == '_memset':
            uc.mem_write(a[0], bytes([a[1] & 255]) * a[2])
            value = a[0]
        elif name == '_strlen':
            value = len(self.cstring(a[0]))
        elif name in ('_strcmp', '_strncmp', '_memcmp'):
            if name == '_memcmp':
                x, y = bytes(uc.mem_read(a[0], a[2])), bytes(uc.mem_read(a[1], a[2]))
            else:
                x, y = self.cstring(a[0]), self.cstring(a[1])
                if name == '_strncmp':
                    x, y = x[:a[2]], y[:a[2]]
            value = (x > y) - (x < y)
        elif name in ('_rand', '_random'):
            value = 123456789
        elif name == '_time':
            value = 1700000000
            if a[0]:
                uc.mem_write(a[0], struct.pack('<Q', value))
        else:
            raise RuntimeError(f'unsupported import {name} at RVA {address-self.image.base:#x}')
        uc.reg_write(UC_ARM64_REG_X0, value & ((1 << 64)-1))
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

    def run(self, config, a1='00000000-1111-2222-3333-444444444444', entry=0x30C454):
        provider, identifier, configptr = self.SCRATCH + 0x9000, self.SCRATCH + 0xA000, self.SCRATCH + 0xB000
        self.uc.mem_write(provider, bytes(96))
        self.uc.mem_write(provider + 72, DEFAULT_SALT)
        self.uc.mem_write(provider + 88, struct.pack('<I', 20))
        self.uc.mem_write(identifier, a1.encode() + b'\0')
        self.uc.mem_write(configptr, config.encode() + b'\0')
        args = (provider, identifier, configptr) if entry == 0x30C454 else (provider, configptr)
        for reg, value in zip(self.ARG_REGS, args + (0,) * (8 - len(args))):
            self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM64_REG_SP, self.STACK + 0xFF000)
        self.uc.reg_write(UC_ARM64_REG_X30, self.STOP)
        self.uc.emu_start(self.image.base + entry, self.STOP, count=20_000_000)
        if self.uc.reg_read(UC_ARM64_REG_PC) != self.STOP:
            raise RuntimeError('instruction budget exceeded')
        return dict(a1=a1, config=config, object=bytes(self.uc.mem_read(provider, 96)).hex(),
                    return_value=self.uc.reg_read(UC_ARM64_REG_X0), events=self.events)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--config', default='')
    p.add_argument('--parser-only', action='store_true')
    p.add_argument('--out', type=Path)
    args = p.parse_args()
    if args.out and args.out.exists():
        p.error("--out must not already exist")
    vm = ProviderVM(args.image)
    try:
        result = vm.run(args.config, entry=0x30C490 if args.parser_only else 0x30C454)
    except Exception:
        print('PC', hex(vm.uc.reg_read(UC_ARM64_REG_PC)), 'recent imports', vm.events[-8:])
        raise
    result['image_sha256'] = hashlib.sha256(vm.image.data).hexdigest()
    result['limitations'] = 'Exploratory VM; unsupported imports fail; not complete provider validation.'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('x') as stream:
            json.dump(result, stream, indent=2)
    print('completed', 'imports', len(result['events']), 'return', result['return_value'])


if __name__ == '__main__':
    main()
