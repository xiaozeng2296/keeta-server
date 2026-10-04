"""Inspect A-payload routing and device collector ABI without a device/network.

The device-info VM runs original instructions until the shared serializer.
Only imports and an exact-RTTI dynamic_cast are supplied. No business data is
read: the collector object is synthetic and execution stops before cache reads.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.a9_provider_emulate import ProviderVM
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X8, UC_ARM64_REG_X30, UC_ARM64_REG_PC


class CollectorVM(ProviderVM):
    def _import(self, uc, address, size, data):
        if address - self.image.base == 0x30ed5d0:  # __dynamic_cast
            obj, source, target, hint = [uc.reg_read(r) for r in self.ARG_REGS[:4]]
            vtable = struct.unpack('<Q', uc.mem_read(obj, 8))[0]
            actual = struct.unpack('<Q', uc.mem_read(vtable - 8, 8))[0]
            if actual != target or hint != 0:
                raise RuntimeError('unsupported RTTI cast; refusing to guess')
            uc.reg_write(UC_ARM64_REG_X0, obj)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
            return
        return super()._import(uc, address, size, data)

    def bind_function_imports(self):
        # VM FFI calls imported function pointers directly. Resolve them to
        # existing Mach-O stubs, whose semantics ProviderVM already supplies.
        stubs = next(s for s in self.image.binary.sections if s.name == '__stubs')
        names = {}
        for address in range(stubs.virtual_address, stubs.virtual_address + stubs.size, 12):
            ins = list(self.image.cs.disasm(self.image.read(address-self.image.base, 12), address))
            if len(ins) == 3 and ins[0].mnemonic == 'adrp' and ins[1].mnemonic == 'ldr':
                got = ins[0].operands[1].imm + ins[1].operands[1].mem.disp
                name = self.imports.get(got)
                if name:
                    names[name] = address
        for binding in self.image.binary.bindings:
            if binding.has_symbol and binding.symbol.name in names:
                self.uc.mem_write(binding.address, struct.pack('<Q', names[binding.symbol.name]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("--out must not already exist")
    vm = CollectorVM(args.image)
    vm.bind_function_imports()
    obj, out = vm.SCRATCH + 0x9000, vm.SCRATCH + 0xa000
    vm.uc.mem_write(obj, struct.pack('<Q', vm.image.base + 0x405e970) + bytes(0x98))
    vm.uc.mem_write(out, bytes(24))
    calls = []

    def serializer(uc, address, size, data):
        ids, count = uc.reg_read(UC_ARM64_REG_X1), uc.reg_read(UC_ARM64_REG_X2)
        assert 0 <= count <= 600
        calls.append(dict(caller_rva=hex(uc.reg_read(UC_ARM64_REG_X30)-vm.image.base),
                          count=count, mode=uc.reg_read(UC_ARM64_REG_X3),
                          field_ids=list(struct.unpack('<'+'I'*count, uc.mem_read(ids, count*4)))))
        uc.reg_write(UC_ARM64_REG_PC, vm.STOP)

    entry = vm.image.base + 0x2fc948
    vm.uc.hook_add(UC_HOOK_CODE, serializer, begin=entry, end=entry)
    vm.uc.reg_write(UC_ARM64_REG_X8, out)
    vm.call(0x2e996c, obj)
    assert len(calls) == 1 and calls[0]['field_ids'] == list(range(600)) and calls[0]['mode'] == 1
    im = vm.image
    arrays = {name: dict(rva=hex(rva), count=n, field_ids=list(struct.unpack('<'+'I'*n, im.read(rva, n*4))))
              for name, rva, n in [('sign_full', 0x330c250, 92), ('sign_privacy', 0x330c3c0, 12),
                                  ('fama_mode3', 0x330c3f0, 24)]}
    xid_raw = bytes(b ^ ((0x66+3*i)&255) for i, b in enumerate(im.read(0x333f260, 0x12e)))
    arrays['info_default'] = dict(encoded_rva='0x333f260', seed=0x66,
                                  field_ids=[int(x) for x in xid_raw.decode().split('|')])
    arrays['info_default']['count'] = len(arrays['info_default']['field_ids'])
    route_targets = [0x31f2f0 + x for x in struct.unpack('<6i', im.read(0x31f2f0, 24))]
    report = dict(image_sha256=hashlib.sha256(im.data).hexdigest(),
                  device_vm_entry='0x2e996c', stopped_at='0x2fc948',
                  substitutions='function imports resolved to existing stubs; exact RTTI cast only; synthetic object',
                  device_serializer_calls=calls, static_arrays=arrays,
                  route_enum_switch={str(i+1):hex(x) for i,x in enumerate(route_targets)},
                  confirmed_routes={'1':'/fingerprint/v1/info/report', '2':'/v5/sign',
                                    '3':'/v5/device-info', '6':'/fingerprint/v1/app/bio/info/report'},
                  imports=sorted({x['name'] for x in vm.events}))
    dest = args.out
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print('PASS: original device-info VM selects 0..599, mode=1 at shared serializer')
    print('Static arrays:', {k:v['count'] for k,v in arrays.items()})
    print('Report:', dest)


if __name__ == '__main__':
    main()
