"""Verify m320 against original ARM64/VM code, entirely offline.

Only runtime configuration inputs and imported library/ObjC services are supplied.
HMAC, AES, sorting and final byte mixing execute unmodified image instructions.
"""
import argparse
import json
import struct
import sys
import zlib
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.verify_registration_collectors import CollectorVM
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP


class ChecksumVM(CollectorVM):
    def get_string(self, obj):
        tag = self.uc.mem_read(obj + 23, 1)[0]
        if tag & 128:
            p, n = struct.unpack('<QQ', self.uc.mem_read(obj, 16))
            return bytes(self.uc.mem_read(p, n))
        return bytes(self.uc.mem_read(obj, tag))

    def set_string(self, obj, data):
        if len(data) < 23:
            self.uc.mem_write(obj, data + bytes(23-len(data)) + bytes([len(data)]))
        else:
            p = self.alloc(len(data)+1)
            self.uc.mem_write(p, data+b'\0')
            self.uc.mem_write(obj, struct.pack('<QQQ', p, len(data), (1 << 63) | (len(data)+1)))

    def _import(self, uc, address, size, data):
        if address-self.image.base == 0x30ef754:
            dst, fmt = [uc.reg_read(r) for r in self.ARG_REGS[:2]]
            form = self.cstring(fmt)
            val = struct.unpack('<Q',uc.mem_read(uc.reg_read(UC_ARM64_REG_SP),8))[0]
            if form not in (b'%u', b'%lu', b'%d', b'%lld'):raise RuntimeError(f'unsupported sprintf {form!r}')
            raw = str(val if form==b'%lld' else val & 0xffffffff).encode()
            uc.mem_write(dst,raw+b'\0')
            uc.reg_write(UC_ARM64_REG_X0,len(raw))
            uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
            return
        if address-self.image.base == 0x30ed804:
            seed, src, n = [uc.reg_read(r) for r in self.ARG_REGS[:3]]
            raw = bytes(uc.mem_read(src,n)) if src else b''
            if src:self.last_adler_input = raw
            result = zlib.adler32(raw, seed & 0xffffffff) if src else 1
            uc.reg_write(UC_ARM64_REG_X0, result)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
            return
        if address-self.image.base in (0x30ecd9c, 0x30ecde4):
            obj, src = [uc.reg_read(r) for r in self.ARG_REGS[:2]]
            self.set_string(obj, self.get_string(src))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
            return
        if address-self.image.base in (0x30eefb0, 0x30eef74, 0x30eef98, 0x30ecdcc):
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
            return
        if address-self.image.base == 0x30eef08:
            obj, sel = [uc.reg_read(r) for r in self.ARG_REGS[:2]]
            name = self.cstring(sel)
            if name == b'defaultCStringEncoding':
                result = 4
            elif name in (b'UTF8String', b'cStringUsingEncoding:') and obj == self.appkey_obj:
                result = self.appkey_bytes
            else:
                raise RuntimeError(f'unsupported ObjC selector {name!r}')
            uc.reg_write(UC_ARM64_REG_X0, result)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
            return
        if address-self.image.base == 0x30eccd0:
            obj, src, n = [uc.reg_read(r) for r in self.ARG_REGS[:3]]
            content = bytes(uc.mem_read(src, n))
            self.append_inputs.append(content)
            self.set_string(obj, self.get_string(obj)+content)
            uc.reg_write(UC_ARM64_REG_X0, obj)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
            return
        return super()._import(uc, address, size, data)

    def checksum(self, fields):
        return self.checksum_pairs(list(fields.items()))

    def checksum_pairs(self, pairs):
        self.append_inputs = []
        self.call(0x2dee3c)
        root = self.uc.reg_read(UC_ARM64_REG_X0)
        for key, value in pairs:
            kp, vp = self.alloc(len(key.encode())+1), self.alloc(len(value.encode())+1)
            self.uc.mem_write(kp, key.encode()+b'\0')
            self.uc.mem_write(vp, value.encode()+b'\0')
            self.call(0x2dec2c, root, kp, vp)
        out = self.alloc(24)
        self.uc.mem_write(out, bytes(24))
        self.uc.reg_write(UC_ARM64_REG_X8, out)
        for register,value in zip(self.ARG_REGS,(root,)+(0,)*7):self.uc.reg_write(register,value)
        self.uc.reg_write(UC_ARM64_REG_SP,self.STACK+0xff000)
        self.uc.reg_write(UC_ARM64_REG_X30,self.STOP)
        self.uc.emu_start(self.image.base+0x2fc910,self.STOP,count=20_000_000)
        if self.uc.reg_read(UC_ARM64_REG_PC)!=self.STOP:raise RuntimeError('checksum VM instruction budget exceeded')
        return self.get_string(out)



def make_vm(context, *, image_path, guard_fault=False):
    vm = ChecksumVM(image_path)
    vm.bind_function_imports()
    app = context['appkey'].encode()
    a0 = context['a0'].encode()
    vm.appkey_obj, vm.appkey_bytes = vm.alloc(8), vm.alloc(len(app)+1)
    vm.uc.mem_write(vm.appkey_bytes, app+b'\0')
    def appkey(uc, address, size, data):
        uc.reg_write(UC_ARM64_REG_X0, vm.appkey_obj)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
    vm.uc.hook_add(UC_HOOK_CODE, appkey, begin=vm.image.base+0x2fe2d8, end=vm.image.base+0x2fe2d8)
    def config(uc, address, size, data):
        name = vm.get_string(uc.reg_read(UC_ARM64_REG_X0))
        if name != b'a0':raise RuntimeError(f'unexpected SDK config lookup {name!r}')
        vm.set_string(uc.reg_read(UC_ARM64_REG_X8), a0)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
    vm.uc.hook_add(UC_HOOK_CODE, config, begin=vm.image.base+0x316ca0, end=vm.image.base+0x316ca0)
    def ready(uc, address, size, data):
        uc.reg_write(UC_ARM64_REG_X0,int(guard_fault))
        uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
    vm.uc.hook_add(UC_HOOK_CODE,ready,begin=vm.image.base+0x316b5c,end=vm.image.base+0x316b5c)
    clock_obj=vm.alloc(8)
    vm.uc.mem_write(clock_obj,struct.pack('<Q',context['launch_seconds']))
    vm.uc.mem_write(vm.image.base+0x4d3a170,b'\xff'*8)
    vm.uc.mem_write(vm.image.base+0x4d3a178,struct.pack('<Q',clock_obj))
    vm.uc.mem_write(vm.image.base+0x4d3a1b0,b'\xff'*8)
    vm.uc.mem_write(vm.image.base+0x4d3a1ac,bytes([context['sdk_flag']]))
    vm.uc.mem_write(vm.image.base+0x4e45570,struct.pack('<i',context['cipher_flag']))
    provider=vm.alloc(96)
    vm.uc.mem_write(provider,bytes.fromhex(context['provider_mask_hex'])+bytes(80))
    vm.uc.mem_write(vm.image.base+0x4d3a890,b'\xff'*8)
    vm.uc.mem_write(vm.image.base+0x4d3a898,struct.pack('<Q',provider))
    names={b.symbol.name:b.address for b in vm.image.binary.bindings if b.has_symbol}
    for off,name in [(0x4cb1cb0,'_malloc'),(0x4cb1cb8,'_free'),(0x4cb1cc0,'_realloc')]:
        vm.uc.mem_write(vm.image.base+off,bytes(vm.uc.mem_read(names[name],8)))
    vm.ffi_calls=[]
    def ffi(uc,address,size,data):
        vm.ffi_calls.append(hex(uc.reg_read(UC_ARM64_REG_X9)-vm.image.base))
    vm.uc.hook_add(UC_HOOK_CODE,ffi,begin=vm.image.base+0x3ac048,end=vm.image.base+0x3ac048)
    return vm



def python_checksum(fields, context):
    from mtgsig.registration_checksum import compute_m320
    return compute_m320(fields, appkey=context['appkey'], version=context['a0'],
        sdk_flag=context['cipher_flag'], provider_mask=bytes.fromhex(context['provider_mask_hex']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True, help="New directory; never overwrites test fixtures")
    parser.add_argument("--evidence-dir", type=Path, help="Optional historical context/payload JSON files; read-only")
    args = parser.parse_args()
    if args.evidence_dir is not None and not args.evidence_dir.is_dir():
        parser.error("--evidence-dir must be an existing directory")
    args.out_dir.mkdir(parents=True, exist_ok=False)
    synthetic_context={'appkey':'00000000-1111-2222-3333-444444444444',
        'a0':'0123456789abcdef'*4, 'cipher_flag':186, 'sdk_flag':1,
        'launch_seconds':1700000000, 'provider_mask_hex':bytes(range(16)).hex()}
    cases=[('base',{'m1':'test','m153':'synthetic-device'},{}),
        ('odd',{'m1':'test!','m153':'synthetic-device'},{}),
        ('lexical',{'m2':'two','m11':'eleven','m1':'one'},{}),
        ('utf8',{'m1':'中文😀','m2':' ~ '},{}),
        ('empty',{'m1':''},{}),
        ('config_short',{'m1':'x'*63},{'a0':'2.5','cipher_flag':0,'sdk_flag':0}),
        ('config_long',{'m1':'x'*64},{'a0':'0123456789abcdef'*6,'cipher_flag':511}),
        ('mask_time',{'m1':'x'*65},{'provider_mask_hex':bytes(reversed(range(16))).hex(),
                               'launch_seconds':1900000001})]
    vectors=[]
    for name,fields,changes in cases:
        context={**synthetic_context,**changes}
        vm=make_vm(context, image_path=args.image)
        native=vm.checksum(fields).decode()
        expected=python_checksum(fields,context)
        assert native==expected, f'synthetic mismatch: {name}'
        vectors.append({'name':name,'fields':fields,'context':context,'native_m320':native})
    fixture=args.out_dir/'registration_m320_vectors.json'
    fixture.write_text(json.dumps({'image_sha256':hashlib.sha256(vm.image.data).hexdigest(),
        'source':'original 2fc910 VM and native crypto; external configuration/services supplied',
        'vectors':vectors},ensure_ascii=False,indent=2)+'\n')
    from mtgsig.registration_checksum import compute_m320_pairs
    pair_vectors = []
    for name, pairs in [
        ('duplicate_status', [('m307', ''), ('m307', '{}')]),
        ('old_checksum_is_material', [('m320', ''), ('m307', '{}')]),
        ('three_equal_keys', [('m307', 'a'), ('m307', 'b'), ('m307', 'c')]),
        ('interleaved_duplicates', [('m307', 'a'), ('m1', 'z'), ('m307', 'b'), ('m2', 'y'), ('m307', 'c')]),
        ('four_equal_keys', [('m307', 'a'), ('m307', 'b'), ('m307', 'c'), ('m307', 'd')]),
    ]:
        vm = make_vm(synthetic_context, image_path=args.image)
        native = vm.checksum_pairs(pairs).decode()
        calculated = compute_m320_pairs(pairs, appkey=synthetic_context['appkey'],
            version=synthetic_context['a0'], sdk_flag=synthetic_context['cipher_flag'],
            provider_mask=bytes.fromhex(synthetic_context['provider_mask_hex']))
        material = b''.join(vm.append_inputs[1::2]).decode()
        expected_material = ''.join(k+v for k,v in sorted(reversed(pairs), key=lambda pair: pair[0]))
        assert native == calculated and material == expected_material, name
        pair_vectors.append({'name': name, 'pairs': pairs, 'native_material': material,
                             'native_m320': native})
    (args.out_dir/'registration_m320_pairs_vectors.json').write_text(json.dumps({
        'image_sha256': hashlib.sha256(vm.image.data).hexdigest(),
        'source': 'original 2fc910 VM; cJSON duplicates retained, append material observed',
        'context': synthetic_context, 'vectors': pair_vectors}, indent=2)+'\n')
    private_results=[]
    private_skipped=[]
    current_context=None
    for filename in ('current_registration_context_02.json','current_registration_payloads_01.json'):
        if args.evidence_dir is None:
            continue
        path=args.evidence_dir/filename
        if not path.exists():continue
        source=json.loads(path.read_text())
        if 'checksum_context' in source:
            current_context=source['checksum_context']
            rows=source['payload_rows']
        else:
            if current_context is None:
                private_skipped.append({'source':filename,'reason':'matching checksum context unavailable'})
                continue
            rows=source['rows']
        for row in rows:
            fields=json.loads(row['prepared_text'])
            stored=fields.pop('m320')
            python_value=python_checksum(fields,current_context)
            vm=make_vm(current_context, image_path=args.image)
            native=vm.checksum(fields).decode()
            item={'source':filename,'name':row['name'],'fields':len(fields),
                'plaintext_sha256':hashlib.sha256(row['prepared_text'].encode()).hexdigest(),
                'python_matches_native':python_value==native,'native_matches_capture':native==stored,
                'python_matches_capture':python_value==stored}
            private_results.append(item)
            assert all(item[k] for k in ('python_matches_native','native_matches_capture','python_matches_capture')), item
    report={'image_sha256':hashlib.sha256(vm.image.data).hexdigest(),
        'entry_rva':'0x2fc910','synthetic_cases':len(vectors),'private_cases':private_results,
        'duplicate_key_native_cases': len(pair_vectors),
        'private_skipped':private_skipped,
        'substitutions':'Allocator/libc++/ObjC string services; supplied appkey, raw a0, counter, mask, launch time; healthy guard result 0'}
    reporting = (args.evidence_dir/'current_reporting_context_04.json') if args.evidence_dir else None
    if reporting is not None and reporting.exists():
        from mtgsig.registration_collector import prepared_pairs, device_mode1_plaintext
        from mtgsig.corpse_codec import encode_fields
        captured = json.loads(reporting.read_text())
        context = captured['checksum_context']
        options = dict(appkey=context['appkey'], version=context['a0'], sdk_flag=context['cipher_flag'],
                       provider_mask=bytes.fromhex(context['provider_mask_hex']))
        rows = {row['name']: row for row in captured['reporting_rows']}
        pairs = prepared_pairs(rows['device_info_mode0']['prepared_text'])
        vm = make_vm(context, image_path=args.image)
        native = vm.checksum_pairs(pairs[:-1]).decode()
        assert native == pairs[-1][1] == compute_m320_pairs(pairs[:-1], **options)
        filtered = device_mode1_plaintext(pairs, **options)
        native_mode1 = json.loads(rows['device_info_mode1']['prepared_text'])
        assert encode_fields(filtered) == native_mode1
        report['full_device_info'] = dict(source=reporting.name,
            source_sha256=hashlib.sha256(reporting.read_bytes()).hexdigest(),
            mode0_entries=len(pairs), unique_keys=len(dict(pairs)),
            original_vm_matches_capture=True, python_matches_original_vm=True,
            filtered_mode1_fields=len(filtered), all_mode1_fields_match_native=True)
    (args.out_dir/'m320_verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS: {len(vectors)} synthetic cases; {len(pair_vectors)} duplicate-key native cases; {len(private_results)} private cache/native/Python triples')
    print('Report:', args.out_dir/'m320_verification.json')


if __name__=='__main__':main()
