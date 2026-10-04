"""Verify the recovered Twofish implementation against original ARM64 code.

This is entirely offline. The Mach-O is read, never patched or executed by the
host. Unicorn runs the original q/MDS initializers, key schedule and block
encrypt/decrypt functions. Only memcpy, memset and stack-canary storage are
provided by the harness. CBC here is composed from native block calls; it does
not claim to execute the SDK's virtualized CBC wrapper.

Dependencies: unicorn, lief, capstone, pycryptodome. Run from the project root:
  python tools/a9_native_verify.py --image /path/to/Keeta.dec --out .private/native-a9.json
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
)

from tools.a9_unflatten import Image
from mtgsig.a9_codec import IV, twofish_schedule
from mtgsig.mtg_crypto import A9Cipher

# Fixed RVAs below belong to this historical research image, not every App build.
EXPECTED_IMAGE_SHA256 = "0900cac89f75fc4f75279c708785bf2c7a03c228301a8e75ce62f93e3ad88488"


class NativeTwofish:
    """Execute unmodified file-backed instructions at their link-time VAs."""

    SCRATCH = 0x200000000
    STACK = 0x210000000
    STOP = 0x220000000
    ARG_REGS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                UC_ARM64_REG_X6, UC_ARM64_REG_X7)

    def __init__(self, path):
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != EXPECTED_IMAGE_SHA256:
            raise ValueError("image SHA256 does not match the verified fixed-RVA research build")
        self.image = Image(path)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for segment in self.image.binary.segments:
            if segment.name == "__PAGEZERO" or not segment.virtual_size:
                continue
            self.uc.mem_map(segment.virtual_address,
                            (segment.virtual_size + 0xFFF) & ~0xFFF)
            if segment.file_size:
                data = self.image.data[segment.file_offset:
                                       segment.file_offset + segment.file_size]
                self.uc.mem_write(segment.virtual_address, data)
        self.uc.mem_map(self.SCRATCH, 0x100000)
        self.uc.mem_map(self.STACK, 0x100000)
        self.uc.mem_map(self.STOP, 0x1000)
        self.keyptr = self.SCRATCH + 0x100
        self.mdsptr = self.SCRATCH + 0x1000
        self.v73ptr = self.SCRATCH + 0x3000
        self.inptr = self.SCRATCH + 0x5000
        self.outptr = self.SCRATCH + 0x6000
        guard = self.SCRATCH + 0x7000
        self.uc.mem_write(self.image.base + 0x404DE20, struct.pack("<Q", guard))
        self.uc.mem_write(guard, b"guard123")
        self.services = {0x2F094C: "memcpy", 0x2F08E8: "memset"}
        self.service_calls = {name: 0 for name in self.services.values()}
        for rva in self.services:
            address = self.image.base + rva
            self.uc.hook_add(UC_HOOK_CODE, self._service, begin=address, end=address)

    def _service(self, uc, address, size, user_data):
        operation = self.services[address - self.image.base]
        dst, value, length = (uc.reg_read(r) for r in self.ARG_REGS[:3])
        if length > 0x10000:
            raise RuntimeError(f"unexpected {operation} length {length}")
        if operation == "memcpy":
            data = bytes(uc.mem_read(value, length))
        else:
            data = bytes([value & 255]) * length
        if data:
            uc.mem_write(dst, data)
        self.service_calls[operation] += 1
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

    def call(self, rva, *args):
        for reg, value in zip(self.ARG_REGS, args + (0,) * (8 - len(args))):
            self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM64_REG_SP, self.STACK + 0xFF000)
        self.uc.reg_write(UC_ARM64_REG_X30, self.STOP)
        try:
            self.uc.emu_start(self.image.base + rva, self.STOP, count=2_000_000)
        except UcError as exc:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            raise RuntimeError(f"native call {rva:#x} failed at {pc:#x}: {exc}") from exc
        if self.uc.reg_read(UC_ARM64_REG_PC) != self.STOP:
            raise RuntimeError(f"native call {rva:#x} exceeded instruction budget")

    def schedule(self, key, modified=False):
        if len(key) != 16:
            raise ValueError("the a9 key must be 16 bytes")
        self.uc.mem_write(self.keyptr, key)
        self.uc.mem_write(self.mdsptr, bytes(0x1010))
        self.uc.mem_write(self.mdsptr + 0x1000,
                          struct.pack("<II", 0, 0xBC if modified else 0xB4))
        # The q nibble tables come directly from the Mach-O's __DATA segment.
        self.call(0x39361C, self.mdsptr)
        self.uc.mem_write(self.v73ptr, bytes(4256))
        self.call(0x3937F0, self.keyptr, len(key), self.v73ptr, self.mdsptr)
        return bytes(self.uc.mem_read(self.v73ptr, 4256))

    def block(self, data, decrypt=False):
        if len(data) != 16:
            raise ValueError("a block must be 16 bytes")
        self.uc.mem_write(self.inptr, data)
        self.uc.mem_write(self.outptr, b"\xA5" * 16)
        self.call(0x394A90 if decrypt else 0x3941EC,
                  self.v73ptr, self.inptr, self.outptr)
        return bytes(self.uc.mem_read(self.outptr, 16))

    def composed_cbc(self, data, decrypt=False):
        if len(data) % 16:
            raise ValueError("CBC input must be padded to a multiple of 16")
        output, previous = bytearray(), IV
        for offset in range(0, len(data), 16):
            block = data[offset:offset + 16]
            if decrypt:
                output.extend(a ^ b for a, b in zip(self.block(block, True), previous))
                previous = block
            else:
                previous = self.block(bytes(a ^ b for a, b in zip(block, previous)))
                output.extend(previous)
        return bytes(output)


def synthetic_bytes(label, size):
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha256(f"a9-native-fixture:{label}:{counter}".encode()).digest())
        counter += 1
    return bytes(output[:size])


def verify(image_path, cases=24):
    native = NativeTwofish(image_path)
    vectors = []
    for modified in (False, True):
        mode = "twofish-mod" if modified else "twofish"
        for index in range(cases):
            key = (bytes(16) if index == 0 else bytes(range(16)) if index == 1
                   else synthetic_bytes(f"key:{index}", 16))
            plain = (bytes(16) if index == 0 else bytes(range(16)) if index == 1
                     else synthetic_bytes(f"block:{index}", 16))
            schedule = native.schedule(key, modified)
            recovered_schedule = twofish_schedule(key, modified=modified)
            if schedule != recovered_schedule:
                first = next(i for i, (a, b) in enumerate(zip(schedule, recovered_schedule)) if a != b)
                raise AssertionError(f"{mode} synthetic case {index}: schedule mismatch at byte {first}")
            cipher = A9Cipher(recovered_schedule)
            encrypted = native.block(plain)
            python_encrypted = struct.pack("<4I", *cipher.enc_block(struct.unpack("<4I", plain)))
            assert encrypted == python_encrypted, (mode, index, "encrypt mismatch")
            assert native.block(encrypted, True) == plain, (mode, index, "native inverse mismatch")
            assert struct.pack("<4I", *cipher.dec_block(struct.unpack("<4I", encrypted))) == plain
            arbitrary_ciphertext = synthetic_bytes(f"ciphertext:{index}", 16)
            assert native.block(arbitrary_ciphertext, True) == struct.pack(
                "<4I", *cipher.dec_block(struct.unpack("<4I", arbitrary_ciphertext)))
            cbc_plaintext = synthetic_bytes(f"cbc:{index}", 16 * (1 + index % 9))
            cbc_ciphertext = native.composed_cbc(cbc_plaintext)
            assert cbc_ciphertext == cipher._cbc_enc(cbc_plaintext), (mode, index, "CBC mismatch")
            assert native.composed_cbc(cbc_ciphertext, True) == cbc_plaintext
            assert cipher._cbc_dec(cbc_ciphertext) == cbc_plaintext
            if index < 3:
                vectors.append({"mode": mode, "key": key.hex(), "plaintext": plain.hex(),
                                "ciphertext": encrypted.hex(),
                                "schedule_sha256": hashlib.sha256(schedule).hexdigest(),
                                "cbc_plaintext": cbc_plaintext.hex(),
                                "cbc_ciphertext": cbc_ciphertext.hex()})
    return {
        "image_sha256": hashlib.sha256(native.image.data).hexdigest(),
        "execution": "Unmodified ARM64 instructions in Unicorn; no device or network access",
        "functions_rva": {"q_mds_init": "0x39361c", "schedule": "0x3937f0",
                          "encrypt_block": "0x3941ec", "decrypt_block": "0x394a90"},
        "substitutions": {"0x2f094c": "memcpy", "0x2f08e8": "memset",
                          "0x404de20": "pointer to synthetic stack guard"},
        "cases_per_mode": cases,
        "checks": {"schedule_all_4256_bytes": 2 * cases,
                   "native_encrypt_vs_python": 2 * cases,
                   "native_decrypt_vs_python_arbitrary_ciphertext": 2 * cases,
                   "native_block_inverse": 2 * cases,
                   "native_block_composed_cbc": 2 * cases},
        "result": "PASS",
        "limitations": ["CBC uses harness chaining of native block calls; SDK VM CBC wrapper was not executed.",
                        "Key/provider derivation and a9 envelope are outside this verifier.",
                        "Only 128-bit keys and the analysed Mach-O build are covered."],
        "vectors": vectors,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cases", type=int, default=24)
    args = parser.parse_args()
    if args.cases < 3:
        parser.error("--cases must be at least 3")
    if args.out.exists():
        parser.error("--out must not already exist")
    report = verify(args.image, args.cases)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"PASS: {args.cases} synthetic keys per mode; original ARM64 schedule, encrypt, decrypt and composed CBC")
    print(f"Report: {args.out}")


if __name__ == "__main__":
    main()
