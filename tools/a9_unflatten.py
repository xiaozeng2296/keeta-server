"""Read-only expansion of Keeta's relative-table dispatcher (RVA 0x2dc7ec).

Writes analysis listings only; does not patch the executable. Addresses in the
listing are module-relative, with Mach-O segment mapping used for file reads.
"""
import argparse
import bisect
import hashlib
import struct
from pathlib import Path

import capstone
import lief


class Image:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.binary = lief.MachO.parse(str(path)).at(0)
        self.base = self.binary.get_segment("__TEXT").virtual_address
        self.starts = list(self.binary.function_starts.functions)
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True
        self.cs.skipdata = True

    def read(self, rva, size):
        va = self.base + rva
        for seg in self.binary.segments:
            delta = va - seg.virtual_address
            if 0 <= delta and delta + size <= seg.file_size:
                off = seg.file_offset + delta
                return self.data[off:off + size]
        raise ValueError(f"not file-backed: {rva:#x}+{size:#x}")

    def u32(self, rva):
        return struct.unpack("<I", self.read(rva, 4))[0]

    def bounds(self, rva):
        i = bisect.bisect_right(self.starts, rva)
        return self.starts[i - 1], self.starts[i]

    def listing(self, rva):
        start, end = self.bounds(rva)
        ins = list(self.cs.disasm(self.read(start, end - start), start))
        dispatch = {i.address: i.address + 4 for i in ins
                    if i.mnemonic == "bl" and i.op_str == "#0x2dc7ec"}
        replacements, omit = {}, set()
        edges = []
        for pos, inst in enumerate(ins):
            if inst.mnemonic != "b":
                continue
            target = inst.operands[0].imm
            if target not in dispatch:
                continue
            index, consumed = None, []
            for prev in reversed(ins[max(0, pos - 5):pos]):
                if prev.mnemonic == "mov" and prev.op_str.startswith(("w0, #", "x0, #")):
                    index = prev.operands[1].imm
                    consumed.append(prev.address)
                    break
                if prev.mnemonic == "ldr" and prev.op_str.startswith("w0, #"):
                    index = self.u32(prev.operands[1].imm)
                    consumed.append(prev.address)
                    break
                if prev.mnemonic not in ("nop", "stp"):
                    break
            if index is None:
                continue
            table = dispatch[target]
            dest = table + self.u32(table + 4 * index)
            if not start <= dest < end or dest % 4:
                raise ValueError(f"invalid dispatcher destination {dest:#x}")
            replacements[inst.address] = f"b #{dest:#x} ; expanded table[{index}] at {table:#x}"
            omit.update(consumed)
            edges.append({"site": inst.address, "table": table, "index": index, "target": dest})
        lines = [f"; function {start:#x}..{end:#x}; dispatcher edges resolved: {len(edges)}"]
        for inst in ins:
            if inst.address in omit or inst.mnemonic in ("udf", "nop"):
                continue
            if inst.op_str == "x0, x30, [sp, #-0x50]" and inst.mnemonic in ("stp", "ldp"):
                continue
            line = replacements.get(inst.address, f"{inst.mnemonic} {inst.op_str}")
            lines.append(f"{inst.address:08x}: {line}")
        return "\n".join(lines) + "\n", edges


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rva", nargs="+", type=lambda x: int(x, 0))
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    image = Image(args.image)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=False)
    for rva in args.rva:
        listing, edges = image.listing(rva)
        listing = "; image_sha256=" + hashlib.sha256(image.data).hexdigest() + "\n" + listing
        if args.out:
            out = args.out / f"{image.bounds(rva)[0]:08x}.asm"
            out.write_text(listing)
            print(f"{out}: {len(edges)} resolved dispatcher branches")
        else:
            print(listing)


if __name__ == "__main__":
    main()
