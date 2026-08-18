#!/usr/bin/env python3
"""Report absolute code addresses stored in a module's data.

A module is linked at address zero and loaded wherever there is room,
so any address the linker resolved to a fixed value is wrong once the
module runs. These are baked-in values rather than relocations, so the
loader has nothing to fix up and nothing reports the discrepancy.

Most modules carry a small, EXPECTED set of these: the `_KEEP_MEMSET`
and `_KEEP_MEMMOVE` anchors in Fluxor's PIC SDK, `#[used]` statics that
exist only to stop LTO eliminating the memory intrinsics. Nothing
dereferences them, so they are inert. Resolve what this prints against
the module's symbol table (`readelf -sW`) before drawing a conclusion:
addresses naming `__aeabi_mem*` are the anchors and are normal.

What is not normal is a table the code actually reads — the usual
source is a `&'static [T]` selected at runtime, or a match with enough
arms to become a lookup table. Those link, pass every host test, and
fault on the first record the module handles.

That mix is why this reports rather than gates.
"""

import re
import struct
import subprocess
import sys
from pathlib import Path


def sections(elf):
    out = subprocess.run(
        ["readelf", "-S", "-W", str(elf)], capture_output=True, text=True
    ).stdout
    found = []
    for line in out.splitlines():
        m = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
            line,
        )
        if m:
            found.append(
                (m.group(1), m.group(2), int(m.group(3), 16),
                 int(m.group(4), 16), int(m.group(5), 16))
            )
    return found


def check(elf):
    secs = sections(elf)
    text = [s for s in secs if s[0] == ".text"]
    if not text:
        return []
    _, _, text_addr, _, text_size = text[0]
    lo, hi = text_addr, text_addr + text_size
    # Below this a word is an ordinary small integer, not an address.
    floor = max(lo, 0x1000)
    data = elf.read_bytes()
    bad = []
    for name, typ, addr, off, size in secs:
        if typ != "PROGBITS" or name == ".text" or size < 8:
            continue
        for i in range(0, size - 7, 8):
            word = struct.unpack_from("<Q", data, off + i)[0]
            if floor <= word < hi:
                bad.append((name, addr + i, word))
    return bad


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "target/bcm2712/modules")
    elves = sorted(root.glob("*.elf"))
    if not elves:
        print(f"pic-abs-addr: no modules under {root}")
        return 0
    failed = 0
    for elf in elves:
        bad = check(elf)
        if bad:
            failed += 1
            print(f"FAILED {elf.name}: {len(bad)} absolute code address(es) in data")
            for name, at, word in bad[:6]:
                print(f"    {name}+0x{at:x} holds 0x{word:x} (inside .text)")
            print("    Resolve against `readelf -sW`: __aeabi_mem* names are")
            print("    the SDK's inert _KEEP_* anchors; anything else is suspect.")
    print(f"pic-abs-addr: {failed} of {len(elves)} module(s) carry absolute addresses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
