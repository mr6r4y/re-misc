#!/usr/bin/env python


import argparse
import platform

import elf
import r2pipe as r2p


def find_syscalls_header(elf_class=None):
    if elf_class is not None:
        a = "64bit" if elf.eh.ELFCLASS64 == elf_class else "32bit"
    else:
        a = platform.architecture()[0]

    return "/usr/include/asm/unistd_64.h" if a == "64bit" else "/usr/include/asm/unistd_32.h"


def parse_syscalls_header(header_file):
    c = "#define __NR_"

    with open(header_file, "r") as h:
        for line in h:
            if line.startswith(c):
                syscall, sysnum = [i.strip() for i in line.replace(c, "").split(" ")]
                yield (int(sysnum), syscall)


def trace_eax(instructions):
    def _analysis(instr):
        if instr["type"] == "mov":
            dst, src = instr["opcode"].replace("mov ", "").split(", ")

            if instr["refptr"] is False:
                try:
                    src = int(src, 16)
                except ValueError:
                    regs[dst] = regs.get(src, None)
                else:
                    regs[dst] = src
            else:
                try:
                    src = int(src, 16)
                except ValueError:
                    regs[dst] = src
                else:
                    regs[dst] = src

    regs = {}
    eax = None
    for instr in instructions:
        _analysis(instr)
        ax = regs.get("ax", None)
        eax = regs.get("eax", None)
        rax = regs.get("rax", None)
        yield (rax if rax else (eax if eax else ax)), instr


def syscall_analysis(r2ob, at_address, syscalls):
    if at_address:
        d = r2ob.cmdj("pdfj @ %i" % at_address)
    else:
        d = r2ob.cmdj("pdfj")

    for eax, instr in trace_eax(d["ops"]):
        if instr["opcode"] == "int 0x80" and eax is not None:
            sysc = syscalls[eax]
            r2ob.cmd("CCu %s @ 0x%x" % (sysc, instr["offset"]))


def get_args():
    parser = argparse.ArgumentParser(description="Analysis of linux Int0x80 syscalls")
    parser.add_argument("-s", "--syscalls-header", help="Path to file for analysis")
    parser.add_argument("-t", "--at-address", type=int, help="Function address to analyse")
    args = parser.parse_args()

    return args


def main():
    args = get_args()

    e = r2p.open()

    elf_hdr = elf.ElfEhdr(e, 0x0)

    syscalls_header = args.syscalls_header\
        if args.syscalls_header else find_syscalls_header(elf_hdr.elf_class)
    at_address = args.at_address if args.at_address else None

    syscalls = dict(list(parse_syscalls_header(syscalls_header)))
    syscall_analysis(e, at_address, syscalls)


if __name__ == '__main__':
    main()
