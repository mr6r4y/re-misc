#!/usr/bin/env python


import argparse
from tabulate import tabulate
import json
import r2pipe as r2p
import elf


__all__ = []


def get_args():
    parser = argparse.ArgumentParser(description="Parse dynamic segmet in ELF file format")
    parser.add_argument("-f", "--file",
                        help="Path to file for analysis")
    parser.add_argument("-o", "--offset", default=0x0, type=int,
                        help="Start offset for ELF parsing")
    parser.add_argument("-j", "--json-format", action="store_true",
                        help="If set the output format would be JSON")

    args = parser.parse_args()

    return args


def main():
    args = get_args()

    if args.file:
        e = r2p.open(args.file)
    else:
        e = r2p.open()

    # e.cmd("#")   # issued because of a forgotten print on init
    o = elf.ElfDyn(e, args.offset)
    imported_libs = [i for i in elf.get_ldd(e, o)]

    if args.json_format:
        print json.dumps(imported_libs)
    else:
        h = ["Imported Libs"]
        t = [[i] for i in imported_libs]
        print
        print tabulate(t, headers=h)
        print


if __name__ == "__main__":
    main()
