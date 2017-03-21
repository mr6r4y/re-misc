#!/usr/bin/env python
#-*- coding: utf-8 -*


__all__ = []


import argparse

import json
from tabulate import tabulate

import r2pipe as r2p
import elf


def get_args():
    parser = argparse.ArgumentParser(description="Parse .symtab section for ELF file format")
    parser.add_argument("-f", "--file",
                        help="Path to file for analysis", required=True)
    parser.add_argument("-j", "--json-format", action="store_true",
                        help="If set the output format would be JSON")
    parser.add_argument("-r", "--r2-format", action="store_true",
                        help="If set the output is in r2 commands")
    parser.add_argument("-n", "--no-output", action="store_true",
                        help=("If set no output is printed. Used when you only want to save analysis "
                              "to r2 project"))
    parser.add_argument("-p", "--r2-script-file",
                        help="If specified the analysis is saved in --r2-script-file")

    args = parser.parse_args()

    return args


def main():
    args = get_args()
    elf_file = args.file

    e = r2p.open(elf_file)
    o = elf.ElfSym(e, ".symtab", ".strtab")

    if args.r2_script_file:
        o.save_r2_project(args.r2_script_file)

    if not args.no_output and args.json_format:
        print json.dumps(o.symbols)
    elif not args.no_output and args.r2_format:
        for i in o.r2_commands():
            print i
    elif not args.no_output:
        h = ["name", "name_paddr", "dynsym_paddr", "st_value", "st_size", "st_other", "st_shndx", "shn", "st_info", "st_type", "st_bind"]
        t = []
        for i in o.symbols:
            t.append([
                "%s" % i["name"],
                "0x%x" % (i["strsect_off"] + i["st_name"]),
                "0x%x" % (i["sect_off"] + i["offset"]),
                "0x%x" % i["st_value"],
                "0x%x" % i["st_size"],
                "0x%x" % i["st_other"],
                "0x%x" % i["st_shndx"],
                "%s" % i["shn"],
                "0x%x" % i["st_info"],
                "%s" % i["st_type"],
                "%s" % i["st_bind"],
            ])
        print
        print tabulate(t, headers=h)
        print


if __name__ == "__main__":
    main()
