#!/usr/bin/env python


import sys
import argparse

import json
from tabulate import tabulate

import r2pipe as r2p
import relib.elf as elf


__all__ = []


def get_args():
    parser = argparse.ArgumentParser(description="Parse dynamic segmet in ELF file format")
    parser.add_argument("-f", "--file",
                        help="Path to file for analysis")
    parser.add_argument("-o", "--offset", default=0x0, type=int,
                        help="Start offset for ELF parsing")
    parser.add_argument("-a", "--analysis", action="store_true",
                        help=("If set and used with #!pipe, the analysis commands are "
                              "run from within the script"))
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

    if args.file:
        e = r2p.open(args.file)
    else:
        e = r2p.open()

    # e.cmd("#")   # issued because of a forgotten print on init
    o = elf.ElfDyn(e, args.offset)

    if not args.file and args.analysis:
        o.exec_r2_commands()
        sys.exit()

    if args.r2_script_file:
        o.save_r2_project(args.r2_script_file)

    if not args.no_output and args.json_format:
        print json.dumps(o.dyns)
    elif not args.no_output and args.r2_format:
        for i in o.r2_commands():
            print i
    elif not args.no_output:
        h = ["offset", "tag", "d_tag", "d_val", "d_ptr"]
        t = []
        for i in o.dyns:
            t.append([
                "0x%x" % i["offset"],
                "%s" % i["tag"],
                "0x%x" % i["d_tag"],
                "0x%x" % i["d_val"],
                "0x%x" % i["d_ptr"],
            ])
        print
        print tabulate(t, headers=h)
        print


if __name__ == "__main__":
    main()
