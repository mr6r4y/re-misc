#!/usr/bin/env python

import argparse
import r2pipe as r2p


def get_args():
    parser = argparse.ArgumentParser(description="Dump dissassembly of all analysed funcs")
    parser.add_argument("-f", "--file",
                        help="Path to file for analysis")

    args = parser.parse_args()

    return args


def dump_funcs(fl):
    r = r2p.open()
    with open(fl, "w") as f:
        for i in r.cmdj("aflj"):
            f.write("0x%x : %s\n\n" % (i["offset"], i["name"]))
            r.cmd("s 0x%x" % i["offset"])
            f.write(r.cmd("pdf"))
            f.write("\n\n\n")


def main():
    args = get_args()
    fl = args.file

    dump_funcs(fl)


if __name__ == "__main__":
    main()
