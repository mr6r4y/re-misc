#!/usr/bin/env python

import argparse
import os
import r2pipe as r2p


def get_args():
    parser = argparse.ArgumentParser(description="Dump dissassembly of all analysed funcs")
    parser.add_argument("-d", "--directory", default="./",
                        help="Path to directory to dump files")

    args = parser.parse_args()

    return args


def dump_funcs(directory):
    r = r2p.open()
    for i in r.cmdj("aflj"):
        fl = os.path.join(directory, i["name"])
        r.cmd("pdfs @ 0x%x > %s.asm" % (i["offset"], fl))


def main():
    args = get_args()
    dr = os.path.abspath(args.directory)

    dump_funcs(dr)


if __name__ == "__main__":
    main()
