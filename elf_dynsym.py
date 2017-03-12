#!/usr/bin/env python
#-*- coding: utf-8 -*


__all__ = []


import os
import argparse

import ctypes
import r2pipe as r2p


def bytes2str(bytes):
    return "".join([chr(i) for i in bytes])


def elf_dynsym(r2ob):
    sections = r2ob.cmdj("Sj")
    dsm = filter(lambda a: 'dynsym' in a['name'], sections)[0]
    dsm_sect = bytes2str(r2ob.cmdj("pcj %i@%i" % (dsm['size'], dsm['paddr'])))
    print dsm_sect

    dss = filter(lambda a: 'dynstr' in a['name'], sections)[0]
    dss_sect = bytes2str(r2ob.cmdj("pcj %i@%i" % (dss['size'], dss['paddr'])))
    print dss_sect


def get_args():
    parser = argparse.ArgumentParser(description="Parse .dynsym section for ELF file format")
    parser.add_argument("-e", "--elf-file",
                        help="Path to file to analysie", required=True)

    args = parser.parse_args()

    return args


def main():
    args = get_args()
    elf_file = args.elf_file
    
    e = r2p.open(elf_file)
    elf_dynsym(e)


if __name__ == "__main__":
    main()
