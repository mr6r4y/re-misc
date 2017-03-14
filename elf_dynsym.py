#!/usr/bin/env python
#-*- coding: utf-8 -*


__all__ = []


import os
import argparse

import ctypes as c
import r2pipe as r2p

from lin_hh.elf_h import Elf64_Sym
from utils import bytes2str


class NotSupportedError(StandardError):
    pass


def elf_dynsym(r2ob):
    # check file type
    finfo = r2ob.cmdj('ij')
    if finfo.get('class', None) not in ['ELF64', 'ELF32']:
        raise NotSupportedError("File is not ELF")

    # list all sections
    sections = r2ob.cmdj("Sj")
    dsm = filter(lambda a: 'dynsym' in a['name'], sections)[0]

    # get dynsym section as binary string
    dsm_sect = bytes2str(r2ob.cmdj("pcj %i@%i" % (dsm['size'], dsm['paddr'])))

    
    

    # get dynstr section as binary string
    dss = filter(lambda a: 'dynstr' in a['name'], sections)[0]
    dss_sect = bytes2str(r2ob.cmdj("pcj %i@%i" % (dss['size'], dss['paddr'])))


def get_args():
    parser = argparse.ArgumentParser(description="Parse .dynsym section for ELF file format")
    parser.add_argument("-f", "--file",
                        help="Path to file for analysis", required=True)
    parser.add_argument("-p", "--r2-project",
                        help="If specified the analysis is saved in --r2-project for the opened file")

    args = parser.parse_args()

    return args


def main():
    args = get_args()
    elf_file = args.file
    
    e = r2p.open(elf_file)
    elf_dynsym(e)


if __name__ == "__main__":
    main()
