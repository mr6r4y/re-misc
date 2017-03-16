#!/usr/bin/env python
#-*- coding: utf-8 -*


__all__ = []


import os
import argparse

import ctypes as c
import r2pipe as r2p

import lin_hh.elf_h as eh
import utils as u


class NotSupportedError(StandardError):
    pass


def parse_symbols(dsm_sect_list, dss_sect):
    symbols = []
    for ds in dsm_sect_list:
        name = dss_sect[ds.st_name:].partition("\x00")[0]
        symbols.append({
            "name": name
        })

    return symbols


def elf_dynsym(r2ob):
    # check file type
    finfo = r2ob.cmdj('ij')
    if finfo.get('bin', {}).get('class', None) not in ['ELF64', 'ELF32']:
        raise NotSupportedError("File is not ELF")

    e_cl = finfo.get('bin', {}).get('class', None)
    Elf_Sym = eh.Elf64_Sym if e_cl == 'ELF64' else eh.Elf32_Sym

    # list all sections
    sections = r2ob.cmdj("Sj")
    dsm = filter(lambda a: 'dynsym' in a['name'], sections)[0]

    # get dynsym section as binary string
    dsm_sect = u.bytes2str(r2ob.cmdj("pcj %i@%i" % (dsm['size'], dsm['paddr'])))

    # cast to Elf_Sym structures
    dsm_sect_c = c.create_string_buffer(dsm_sect)
    dsm_sect_l = []
    for i in range(len(dsm_sect) / c.sizeof(Elf_Sym)):
        dsm_sect_l.append(u.cast(dsm_sect_c, i*c.sizeof(Elf_Sym), Elf_Sym))

    # get dynstr section as binary string
    dss = filter(lambda a: 'dynstr' in a['name'], sections)[0]
    dss_sect = u.bytes2str(r2ob.cmdj("pcj %i@%i" % (dss['size'], dss['paddr'])))

    # TO-DO: Make another class that represents Elf_Sym struct that is human friendly for showing and printing and
    # cast between constants and strings in dss_sect_c
    return parse_symbols(dsm_sect_l, dss_sect)


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
    print elf_dynsym(e)


if __name__ == "__main__":
    main()
