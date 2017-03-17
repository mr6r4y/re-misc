#!/usr/bin/env python
#-*- coding: utf-8 -*


__all__ = []


import os
import argparse

import json
from tabulate import tabulate

import ctypes as c
import r2pipe as r2p

import lin_hh.elf_h as eh
import utils as u


class NotSupportedError(StandardError):
    pass


ST_TYPE = {
    eh.STT_NOTYPE: "STT_NOTYPE",
    eh.STT_OBJECT: "STT_OBJECT",
    eh.STT_FUNC: "STT_FUNC",
    eh.STT_SECTION: "STT_SECTION",
    eh.STT_FILE: "STT_FILE",
    eh.STT_COMMON: "STT_COMMON",
    eh.STT_TLS: "STT_TLS"
}


ST_BIND = {
    eh.STB_LOCAL: "STB_LOCAL",
    eh.STB_GLOBAL: "STB_GLOBAL",
    eh.STB_WEAK: "STB_WEAK"
}


SHN = {
    eh.SHN_UNDEF: "SHN_UNDEF",
    eh.SHN_LORESERVE: "SHN_LORESERVE",
    eh.SHN_LOPROC: "SHN_LOPROC",
    eh.SHN_HIPROC: "SHN_HIPROC",
    eh.SHN_ABS: "SHN_ABS",
    eh.SHN_COMMON: "SHN_COMMON",
    eh.SHN_HIRESERVE: "SHN_HIRESERVE"
}


def parse_symbols(dsm_sect_list, dss_sect):
    symbols = []
    for ds in dsm_sect_list:
        name = dss_sect[ds.st_name:].partition("\x00")[0]
        symbols.append({
            "name": name,
            "st_value": ds.st_value,
            "st_size": ds.st_size,
            "st_other": ds.st_other,
            "st_shndx": ds.st_shndx,
            "shn": SHN.get(ds.st_shndx, "?"),
            "st_info": ds.st_info,
            # mimic ELF_ST_TYPE macro
            "st_type": ST_TYPE.get(ds.st_info & 0xf, "?"),
            # mimic ELF_ST_BIND macro
            "st_bind": ST_BIND.get(ds.st_info >> 4, "?")
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

    return parse_symbols(dsm_sect_l, dss_sect)


def get_args():
    parser = argparse.ArgumentParser(description="Parse .dynsym section for ELF file format")
    parser.add_argument("-f", "--file",
                        help="Path to file for analysis", required=True)
    parser.add_argument("-j", "--json-format", action="store_true",
                        help="If set the output format would be JSON")
    parser.add_argument("-n", "--no-output", action="store_true",
                        help=("If set no output is printed. Used when you only want to save analysis "
                             "to r2 project"))
    parser.add_argument("-p", "--r2-project",
                        help="If specified the analysis is saved in --r2-project for the opened file")

    args = parser.parse_args()

    return args


def main():
    args = get_args()
    elf_file = args.file

    # TO-DO: Implement Save To Project
    e = r2p.open(elf_file)
    o = elf_dynsym(e)

    if not args.no_output and args.json_format:
        print json.dumps(o)
    elif not args.no_output:
        h = ["name", "st_value", "st_size", "st_other", "st_shndx", "shn", "st_info", "st_type", "st_bind"]
        t = []
        for i in o:
            t.append([
                "%s" % i["name"],
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


if __name__ == "__main__":
    main()
