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


def r2_analysis(r2ob, dt, project):
    pass


class ElfDynsym(object):
    def __init__(self, r2ob):
        self.r2ob = r2ob
        self.finfo = self.r2ob.cmdj('ij')
        self._check_file_type(self.r2ob)
        self.elf_class = self.finfo.get('bin', {}).get('class', None)
        self.Elf_Sym = eh.Elf64_Sym if self.elf_class == 'ELF64' else eh.Elf32_Sym

        self.Elf_Sym_fmt = u.struct2r2fmt(self.Elf_Sym)
        self.Elf_Sym_size = c.sizeof(self.Elf_Sym)

        self.symbols = None
        self.symbols_struct_l = None

        self._analyse()

    def _check_file_type(self, r2ob):
        # check file type
        if self.finfo.get('bin', {}).get('class', None) not in ['ELF64', 'ELF32']:
            raise NotSupportedError("File is not ELF")

    def _parse_symbols(self, dsm_sect_list, dss_sect, dynsym_offset, dynstr_offset):
        symbols = []
        for ds, offs in dsm_sect_list:
            name = dss_sect[ds.st_name:].partition("\x00")[0]
            symbols.append({
                "name": name,
                "st_name": ds.st_name,
                "st_value": ds.st_value,
                "st_size": ds.st_size,
                "st_other": ds.st_other,
                "st_shndx": ds.st_shndx,
                "shn": SHN.get(ds.st_shndx, "?"),
                "st_info": ds.st_info,

                # mimic ELF_ST_TYPE macro
                "st_type": ST_TYPE.get(ds.st_info & 0xf, "?"),

                # mimic ELF_ST_BIND macro
                "st_bind": ST_BIND.get(ds.st_info >> 4, "?"),

                "dynsym_off": dynsym_offset,
                "dynstr_off": dynstr_offset,

                # offset of the current symbol struct from the beginning of dynsym section
                "offset": offs,
            })

        return symbols

    def _analyse(self):
        # list all sections
        sections = self.r2ob.cmdj("Sj")
        dsm = filter(lambda a: 'dynsym' in a['name'], sections)[0]

        # get dynsym section as binary string
        dsm_sect = u.bytes2str(self.r2ob.cmdj("pcj %i@%i" % (dsm['size'], dsm['paddr'])))

        # cast to Elf_Sym structures
        dsm_sect_c = c.create_string_buffer(dsm_sect)
        dsm_sect_l = []
        for i in range(len(dsm_sect) / c.sizeof(self.Elf_Sym)):
            offset = i*c.sizeof(self.Elf_Sym)
            dsm_sect_l.append((u.cast(dsm_sect_c, offset, self.Elf_Sym), offset))

        # get dynstr section as binary string
        dss = filter(lambda a: 'dynstr' in a['name'], sections)[0]
        dss_sect = u.bytes2str(self.r2ob.cmdj("pcj %i@%i" % (dss['size'], dss['paddr'])))

        self.symbols = self._parse_symbols(dsm_sect_l, dss_sect, dsm['paddr'], dss['paddr'])

    def r2_commands(self):
        for s in self.symbols:
            yield ("CC Elf_Sym: '%s' @0x%x" % (s["name"], s["dynsym_off"] + s["offset"]))
            yield ("Cf %i %s @0x%x" % (self.Elf_Sym_size, self.Elf_Sym_fmt, s["dynsym_off"] + s["offset"]))
            yield ("Cz @0x%x" % (s["dynstr_off"] + s["st_name"]))

    def save_r2_project(self, r2_script_file):
        with open(r2_script_file, 'w') as f:
            for c in self.r2_commands():
                f.write("%s\n" % c)


def get_args():
    parser = argparse.ArgumentParser(description="Parse .dynsym section for ELF file format")
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
    o = ElfDynsym(e)

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
                "0x%x" % (i["dynstr_off"] + i["st_name"]),
                "0x%x" % (i["dynsym_off"] + i["offset"]),
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
