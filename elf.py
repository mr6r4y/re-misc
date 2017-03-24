#!/usr/bin/env python
#-*- coding: utf-8 -*


__all__ = []


import ctypes as c

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


class ElfSym(u.R2Scriptable):
    def __init__(self, r2ob, sym_sect, symstr_sect, use_vaddr=False):
        super(ElfSym, self).__init__(r2ob)

        self.sym_sect = sym_sect
        self.symstr_sect = symstr_sect
        self.addr_type = 'paddr' if not use_vaddr else 'vaddr'
        self.size_type = 'size' if not use_vaddr else 'vsize'

        self.finfo = self.r2ob.cmdj('ij')
        self._check_file_type(self.r2ob)
        self.elf_class = self.finfo.get('bin', {}).get('class', None)
        self.Elf_Sym = eh.Elf64_Sym if self.elf_class == 'ELF64' else eh.Elf32_Sym

        self.Elf_Sym_fmt = "xbb[2]Eqq st_name st_info st_other (elf_shn)st_shndx st_value st_size"\
                           if self.elf_class == 'ELF64' else\
                           "xxxbb[2]E st_name st_value st_size st_info st_other (elf_shn)st_shndx"
        self.Elf_Sym_shn_enum_td = u.enum2td("elf_shn", SHN)
        self.Elf_Sym_size = c.sizeof(self.Elf_Sym)

        self.symbols = []

        self._analyse()

    def _check_file_type(self, r2ob):
        # check file type
        if self.finfo.get('bin', {}).get('class', None) not in ['ELF64', 'ELF32']:
            raise NotSupportedError("File is not ELF")

    def _parse_symbols(self, dsm_sect_list, dss_sect, sym_offset, symstr_offset):
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

                "sect_off": sym_offset,
                "strsect_off": symstr_offset,

                # offset of the current symbol struct from the beginning of dynsym section
                "offset": offs,
            })

        return symbols

    def _analyse(self):
        # list all sections
        sections = self.r2ob.cmdj("Sj")
        sm = filter(lambda a: self.sym_sect in a['name'], sections)
        if sm:
            sm = sm[0]
        else:
            return

        # get dynsym section as binary string
        sym_sect = u.bytes2str(self.r2ob.cmdj("pcj %i@%i" % (sm[self.size_type], sm[self.addr_type])))

        # cast to Elf_Sym structures
        symstr_sect_c = c.create_string_buffer(sym_sect)
        symstr_sect_l = []
        for i in range(len(sym_sect) / c.sizeof(self.Elf_Sym)):
            offset = i*c.sizeof(self.Elf_Sym)
            symstr_sect_l.append((u.cast(symstr_sect_c, offset, self.Elf_Sym), offset))

        # get dynstr section as binary string
        ss = filter(lambda a: self.symstr_sect in a['name'], sections)[0]
        ss_sect = u.bytes2str(self.r2ob.cmdj("pcj %i@%i" % (ss[self.size_type], ss[self.addr_type])))

        self.symbols = self._parse_symbols(symstr_sect_l, ss_sect, sm[self.addr_type], ss[self.addr_type])

    def r2_commands(self):
        yield self.Elf_Sym_shn_enum_td

        yield "pf.Elf_Sym %s" % self.Elf_Sym_fmt

        yield "fs %s" % self.sym_sect.strip(".")

        for s in self.symbols:
            yield ("f %s 0x%x @ 0x%x" % ("sym.%s.0x%x" % (s["name"], s["sect_off"] + s["offset"]), self.Elf_Sym_size, s["sect_off"] + s["offset"]))
            yield ("Cf %i %s @0x%x" % (self.Elf_Sym_size, self.Elf_Sym_fmt, s["sect_off"] + s["offset"]))

        yield "fs %s" % self.symstr_sect.strip(".")

        for s in self.symbols:
            yield ("f %s @ 0x%x" % ("str.%s.0x%x" % (s["name"], s["strsect_off"] + s["st_name"]), s["strsect_off"] + s["st_name"]))
            yield ("Cz @0x%x" % (s["strsect_off"] + s["st_name"]))


class ElfRel(u.R2Scriptable):
    def __init__(self, r2ob):
        super(ElfRel, self).__init__(r2ob)

    def r2_commands(self):
        pass


class ElfDynamic(u.R2Scriptable):
    def __init__(self, r2ob):
        super(ElfDynamic, self).__init__(r2ob)

    def r2_commands(self):
        pass
