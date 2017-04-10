

import ctypes as c

import lin_hh.elf_h as eh
import utils as u
from collections import OrderedDict


__all__ = []


class NotSupportedError(StandardError):
    pass


EM = {
    eh.EM_NONE: "EM_NONE",
    eh.EM_M32: "EM_M32",
    eh.EM_SPARC: "EM_SPARC",
    eh.EM_386: "EM_386",
    eh.EM_68K: "EM_68K",
    eh.EM_88K: "EM_88K",
    eh.EM_486: "EM_486",
    eh.EM_860: "EM_860",
    eh.EM_MIPS: "EM_MIPS",
    eh.EM_MIPS_RS3_LE: "EM_MIPS_RS3_LE",
    eh.EM_MIPS_RS4_BE: "EM_MIPS_RS4_BE",
    eh.EM_PARISC: "EM_PARISC",
    eh.EM_SPARC32PLUS: "EM_SPARC32PLUS",
    eh.EM_PPC: "EM_PPC",
    eh.EM_PPC64: "EM_PPC64",
    eh.EM_SPU: "EM_SPU",
    eh.EM_ARM: "EM_ARM",
    eh.EM_SH: "EM_SH",
    eh.EM_SPARCV9: "EM_SPARCV9",
    eh.EM_IA_64: "EM_IA_64",
    eh.EM_X86_64: "EM_X86_64",
    eh.EM_S390: "EM_S390",
    eh.EM_CRIS: "EM_CRIS",
    eh.EM_V850: "EM_V850",
    eh.EM_M32R: "EM_M32R",
    eh.EM_MN10300: "EM_MN10300",
    eh.EM_BLACKFIN: "EM_BLACKFIN",
    eh.EM_TI_C6000: "EM_TI_C6000",
    eh.EM_AARCH64: "EM_AARCH64",
    eh.EM_FRV: "EM_FRV",
    eh.EM_AVR32: "EM_AVR32",
    eh.EM_ALPHA: "EM_ALPHA",
    eh.EM_CYGNUS_V850: "EM_CYGNUS_V850",
    eh.EM_CYGNUS_M32R: "EM_CYGNUS_M32R",
    eh.EM_S390_OLD: "EM_S390_OLD",
    eh.EM_CYGNUS_MN10300: "EM_CYGNUS_MN10300",
}


PT = {
    eh.PT_NULL: "PT_NULL",
    eh.PT_LOAD: "PT_LOAD",
    eh.PT_DYNAMIC: "PT_DYNAMIC",
    eh.PT_INTERP: "PT_INTERP",
    eh.PT_NOTE: "PT_NOTE",
    eh.PT_SHLIB: "PT_SHLIB",
    eh.PT_PHDR: "PT_PHDR",
    eh.PT_TLS: "PT_TLS",
    eh.PT_LOOS: "PT_LOOS",
    eh.PT_HIOS: "PT_HIOS",
    eh.PT_LOPROC: "PT_LOPROC",
    eh.PT_HIPROC: "PT_HIPROC",
    eh.PT_GNU_EH_FRAME: "PT_GNU_EH_FRAME",
    eh.PT_GNU_STACK: "PT_GNU_STACK",
    eh.PT_GNU_RELRO: "PT_GNU_RELRO",
}


ET = {
    eh.ET_NONE: "ET_NONE",
    eh.ET_REL: "ET_REL",
    eh.ET_EXEC: "ET_EXEC",
    eh.ET_DYN: "ET_DYN",
    eh.ET_CORE: "ET_CORE",
    eh.ET_LOPROC: "ET_LOPROC",
    eh.ET_HIPROC: "ET_HIPROC",
}


DT = {
    eh.DT_NULL: "DT_NULL",
    eh.DT_NEEDED: "DT_NEEDED",
    eh.DT_PLTRELSZ: "DT_PLTRELSZ",
    eh.DT_PLTGOT: "DT_PLTGOT",
    eh.DT_HASH: "DT_HASH",
    eh.DT_STRTAB: "DT_STRTAB",
    eh.DT_SYMTAB: "DT_SYMTAB",
    eh.DT_RELA: "DT_RELA",
    eh.DT_RELASZ: "DT_RELASZ",
    eh.DT_RELAENT: "DT_RELAENT",
    eh.DT_STRSZ: "DT_STRSZ",
    eh.DT_SYMENT: "DT_SYMENT",
    eh.DT_INIT: "DT_INIT",
    eh.DT_FINI: "DT_FINI",
    eh.DT_SONAME: "DT_SONAME",
    eh.DT_RPATH: "DT_RPATH",
    eh.DT_SYMBOLIC: "DT_SYMBOLIC",
    eh.DT_REL: "DT_REL",
    eh.DT_RELSZ: "DT_RELSZ",
    eh.DT_RELENT: "DT_RELENT",
    eh.DT_PLTREL: "DT_PLTREL",
    eh.DT_DEBUG: "DT_DEBUG",
    eh.DT_TEXTREL: "DT_TEXTREL",
    eh.DT_JMPREL: "DT_JMPREL",
    eh.DT_ENCODING: "DT_ENCODING",
    eh.OLD_DT_LOOS: "OLD_DT_LOOS",
    eh.DT_LOOS: "DT_LOOS",
    eh.DT_HIOS: "DT_HIOS",
    eh.DT_VALRNGLO: "DT_VALRNGLO",
    eh.DT_VALRNGHI: "DT_VALRNGHI",
    eh.DT_ADDRRNGLO: "DT_ADDRRNGLO",
    eh.DT_ADDRRNGHI: "DT_ADDRRNGHI",
    eh.DT_VERSYM: "DT_VERSYM",
    eh.DT_RELACOUNT: "DT_RELACOUNT",
    eh.DT_RELCOUNT: "DT_RELCOUNT",
    eh.DT_FLAGS_1: "DT_FLAGS_1",
    eh.DT_VERDEF: "DT_VERDEF",
    eh.DT_VERDEFNUM: "DT_VERDEFNUM",
    eh.DT_VERNEED: "DT_VERNEED",
    eh.DT_VERNEEDNUM: "DT_VERNEEDNUM",
    eh.OLD_DT_HIOS: "OLD_DT_HIOS",
    eh.DT_LOPROC: "DT_LOPROC",
    eh.DT_HIPROC: "DT_HIPROC",
}


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


PF = {
    eh.PF_R: "PF_R",
    eh.PF_W: "PF_W",
    eh.PF_X: "PF_X",
}


SHT = {
    eh.SHT_NULL: "SHT_NULL",
    eh.SHT_PROGBITS: "SHT_PROGBITS",
    eh.SHT_SYMTAB: "SHT_SYMTAB",
    eh.SHT_STRTAB: "SHT_STRTAB",
    eh.SHT_RELA: "SHT_RELA",
    eh.SHT_HASH: "SHT_HASH",
    eh.SHT_DYNAMIC: "SHT_DYNAMIC",
    eh.SHT_NOTE: "SHT_NOTE",
    eh.SHT_NOBITS: "SHT_NOBITS",
    eh.SHT_REL: "SHT_REL",
    eh.SHT_SHLIB: "SHT_SHLIB",
    eh.SHT_DYNSYM: "SHT_DYNSYM",
    eh.SHT_NUM: "SHT_NUM",
    eh.SHT_LOPROC: "SHT_LOPROC",
    eh.SHT_HIPROC: "SHT_HIPROC",
    eh.SHT_LOUSER: "SHT_LOUSER",
    eh.SHT_HIUSER: "SHT_HIUSER",
}


SHF = {
    eh.SHF_WRITE: "SHF_WRITE",
    eh.SHF_ALLOC: "SHF_ALLOC",
    eh.SHF_EXECINSTR: "SHF_EXECINSTR",
    eh.SHF_MASKPROC: "SHF_MASKPROC",
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


ELFCLASS = {
    eh.ELFCLASSNONE: "ELFCLASSNONE",
    eh.ELFCLASS32: "ELFCLASS32",
    eh.ELFCLASS64: "ELFCLASS64",
    eh.ELFCLASSNUM: "ELFCLASSNUM",
}


ELFDATA = {
    eh.ELFDATANONE: "ELFDATANONE",
    eh.ELFDATA2LSB: "ELFDATA2LSB",
    eh.ELFDATA2MSB: "ELFDATA2MSB",
}


EV = {
    eh.EV_NONE: "EV_NONE",
    eh.EV_CURRENT: "EV_CURRENT",
    eh.EV_NUM: "EV_NUM",
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
            offset = i * c.sizeof(self.Elf_Sym)
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
            yield ("f %s 0x%x @ 0x%x" % ("sym.%s.0x%x" % (s["name"], s["sect_off"] + s["offset"]),
                                         self.Elf_Sym_size, s["sect_off"] + s["offset"]))
            yield ("Cf %i %s @0x%x" % (self.Elf_Sym_size, self.Elf_Sym_fmt, s["sect_off"] + s["offset"]))

        yield "fs %s" % self.symstr_sect.strip(".")

        for s in self.symbols:
            yield ("f %s @ 0x%x" % ("str.%s.0x%x" % (s["name"], s["strsect_off"] + s["st_name"]),
                                    s["strsect_off"] + s["st_name"]))
            yield ("Cz @0x%x" % (s["strsect_off"] + s["st_name"]))


class ElfEhdr(u.R2Scriptable):
    def __init__(self, r2ob, elf_offset):
        super(ElfEhdr, self).__init__(r2ob)
        self.elf_offset = elf_offset
        self.elf_class = self._get_elf_class()

        if self.elf_class not in (eh.ELFCLASS32, eh.ELFCLASS64):
            raise NotSupportedError("Not Elf32 or Elf64")

        self.Elf_Ehdr = eh.Elf32_Ehdr if self.elf_class == eh.ELFCLASS32 else eh.Elf64_Ehdr
        self.Elf_Ehdr_size = c.sizeof(self.Elf_Ehdr)

        self.Elf_Ehdr_fmt = ("[16]c[2]E[2]Exxxxxwwwwww "
                             "e_ident (elf_type)e_type (elf_machine)e_machine e_version e_entry "
                             "e_phoff e_shoff e_flags e_ehsize e_phentsize "
                             "e_phnum e_shentsize e_shnum "
                             "e_shstrndx") if self.elf_class == eh.ELFCLASS32 else \
                            ("[16]c[2]E[2]Exqqqxwwwwww "
                             "e_ident (elf_type)e_type (elf_machine)e_machine e_version e_entry "
                             "e_phoff e_shoff e_flags e_ehsize e_phentsize "
                             "e_phnum e_shentsize e_shnum e_shstrndx")
        self.Elf_Ehdr_machine_enum_td = u.enum2td("elf_machine", EM)
        self.Elf_Ehdr_type_enum_td = u.enum2td("elf_type", ET)

        self._analyse()

    def _get_elf_class(self):
        a = self.r2ob.cmdj("pfj N1 @ %i"
                           % (self.elf_offset + eh.EI_CLASS))
        return a[0]["value"]

    def _analyse(self):
        elf_ehdr = u.bytes2str(self.r2ob.cmdj("pcj %i@%i" % (self.Elf_Ehdr_size, self.elf_offset)))
        elf_ehdr_c = c.create_string_buffer(elf_ehdr)
        ehdr = u.cast(elf_ehdr_c, 0, self.Elf_Ehdr)
        self.ehdr = OrderedDict([
            ("ei_class", self.elf_class,),
            ("ei_class_desc", ELFCLASS.get(self.elf_class, "N/A"),),
            ("e_type", ET[ehdr.e_type],),
            ("e_machine", EM[ehdr.e_machine],),
            ("e_version", EV[ehdr.e_version],),
            ("e_entry", ehdr.e_entry,),
            ("e_phoff", ehdr.e_phoff,),
            ("e_shoff", ehdr.e_shoff,),
            ("e_flags", ehdr.e_flags,),
            ("e_ehsize", ehdr.e_ehsize,),
            ("e_phentsize", ehdr.e_phentsize,),
            ("e_phnum", ehdr.e_phnum,),
            ("e_shentsize", ehdr.e_shentsize,),
            ("e_shnum", ehdr.e_shnum,),
            ("e_shstrndx", ehdr.e_shstrndx),
        ])

    def r2_commands(self):
        yield self.Elf_Ehdr_machine_enum_td
        yield self.Elf_Ehdr_type_enum_td
        yield "pf.Elf_Ehdr %s" % self.Elf_Ehdr_fmt

        yield "# Bug in:"
        yield ("# Cf %i %s @0x%x" % (self.Elf_Ehdr_size, self.Elf_Ehdr_fmt, self.elf_offset))


class ElfPhdr(u.R2Scriptable):
    def __init__(self, r2ob, elf_offset):
        super(ElfPhdr, self).__init__(r2ob)

        self.elf_offset = elf_offset
        self.ehdr = ElfEhdr(self.r2ob, self.elf_offset).ehdr

        self.phoff = self.elf_offset + self.ehdr["e_phoff"]
        self.phnum = self.ehdr["e_phnum"]

        self.elf_class = self.ehdr["ei_class"]
        self.Elf_Phdr = eh.Elf32_Phdr if self.elf_class == eh.ELFCLASS32 else eh.Elf64_Phdr
        self.Elf_Phdr_size = c.sizeof(self.Elf_Phdr)
        self.Elf_Phdr_fmt = ("[4]Exxxxxxx (phdr_type)p_type p_offset p_vaddr p_paddr p_filesz p_memsz "
                             "p_flags p_align") if self.elf_class == eh.ELFCLASS32 else \
                            ("[4]Exqqqqqq (phdr_type)p_type p_flags p_offset p_vaddr p_paddr "
                             "p_filesz p_memsz p_align")
        self.Elf_Phdr_pt_enum_td = u.enum2td("phdr_type", PT)

        self.segments = None
        self._analyse()

    def _parse_segments(self, segments):
        for s, o in segments:
            yield {
                "p_type": s.p_type,
                "p_offset": s.p_offset,
                "p_vaddr": s.p_vaddr,
                "p_paddr": s.p_paddr,
                "p_filesz": s.p_filesz,
                "p_memsz": s.p_memsz,
                "p_flags": s.p_flags,
                "p_align": s.p_align,
                "type": PT.get(s.p_type, s.p_type),
                "flags": "|".join([PF[i] for i in filter(lambda a: s.p_flags & a, PF)]),
                "hdr_offset": self.phoff + o
            }

    def _analyse(self):
        elf_phdr = u.bytes2str(self.r2ob.cmdj("pcj %i@%i" % (self.Elf_Phdr_size * self.phnum,
                                                             self.phoff)))
        elf_phdr_c = c.create_string_buffer(elf_phdr)
        segments_l = []
        for i in range(len(elf_phdr) / self.Elf_Phdr_size):
            offset = i * self.Elf_Phdr_size
            segments_l.append((u.cast(elf_phdr_c, offset, self.Elf_Phdr), offset))

        self.segments = [i for i in self._parse_segments(segments_l)]

    def r2_commands(self):
        yield self.Elf_Phdr_pt_enum_td
        yield "pf.Elf_Phdr %s" % self.Elf_Phdr_fmt

        for s in self.segments:
            yield ("Cf %i %s @0x%x" % (self.Elf_Phdr_size, self.Elf_Phdr_fmt, s["hdr_offset"]))


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
