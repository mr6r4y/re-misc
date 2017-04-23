

import ctypes as c

import lin_hh.elf_h as eh
import utils as u
from collections import OrderedDict


__all__ = []


class NotSupportedError(StandardError):
    pass


class ImpossibleExecutableError(StandardError):
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
    eh.DT_BIND_NOW: "DT_BIND_NOW",
    eh.DT_INIT_ARRAY: "DT_INIT_ARRAY",
    eh.DT_FINI_ARRAY: "DT_FINI_ARRAY",
    eh.DT_INIT_ARRAYSZ: "DT_INIT_ARRAYSZ",
    eh.DT_FINI_ARRAYSZ: "DT_FINI_ARRAYSZ",
    eh.DT_RUNPATH: "DT_RUNPATH",
    eh.DT_FLAGS: "DT_FLAGS",
    eh.DT_ENCODING: "DT_ENCODING",
    eh.DT_PREINIT_ARRAY: "DT_PREINIT_ARRAY",
    eh.DT_PREINIT_ARRAYSZ: "DT_PREINIT_ARRAYSZ",
    eh.DT_NUM: "DT_NUM",
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
    eh.DT_GNU_HASH: "DT_GNU_HASH",
    eh.DT_TLSDESC_PLT: "DT_TLSDESC_PLT",
    eh.DT_TLSDESC_GOT: "DT_TLSDESC_GOT",
    eh.DT_GNU_CONFLICT: "DT_GNU_CONFLICT",
    eh.DT_GNU_LIBLIST: "DT_GNU_LIBLIST",
    eh.DT_CONFIG: "DT_CONFIG",
    eh.DT_DEPAUDIT: "DT_DEPAUDIT",
    eh.DT_AUDIT: "DT_AUDIT",
    eh.DT_PLTPAD: "DT_PLTPAD",
    eh.DT_MOVETAB: "DT_MOVETAB",
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
    eh.ELFDATA2LSB: "ELFDATA2LSB",       # Little endian 2's complement
    eh.ELFDATA2MSB: "ELFDATA2MSB",       # Big endian 2's complement
}


EV = {
    eh.EV_NONE: "EV_NONE",
    eh.EV_CURRENT: "EV_CURRENT",
    eh.EV_NUM: "EV_NUM",
}

R32 = {
    eh.R_386_NONE: "R_386_NONE",
    eh.R_386_32: "R_386_32",
    eh.R_386_PC32: "R_386_PC32",
    eh.R_386_GOT32: "R_386_GOT32",
    eh.R_386_PLT32: "R_386_PLT32",
    eh.R_386_COPY: "R_386_COPY",
    eh.R_386_GLOB_DAT: "R_386_GLOB_DAT",
    eh.R_386_JMP_SLOT: "R_386_JMP_SLOT",
    eh.R_386_RELATIVE: "R_386_RELATIVE",
    eh.R_386_GOTOFF: "R_386_GOTOFF",
    eh.R_386_GOTPC: "R_386_GOTPC",
    eh.R_386_NUM: "R_386_NUM",
}

R64 = {
    eh.R_X86_64_NONE: "R_X86_64_NONE",
    eh.R_X86_64_64: "R_X86_64_64",
    eh.R_X86_64_PC32: "R_X86_64_PC32",
    eh.R_X86_64_GOT32: "R_X86_64_GOT32",
    eh.R_X86_64_PLT32: "R_X86_64_PLT32",
    eh.R_X86_64_COPY: "R_X86_64_COPY",
    eh.R_X86_64_GLOB_DAT: "R_X86_64_GLOB_DAT",
    eh.R_X86_64_JUMP_SLOT: "R_X86_64_JUMP_SLOT",
    eh.R_X86_64_RELATIVE: "R_X86_64_RELATIVE",
    eh.R_X86_64_GOTPCREL: "R_X86_64_GOTPCREL",
    eh.R_X86_64_32: "R_X86_64_32",
    eh.R_X86_64_32S: "R_X86_64_32S",
    eh.R_X86_64_16: "R_X86_64_16",
    eh.R_X86_64_PC16: "R_X86_64_PC16",
    eh.R_X86_64_8: "R_X86_64_8",
    eh.R_X86_64_PC8: "R_X86_64_PC8",
    eh.R_X86_64_NUM: "R_X86_64_NUM",
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
        self.Elf_Sym_shn_enum_td = u.enum2tk("elf_shn", SHN)
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
        for i in self.Elf_Sym_shn_enum_td:
            yield i

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
        self.Elf_Ehdr_machine_enum_td = u.enum2tk("elf_machine", EM)
        self.Elf_Ehdr_type_enum_td = u.enum2tk("elf_type", ET)

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
        for i in self.Elf_Ehdr_machine_enum_td:
            yield i

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
        self.Elf_Phdr_pt_enum_td = u.enum2tk("phdr_type", PT)

        self.phdrs = None
        self._analyse()

    def _parse_segments(self, phdrs):
        for s, o in phdrs:
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

        self.phdrs = [i for i in self._parse_segments(segments_l)]

    def r2_commands(self):
        for i in self.Elf_Phdr_pt_enum_td:
            yield i

        yield "pf.Elf_Phdr %s" % self.Elf_Phdr_fmt

        yield "fs phdr"

        for s in self.phdrs:
            yield ("f %s 0x%x @ 0x%x" % ("phdr.%s.0x%x" % (s["type"], s["hdr_offset"]),
                                         self.Elf_Phdr_size, s["hdr_offset"]))
            yield ("Cf %i %s @0x%x" % (self.Elf_Phdr_size, self.Elf_Phdr_fmt, s["hdr_offset"]))


class ElfRel(u.R2Scriptable):
    def __init__(self, r2ob, elf_offset):
        super(ElfRel, self).__init__(r2ob)

        self.elf_offset = elf_offset
        self.ehdr = ElfEhdr(self.r2ob, self.elf_offset).ehdr
        self.dyns = ElfDyn(self.r2ob, self.elf_offset).dyns

        self.elf_class = self.ehdr["ei_class"]
        self.relocs = []

        self.Elf_Rel = eh.Elf32_Rel if self.elf_class == eh.ELFCLASS32 else eh.Elf64_Rel
        self.Elf_Rel_size = c.sizeof(self.Elf_Rel)
        self.Elf_Rela = eh.Elf32_Rela if self.elf_class == eh.ELFCLASS32 else eh.Elf64_Rela
        self.Elf_Rela_size = c.sizeof(self.Elf_Rela)
        self.r_sym = eh.ELF32_R_SYM if self.elf_class == eh.ELFCLASS32 else eh.ELF64_R_SYM
        self.r_type = eh.ELF32_R_TYPE if self.elf_class == eh.ELFCLASS32 else eh.ELF64_R_TYPE
        self.r_type_enum = R32 if self.elf_class == eh.ELFCLASS32 else R64
        self.r_type_enum_td = u.enum2tk("elf_reloc_type", self.r_type_enum)

        self.Elf_Rel_fmt = "xq r_offset r_info" if self.elf_class == eh.ELFCLASS32 else "qx r_offset r_info"
        self.Elf_Rela_fmt = "xxx r_offset r_info r_addend"\
                            if self.elf_class == eh.ELFCLASS32 else\
                            "qqq r_offset r_info r_addend"

        self.relocs = []

        if self.dyns:
            self.relsz = filter(lambda a: a["d_tag"] == eh.DT_RELSZ, self.dyns)
            self.relasz = filter(lambda a: a["d_tag"] == eh.DT_RELASZ, self.dyns)
            self.rel = filter(lambda a: a["d_tag"] == eh.DT_REL, self.dyns)
            self.rela = filter(lambda a: a["d_tag"] == eh.DT_RELA, self.dyns)

            if self.relsz:
                self._analyse_reln()
            if self.relasz:
                self._analyse_reln(addend=True)

    def _parse_reln(self, rels, addend=False):
        for r, o in rels:
            yield {
                "offset": o,
                "r_offset": r.r_offset,
                "r_info": r.r_info,
                "r_addend": None if not addend else r.r_addend,
                "r_sym": self.r_sym(r.r_info),
                "r_type": self.r_type_enum.get(self.r_type(r.r_info), r.r_info)
            }

    def _analyse_reln(self, addend=False):
        r_c = self.relsz[0]["d_val"] if not addend else self.relasz[0]["d_val"]
        v_addr = self.rel[0]["d_ptr"] if not addend else self.rela[0]["d_ptr"]
        sz = self.Elf_Rel_size if not addend else self.Elf_Rela_size
        reln = self.Elf_Rel if not addend else self.Elf_Rela

        relocs = u.bytes2str(self.r2ob.cmdj("pcj %i@%i" % (sz * r_c,
                                                           v_addr)))
        relocs_c = c.create_string_buffer(relocs)

        rels = []
        for i in range(len(relocs) / sz):
            offset = i * sz
            rels.append((u.cast(relocs_c, offset, reln), v_addr + offset))

        for i in self._parse_reln(rels, addend):
            self.relocs.append(i)

    def r2_commands(self):
        for i in self.r_type_enum_td:
            yield i

        yield "pf.Elf_Rel %s" % self.Elf_Rel_fmt
        yield "pf.Elf_Rela %s" % self.Elf_Rela_fmt


class ElfDyn(u.R2Scriptable):
    def __init__(self, r2ob, elf_offset):
        super(ElfDyn, self).__init__(r2ob)

        self.elf_offset = elf_offset
        self.ehdr = ElfEhdr(self.r2ob, self.elf_offset).ehdr
        self.phdrs = ElfPhdr(self.r2ob, self.elf_offset).phdrs

        dphdrs = filter(lambda a: a["p_type"] == eh.PT_DYNAMIC, self.phdrs)

        self.dyn_phdr = dphdrs[0] if dphdrs else None

        self.dyns = []

        if self.dyn_phdr:
            self.dynseg_off = elf_offset + self.dyn_phdr["p_offset"]
            self.dynseg_size = self.dyn_phdr["p_filesz"]

            self.elf_class = self.ehdr["ei_class"]
            self.Elf_Dyn = eh.Elf32_Dyn if self.elf_class == eh.ELFCLASS32 else eh.Elf64_Dyn
            self.Elf_Dyn_size = c.sizeof(self.Elf_Dyn)
            self.Elf_Dyn_num = self.dynseg_size / self.Elf_Dyn_size

            self.dt_type_enum_td = u.enum2tk("elf_dt_type", DT)

            self.Elf_Dyn_fmt = ("[4]Ex (elf_dt_type)d_tag d_val_addr")\
                               if self.elf_class == eh.ELFCLASS32 else\
                               ("[8]Eq (elf_dt_type)d_tag d_val_addr")

            self._analyse()

    def _parse_dyns(self, dyns):
        for s, o in dyns:
            yield {
                "offset": self.dynseg_off + o,
                "d_tag": s.d_tag,
                "d_val": s.d_un.d_val,
                "d_ptr": s.d_un.d_ptr,
                "tag": DT.get(s.d_tag, "UNKNOWN")
            }

    def _analyse(self):
        elf_dyn = u.bytes2str(self.r2ob.cmdj("pcj %i@%i" % (self.Elf_Dyn_size * self.Elf_Dyn_num,
                                                            self.dynseg_off)))
        elf_dyn_c = c.create_string_buffer(elf_dyn)

        dyns = []
        for i in range(len(elf_dyn) / self.Elf_Dyn_size):
            offset = i * self.Elf_Dyn_size
            dyns.append((u.cast(elf_dyn_c, offset, self.Elf_Dyn), offset))

        self.dyns = [i for i in self._parse_dyns(dyns)]

    def r2_commands(self):
        for i in self.dt_type_enum_td:
            yield i

        yield "pf.Elf_Dyn %s" % self.Elf_Dyn_fmt

        yield "fs dyn"

        for s in self.dyns:
            yield ("f %s 0x%x @ 0x%x" % ("dyn.%s.0x%x" % (s["tag"], s["offset"]),
                                         self.Elf_Dyn_size, s["offset"]))
            yield ("Cf %i %s @0x%x" % (self.Elf_Dyn_size, self.Elf_Dyn_fmt, s["offset"]))


def get_ldd(r2ob, dyn_ob):
    needed = filter(lambda a: a["d_tag"] == eh.DT_NEEDED, dyn_ob.dyns)
    strtab = filter(lambda a: a["d_tag"] == eh.DT_STRTAB, dyn_ob.dyns)
    if strtab:
        strtab_v_adr = strtab[0]["d_ptr"]
        for i in needed:
            str_v_adr = strtab_v_adr + i["d_val"]
            cm = "ps @ 0x%x" % str_v_adr
            yield r2ob.cmd(cm)
