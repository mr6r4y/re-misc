#-*- coding: utf-8 -*


__all__ = [

]


import ctypes as c


## These constants define the various ELF target machines
EM_NONE = 0
EM_M32 = 1
EM_SPARC = 2
EM_386 = 3
EM_68K = 4
EM_88K = 5
EM_486 = 6    # Perhaps disused
EM_860 = 7
EM_MIPS = 8   # MIPS R3000 (officially, big-endian only)
              # Next two are historical and binaries and
              # modules of these types will be rejected by
              # Linux.

EM_MIPS_RS3_LE = 10  # MIPS R3000 little-endian
EM_MIPS_RS4_BE = 10  # MIPS R4000 big-endian

EM_PARISC = 15   # HPPA
EM_SPARC32PLUS = 18   # Sun's "v8plus"
EM_PPC = 20   # PowerPC
EM_PPC64 = 21   # PowerPC64
EM_SPU = 23   # Cell BE SPU
EM_ARM = 40   # ARM 32 bit
EM_SH = 42   # SuperH
EM_SPARCV9 = 43   # SPARC v9 64-bit
EM_IA_64 = 50   # HP/Intel IA-64
EM_X86_64 = 62   # AMD x86-64
EM_S390 = 22   # IBM S/390
EM_CRIS = 76   # Axis Communications 32-bit embedded processor
EM_V850 = 87   # NEC v850
EM_M32R = 88   # Renesas M32R
EM_MN10300 = 89   # Panasonic/MEI MN10300, AM33
EM_BLACKFIN = 106   # ADI Blackfin Processor
EM_TI_C6000 = 140   # TI C6X DSPs
EM_AARCH64 = 183   # ARM 64 bit
EM_FRV = 0x5441   # Fujitsu FR-V
EM_AVR32 = 0x18ad   # Atmel AVR32

## This is an interim value that we will use until the committee comes
## up with a final number.
EM_ALPHA = 0x9026

## Bogus old v850 magic number, used by old tools.
EM_CYGNUS_V850 = 0x9080
## Bogus old m32r magic number, used by old tools.
EM_CYGNUS_M32R = 0x9041
## This is the old interim value for S/390 architecture
EM_S390_OLD = 0xA390
## Also Panasonic/MEI MN10300, AM33
EM_CYGNUS_MN10300 = 0xbeef


## 32-bit ELF base types.
Elf32_Addr = c.c_uint32
Elf32_Half = c.c_uint16
Elf32_Off = c.c_uint32
Elf32_Sword = c.c_int32
Elf32_Word = c.c_uint32

## 64-bit ELF base types.
Elf64_Addr = c.c_uint64
Elf64_Half = c.c_uint16
Elf64_SHalf = c.c_int16
Elf64_Off = c.c_uint64
Elf64_Sword = c.c_int32
Elf64_Word = c.c_uint32
Elf64_Xword = c.c_uint64
Elf64_Sxword = c.c_int64


## These constants are for the segment types stored in the image headers
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7    # Thread local storage segment
PT_LOOS = 0x60000000    # OS-specific
PT_HIOS = 0x6fffffff    # OS-specific
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_RELRO = 0x6474e552

PT_GNU_STACK = (PT_LOOS + 0x474e551)


##
## Extended Numbering
##
## If the real number of program header table entries is larger than
## or equal to PN_XNUM(0xffff), it is set to sh_info field of the
## section header at index 0, and PN_XNUM is set to e_phnum
## field. Otherwise, the section header at index 0 is zero
## initialized, if it exists.
##
## Specifications are available in:
##
## - Oracle: Linker and Libraries.
##   Part No: 817–1984–19, August 2011.
##   http://docs.oracle.com/cd/E18752_01/pdf/817-1984.pdf
##
## - System V ABI AMD64 Architecture Processor Supplement
##   Draft Version 0.99.4,
##   January 13, 2010.
##   http://www.cs.washington.edu/education/courses/cse351/12wi/supp-docs/abi.pdf
##
PN_XNUM = 0xffff

## These constants define the different elf file types
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_LOPROC = 0xff00
ET_HIPROC = 0xffff

## This is the info that is needed to parse the dynamic section of the file
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_BIND_NOW = 24                # Process relocations of object
DT_INIT_ARRAY = 25                # Array with addresses of init fct
DT_FINI_ARRAY = 26                # Array with addresses of fini fct
DT_INIT_ARRAYSZ = 27                # Size in bytes of DT_INIT_ARRAY
DT_FINI_ARRAYSZ = 28                # Size in bytes of DT_FINI_ARRAY
DT_RUNPATH = 29                # Library search path
DT_FLAGS = 30                # Flags for the object being loaded
DT_ENCODING = 32                # Start of encoded range
DT_PREINIT_ARRAY = 32                # Array with addresses of preinit fct
DT_PREINIT_ARRAYSZ = 33                # size in bytes of DT_PREINIT_ARRAY
DT_NUM = 34                # Number used
OLD_DT_LOOS = 0x60000000
DT_LOOS = 0x6000000d
DT_HIOS = 0x6ffff000
DT_VALRNGLO = 0x6ffffd00
DT_VALRNGHI = 0x6ffffdff
DT_ADDRRNGLO = 0x6ffffe00
DT_ADDRRNGHI = 0x6ffffeff
DT_VERSYM = 0x6ffffff0
DT_RELACOUNT = 0x6ffffff9
DT_RELCOUNT = 0x6ffffffa
DT_FLAGS_1 = 0x6ffffffb
DT_VERDEF = 0x6ffffffc
DT_VERDEFNUM = 0x6ffffffd
DT_VERNEED = 0x6ffffffe
DT_VERNEEDNUM = 0x6fffffff
OLD_DT_HIOS = 0x6fffffff
DT_LOPROC = 0x70000000
DT_HIPROC = 0x7fffffff
DT_GNU_HASH = 0x6ffffef5        # GNU-style hash table.
DT_TLSDESC_PLT = 0x6ffffef6
DT_TLSDESC_GOT = 0x6ffffef7
DT_GNU_CONFLICT = 0x6ffffef8        # Start of conflict section
DT_GNU_LIBLIST = 0x6ffffef9        # Library list
DT_CONFIG = 0x6ffffefa        # Configuration information.
DT_DEPAUDIT = 0x6ffffefb        # Dependency auditing.
DT_AUDIT = 0x6ffffefc        # Object auditing.
DT_PLTPAD = 0x6ffffefd        # PLT padding.
DT_MOVETAB = 0x6ffffefe        # Move table.


## This info is needed when parsing the symbol table
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6


def ELF_ST_BIND(x):
    return x >> 4


def ELF_ST_TYPE(x):
    return x & 0xf


def ELF32_ST_BIND(x):
    return ELF_ST_BIND(x)


def ELF32_ST_TYPE(x):
    return ELF_ST_TYPE(x)


def ELF64_ST_BIND(x):
    return ELF_ST_BIND(x)


def ELF64_ST_TYPE(x):
    return ELF_ST_TYPE(x)


class Elf32_Dyn(c.Structure):
    class _d_un(c.Union):
        _fields_ = [
            ("d_val", Elf32_Sword),
            ("d_ptr", Elf32_Addr),
        ]

    _fields_ = [
        ("d_tag", Elf32_Sword),
        ("d_un", _d_un),
    ]


class Elf64_Dyn(c.Structure):
    class _d_un(c.Union):
        _fields_ = [
            ("d_val", Elf64_Xword),
            ("d_ptr", Elf64_Addr),
        ]

    _fields_ = [
        ("d_tag", Elf64_Sxword),   # entry tag value
        ("d_un", _d_un),
    ]


## The following are used with relocations
def ELF32_R_SYM(x):
    return x >> 8


def ELF32_R_TYPE(x):
    return x & 0xff


## #define ELF64_R_SYM(i)          ((i) >> 32)
def ELF64_R_SYM(i):
    return i >> 32


def ELF64_R_TYPE(i):
    return i & 0xffffffff


class Elf32_Rel(c.Structure):
    _fields_ = [
        ("r_offset", Elf32_Addr),
        ("r_info", Elf64_Xword)
    ]


class Elf64_Rel(c.Structure):
    _fields_ = [
        ("r_offset", Elf64_Addr),  # Location at which to apply the action
        ("r_info", Elf64_Word)     # index and type of relocation
    ]


class Elf32_Rela(c.Structure):
    _fields_ = [
        ("r_offset", Elf32_Addr),
        ("r_info", Elf32_Word),
        ("r_addend", Elf32_Sword)
    ]


class Elf64_Rela(c.Structure):
    _fields_ = [
        ("r_offset", Elf64_Addr),    # Location at which to apply the action
        ("r_info", Elf64_Xword),     # index and type of relocation
        ("r_addend", Elf64_Sxword)   # Constant addend used to compute value
    ]


class Elf32_Sym(c.Structure):
    _fields_ = [
        ("st_name", Elf32_Word),
        ("st_value", Elf32_Addr),
        ("st_size", Elf32_Word),
        ("st_info", c.c_ubyte),
        ("st_other", c.c_ubyte),
        ("st_shndx", Elf32_Half),
    ]


class Elf64_Sym(c.Structure):
    _fields_ = [
        ("st_name", Elf64_Word),   # Symbol name, index in string tbl
        ("st_info", c.c_ubyte),    # Type and binding attributes
        ("st_other", c.c_ubyte),   # No defined meaning, 0
        ("st_shndx", Elf64_Half),  # Associated section index
        ("st_value", Elf64_Addr),  # Value of the symbol
        ("st_size", Elf64_Xword),  # Associated symbol size
    ]


EI_NIDENT = 16


class Elf32_Ehdr(c.Structure):
    _fields_ = [
        ("e_ident", c.c_ubyte * EI_NIDENT),
        ("e_type", Elf32_Half),
        ("e_machine", Elf32_Half),
        ("e_version", Elf32_Word),
        ("e_entry", Elf32_Addr),    # Entry point
        ("e_phoff", Elf32_Off),
        ("e_shoff", Elf32_Off),
        ("e_flags", Elf32_Word),
        ("e_ehsize", Elf32_Half),
        ("e_phentsize", Elf32_Half),
        ("e_phnum", Elf32_Half),
        ("e_shentsize", Elf32_Half),
        ("e_shnum", Elf32_Half),
        ("e_shstrndx", Elf32_Half),
    ]


class Elf64_Ehdr(c.Structure):
    _fields_ = [
        ("e_ident", c.c_ubyte * EI_NIDENT),  # ELF "magic number"
        ("e_type", Elf64_Half),
        ("e_machine", Elf64_Half),
        ("e_version", Elf64_Word),
        ("e_entry", Elf64_Addr),      # Entry point virtual address
        ("e_phoff", Elf64_Off),       # Program header table file offset
        ("e_shoff", Elf64_Off),       # Section header table file offset
        ("e_flags", Elf64_Word),
        ("e_ehsize", Elf64_Half),
        ("e_phentsize", Elf64_Half),
        ("e_phnum", Elf64_Half),
        ("e_shentsize", Elf64_Half),
        ("e_shnum", Elf64_Half),
        ("e_shstrndx", Elf64_Half),
    ]


## These constants define the permissions on sections in the program
## header, p_flags.
PF_R = 0x4
PF_W = 0x2
PF_X = 0x1


class Elf32_Phdr(c.Structure):
    _fields_ = [
        ("p_type", Elf32_Word),
        ("p_offset", Elf32_Off),
        ("p_vaddr", Elf32_Addr),
        ("p_paddr", Elf32_Addr),
        ("p_filesz", Elf32_Word),
        ("p_memsz", Elf32_Word),
        ("p_flags", Elf32_Word),
        ("p_align", Elf32_Word),
    ]


class Elf64_Phdr(c.Structure):
    _fields_ = [
        ("p_type", Elf64_Word),
        ("p_flags", Elf64_Word),
        ("p_offset", Elf64_Off),
        ("p_vaddr", Elf64_Addr),
        ("p_paddr", Elf64_Addr),
        ("p_filesz", Elf64_Xword),
        ("p_memsz", Elf64_Xword),
        ("p_align", Elf64_Xword),
    ]


## sh_type
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_NUM = 12
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7fffffff
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0xffffffff

## sh_flags
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_MASKPROC = 0xf0000000


## special section indexes
SHN_UNDEF = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC = 0xff00
SHN_HIPROC = 0xff1f
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2
SHN_HIRESERVE = 0xffff


class Elf32_Shdr(c.Structure):
    _fields_ = [
        ("sh_name", Elf32_Word),
        ("sh_type", Elf32_Word),
        ("sh_flags", Elf32_Word),
        ("sh_addr", Elf32_Addr),
        ("sh_offset", Elf32_Off),
        ("sh_size", Elf32_Word),
        ("sh_link", Elf32_Word),
        ("sh_info", Elf32_Word),
        ("sh_addralign", Elf32_Word),
        ("sh_entsize", Elf32_Word),
    ]


class Elf64_Shdr(c.Structure):
    _fields_ = [
        ("sh_name", Elf64_Word),      # Section name, index in string tbl
        ("sh_type", Elf64_Word),      # Type of section
        ("sh_flags", Elf64_Xword),      # Miscellaneous section attributes
        ("sh_addr", Elf64_Addr),      # Section virtual addr at execution
        ("sh_offset", Elf64_Off),      # Section file offset
        ("sh_size", Elf64_Xword),      # Size of section in bytes
        ("sh_link", Elf64_Word),      # Index of another section
        ("sh_info", Elf64_Word),      # Additional section information
        ("sh_addralign", Elf64_Xword),      # Section alignment
        ("sh_entsize", Elf64_Xword),      # Entry size if section holds table
    ]


EI_MAG0 = 0       # e_ident[] indexes
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7
EI_PAD = 8

ELFMAG0 = 0x7f        # EI_MAG
ELFMAG1 = 'E'
ELFMAG2 = 'L'
ELFMAG3 = 'F'
ELFMAG = "\177ELF"
SELFMAG = 4

ELFCLASSNONE = 0       # EI_CLASS
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFCLASSNUM = 3

ELFDATANONE = 0       # e_ident[EI_DATA]
ELFDATA2LSB = 1
ELFDATA2MSB = 2

EV_NONE = 0       # e_version, EI_VERSION
EV_CURRENT = 1
EV_NUM = 2

ELFOSABI_NONE = 0
ELFOSABI_LINUX = 3

#ifndef ELF_OSABI
#define ELF_OSABI ELFOSABI_NONE
#endif

##
## Notes used in ET_CORE. Architectures export some of the arch register sets
## using the corresponding note types via the PTRACE_GETREGSET and
## PTRACE_SETREGSET requests.
##
NT_PRSTATUS = 1
NT_PRFPREG = 2
NT_PRPSINFO = 3
NT_TASKSTRUCT = 4
NT_AUXV = 6


##
## Note to userspace developers: size of NT_SIGINFO note may increase
## in the future to accomodate more fields, don't assume it is fixed!
##
NT_SIGINFO = 0x53494749
NT_FILE = 0x46494c45
NT_PRXFPREG = 0x46e62b7f      # copied from gdb5.1/include/elf/common.h
NT_PPC_VMX = 0x100       # PowerPC Altivec/VMX registers
NT_PPC_SPE = 0x101       # PowerPC SPE/EVR registers
NT_PPC_VSX = 0x102       # PowerPC VSX registers
NT_386_TLS = 0x200       # i386 TLS slots (struct user_desc)
NT_386_IOPERM = 0x201       # x86 io permission bitmap (1=deny)
NT_X86_XSTATE = 0x202       # x86 extended state using xsave
NT_S390_HIGH_GPRS = 0x300   # s390 upper register halves
NT_S390_TIMER = 0x301       # s390 timer register
NT_S390_TODCMP = 0x302       # s390 TOD clock comparator register
NT_S390_TODPREG = 0x303       # s390 TOD programmable register
NT_S390_CTRS = 0x304       # s390 control registers
NT_S390_PREFIX = 0x305       # s390 prefix register
NT_S390_LAST_BREAK = 0x306   # s390 breaking event address
NT_S390_SYSTEM_CALL = 0x307   # s390 system call restart data
NT_S390_TDB = 0x308       # s390 transaction diagnostic block
NT_ARM_VFP = 0x400       # ARM VFP/NEON registers
NT_ARM_TLS = 0x401       # ARM TLS register
NT_ARM_HW_BREAK = 0x402       # ARM hardware breakpoint registers
NT_ARM_HW_WATCH = 0x403       # ARM hardware watchpoint registers
NT_METAG_CBUF = 0x500       # Metag catch buffer registers
NT_METAG_RPIPE = 0x501       # Metag read pipeline state
NT_METAG_TLS = 0x502       # Metag TLS pointer


## Note header in a PT_NOTE section
class Elf32_Nhdr(c.Structure):
    _fields_ = [
        ("n_namesz", Elf32_Word),    # Name size
        ("n_descsz", Elf32_Word),    # Content size
        ("n_type", Elf32_Word),      # Content type
    ]


## Note header in a PT_NOTE section
class Elf64_Nhdr(c.Structure):
    _fields_ = [
        ("n_namesz", Elf64_Word),    # Name size
        ("n_descsz", Elf64_Word),    # Content size
        ("n_type", Elf64_Word),      # Content type
    ]
