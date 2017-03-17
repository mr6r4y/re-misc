#-*- coding: utf-8 -*


__all__ = [

]


import ctypes as c


# /* 32-bit ELF base types. */
# typedef __u32   Elf32_Addr;
# typedef __u16   Elf32_Half;
# typedef __u32   Elf32_Off;
# typedef __s32   Elf32_Sword;
# typedef __u32   Elf32_Word;

# /* 64-bit ELF base types. */
# typedef __u64   Elf64_Addr;
# typedef __u16   Elf64_Half;
# typedef __s16   Elf64_SHalf;
# typedef __u64   Elf64_Off;
# typedef __s32   Elf64_Sword;
# typedef __u32   Elf64_Word;
# typedef __u64   Elf64_Xword;
# typedef __s64   Elf64_Sxword;

Elf32_Addr = c.c_uint32
Elf32_Half = c.c_uint16
Elf32_Off = c.c_uint32
Elf32_Sword = c.c_int32
Elf32_Word = c.c_uint32

Elf64_Addr = c.c_uint64
Elf64_Half = c.c_uint16
Elf64_SHalf = c.c_int16
Elf64_Off = c.c_uint64
Elf64_Sword = c.c_int32
Elf64_Word = c.c_uint32
Elf64_Xword = c.c_uint64
Elf64_Sxword = c.c_int64


# /* These constants are for the segment types stored in the image headers */
# #define PT_NULL    0
# #define PT_LOAD    1
# #define PT_DYNAMIC 2
# #define PT_INTERP  3
# #define PT_NOTE    4
# #define PT_SHLIB   5
# #define PT_PHDR    6
# #define PT_TLS     7               /* Thread local storage segment */
# #define PT_LOOS    0x60000000      /* OS-specific */
# #define PT_HIOS    0x6fffffff      /* OS-specific */
# #define PT_LOPROC  0x70000000
# #define PT_HIPROC  0x7fffffff
# #define PT_GNU_EH_FRAME     0x6474e550

# #define PT_GNU_STACK    (PT_LOOS + 0x474e551)

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_LOOS = 0x60000000
PT_HIOS = 0x6fffffff
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff
PT_GNU_EH_FRAME = 0x6474e550

PT_GNU_STACK = (PT_LOOS + 0x474e551)


# /* This info is needed when parsing the symbol table */
# #define STB_LOCAL  0
# #define STB_GLOBAL 1
# #define STB_WEAK   2

# #define STT_NOTYPE  0
# #define STT_OBJECT  1
# #define STT_FUNC    2
# #define STT_SECTION 3
# #define STT_FILE    4
# #define STT_COMMON  5
# #define STT_TLS     6

# #define ELF_ST_BIND(x)      ((x) >> 4)
# #define ELF_ST_TYPE(x)      (((unsigned int) x) & 0xf)
# #define ELF32_ST_BIND(x)    ELF_ST_BIND(x)
# #define ELF32_ST_TYPE(x)    ELF_ST_TYPE(x)
# #define ELF64_ST_BIND(x)    ELF_ST_BIND(x)
# #define ELF64_ST_TYPE(x)    ELF_ST_TYPE(x)

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


# typedef struct elf32_sym{
#   Elf32_Word    st_name;
#   Elf32_Addr    st_value;
#   Elf32_Word    st_size;
#   unsigned char st_info;
#   unsigned char st_other;
#   Elf32_Half    st_shndx;
# } Elf32_Sym;

class Elf32_Sym(c.Structure):
    _fields_ = [
        ("st_name", Elf32_Word),
        ("st_value", Elf32_Addr),
        ("st_size", Elf32_Word),
        ("st_info", c.c_ubyte),
        ("st_other", c.c_ubyte),
        ("st_shndx", Elf32_Half),
    ]


# typedef struct elf64_sym {
#   Elf64_Word st_name;       /* Symbol name, index in string tbl */
#   unsigned char st_info;    /* Type and binding attributes */
#   unsigned char st_other;   /* No defined meaning, 0 */
#   Elf64_Half st_shndx;      /* Associated section index */
#   Elf64_Addr st_value;      /* Value of the symbol */
#   Elf64_Xword st_size;      /* Associated symbol size */
# } Elf64_Sym;

class Elf64_Sym(c.Structure):
    _fields_ = [
        ("st_name", Elf64_Word),
        ("st_info", c.c_ubyte),
        ("st_other", c.c_ubyte),
        ("st_shndx", Elf64_Half),
        ("st_value", Elf64_Addr),
        ("st_size", Elf64_Xword),
    ]


# /* special section indexes */
# #define SHN_UNDEF   0
# #define SHN_LORESERVE   0xff00
# #define SHN_LOPROC  0xff00
# #define SHN_HIPROC  0xff1f
# #define SHN_ABS     0xfff1
# #define SHN_COMMON  0xfff2
# #define SHN_HIRESERVE   0xffff

SHN_UNDEF = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC = 0xff00
SHN_HIPROC = 0xff1f
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2
SHN_HIRESERVE = 0xffff
