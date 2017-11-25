#-*- coding: utf-8 -*


__all__ = [

]


import ctypes as c
import intsafe_h as ih


MINCHAR = 0x80
MAXCHAR = 0x7f
MINSHORT = 0x8000
MAXSHORT = 0x7fff
MINLONG = 0x80000000
MAXLONG = 0x7fffffff
MAXBYTE = 0xff
MAXWORD = 0xffff
MAXDWORD = 0xfffffff


IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_OS2_SIGNATURE = 0x454C  # NE
IMAGE_OS2_SIGNATURE_LE = 0x4E45  # LE
IMAGE_NT_SIGNATURE = 0x00004550  # PE00


IMAGE_SIZEOF_FILE_HEADER = 20

IMAGE_FILE_RELOCS_STRIPPED = 0x0001  # Relocation info stripped from file.
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002  # File is executable  (i.e. no unresolved externel references).
IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004  # Line nunbers stripped from file.
IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008  # Local symbols stripped from file.
IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010  # Agressively trim working set
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020  # App can handle >2gb addresses
IMAGE_FILE_BYTES_REVERSED_LO = 0x0080  # Bytes of machine word are reversed.
IMAGE_FILE_32BIT_MACHINE = 0x0100  # 32 bit word machine.
IMAGE_FILE_DEBUG_STRIPPED = 0x0200  # Debugging info stripped from file in .DBG file
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400  # If Image is on removable media, copy and run from the swap file.
IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800  # If Image is on Net, copy and run from the swap file.
IMAGE_FILE_SYSTEM = 0x1000  # System File.
IMAGE_FILE_DLL = 0x2000  # File is a DLL.
IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000  # File should only be run on a UP machine
IMAGE_FILE_BYTES_REVERSED_HI = 0x8000  # Bytes of machine word are reversed.

IMAGE_FILE_MACHINE_UNKNOWN = 0
IMAGE_FILE_MACHINE_I386 = 0x014c  # Intel 386.
IMAGE_FILE_MACHINE_R3000 = 0x0162  # MIPS little-endian, 0x160 big-endian
IMAGE_FILE_MACHINE_R4000 = 0x0166  # MIPS little-endian
IMAGE_FILE_MACHINE_R10000 = 0x0168  # MIPS little-endian
IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169  # MIPS little-endian WCE v2
IMAGE_FILE_MACHINE_ALPHA = 0x0184  # Alpha_AXP
IMAGE_FILE_MACHINE_SH3 = 0x01a2  # SH3 little-endian
IMAGE_FILE_MACHINE_SH3DSP = 0x01a3
IMAGE_FILE_MACHINE_SH3E = 0x01a4  # SH3E little-endian
IMAGE_FILE_MACHINE_SH4 = 0x01a6  # SH4 little-endian
IMAGE_FILE_MACHINE_SH5 = 0x01a8  # SH5
IMAGE_FILE_MACHINE_ARM = 0x01c0  # ARM Little-Endian
IMAGE_FILE_MACHINE_THUMB = 0x01c2
IMAGE_FILE_MACHINE_AM33 = 0x01d3
IMAGE_FILE_MACHINE_POWERPC = 0x01F0  # IBM PowerPC Little-Endian
IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1
IMAGE_FILE_MACHINE_IA64 = 0x0200  # Intel 64
IMAGE_FILE_MACHINE_MIPS16 = 0x0266  # MIPS
IMAGE_FILE_MACHINE_ALPHA64 = 0x0284  # ALPHA64
IMAGE_FILE_MACHINE_MIPSFPU = 0x0366  # MIPS
IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466  # MIPS
IMAGE_FILE_MACHINE_AXP64 = IMAGE_FILE_MACHINE_ALPHA64
IMAGE_FILE_MACHINE_TRICORE = 0x0520  # Infineon
IMAGE_FILE_MACHINE_CEF = 0x0CEF
IMAGE_FILE_MACHINE_EBC = 0x0EBC  # EFI Byte Code
IMAGE_FILE_MACHINE_AMD64 = 0x8664  # AMD64 (K8)
IMAGE_FILE_MACHINE_M32R = 0x9041  # M32R little-endian
IMAGE_FILE_MACHINE_CEE = 0xC0EE


IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16


# Subsystem Values
IMAGE_SUBSYSTEM_UNKNOWN = 0  # Unknown subsystem.
IMAGE_SUBSYSTEM_NATIVE = 1  # Image doesn't require a subsystem.
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2  # Image runs in the Windows GUI subsystem.
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3  # Image runs in the Windows character subsystem.
IMAGE_SUBSYSTEM_OS2_CUI = 5  # image runs in the OS/2 character subsystem.
IMAGE_SUBSYSTEM_POSIX_CUI = 7  # image runs in the Posix character subsystem.
IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8  # image is a native Win9x driver.
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9  # Image runs in the Windows CE subsystem.
IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
IMAGE_SUBSYSTEM_EFI_ROM = 13
IMAGE_SUBSYSTEM_XBOX = 14
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16

# DllCharacteristics Entries
#      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
#      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
#      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
#      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040  # DLL can move.
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080  # Code Integrity Image
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100  # Image is NX compatible
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200  # Image understands isolation and doesn't want it
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400  # Image does not use SEH.  No SE handler may reside in this image
IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800  # Do not bind this image.
#                                            0x1000     // Reserved.
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000  # Driver uses WDM model
#                                            0x4000     // Reserved.
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

# Directory Entries
IMAGE_DIRECTORY_ENTRY_EXPORT = 0  # Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT = 1  # Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2  # Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3  # Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY = 4  # Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5  # Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG = 6  # Debug Directory
# DIRECTORY_ENTRY_COPYRIGHT = 7  # X86 usage)
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7  # Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8  # RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS = 9  # TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10  # Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11  # Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT = 12  # Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13  # Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14  # COM Runtime descriptor


# Section Header Format
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_SIZEOF_SECTION_HEADER = 40


# Section characteristics.
#      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
#      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
#      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
#      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
IMAGE_SCN_TYPE_NO_PAD = 0x00000008  # Reserved.
#      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

IMAGE_SCN_CNT_CODE = 0x00000020  # Section contains code.
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040  # Section contains initialized data.
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080  # Section contains uninitialized data.

IMAGE_SCN_LNK_OTHER = 0x00000100  # Reserved.
IMAGE_SCN_LNK_INFO = 0x00000200  # Section contains comments or some other type of information.
#      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
IMAGE_SCN_LNK_REMOVE = 0x00000800  # Section contents will not become part of image.
IMAGE_SCN_LNK_COMDAT = 0x00001000  # Section contents comdat.
#                                           0x00002000  // Reserved.
#      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000  # Reset speculative exceptions handling bits in the TLB entries for this section.
IMAGE_SCN_GPREL = 0x00008000  # Section content can be accessed relative to GP
IMAGE_SCN_MEM_FARDATA = 0x00008000
#      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
IMAGE_SCN_MEM_PURGEABLE = 0x00020000
IMAGE_SCN_MEM_16BIT = 0x00020000
IMAGE_SCN_MEM_LOCKED = 0x00040000
IMAGE_SCN_MEM_PRELOAD = 0x00080000

IMAGE_SCN_ALIGN_1BYTES = 0x00100000
IMAGE_SCN_ALIGN_2BYTES = 0x00200000
IMAGE_SCN_ALIGN_4BYTES = 0x00300000
IMAGE_SCN_ALIGN_8BYTES = 0x00400000
IMAGE_SCN_ALIGN_16BYTES = 0x00500000  # Default alignment if no others are specified.
IMAGE_SCN_ALIGN_32BYTES = 0x00600000
IMAGE_SCN_ALIGN_64BYTES = 0x00700000
IMAGE_SCN_ALIGN_128BYTES = 0x00800000
IMAGE_SCN_ALIGN_256BYTES = 0x00900000
IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
# Unused                                    0x00F00000
IMAGE_SCN_ALIGN_MASK = 0x00F00000

IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000  # Section contains extended relocations.
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000  # Section can be discarded.
IMAGE_SCN_MEM_NOT_CACHED = 0x04000000  # Section is not cachable.
IMAGE_SCN_MEM_NOT_PAGED = 0x08000000  # Section is not pageable.
IMAGE_SCN_MEM_SHARED = 0x10000000  # Section is shareable.
IMAGE_SCN_MEM_EXECUTE = 0x20000000  # Section is executable.
IMAGE_SCN_MEM_READ = 0x40000000  # Section is readable.
IMAGE_SCN_MEM_WRITE = 0x80000000  # Section is writeable.

# TLS Chaacteristic Flags
IMAGE_SCN_SCALE_INDEX = 0x00000001  # Tls index is scaled


# # Section values.
# #
# # Symbols have a section number of the section in which they are
# # defined. Otherwise, section numbers have the following meanings:

# IMAGE_SYM_UNDEFINED = SHORT(0)  # Symbol is undefined or is common.
# IMAGE_SYM_ABSOLUTE = SHORT(-1)  # Symbol is an absolute value.
# IMAGE_SYM_DEBUG = SHORT(-2)  # Symbol is a special debug item.
# IMAGE_SYM_SECTION_MAX =  0xFEFF # Values 0xFF00-0xFFFF are special
# IMAGE_SYM_SECTION_MAX_EX = MAXLONG


IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
IMAGE_ORDINAL_FLAG32 = 0x80000000


class IMAGE_DOS_HEADER(c.Structure):
    _pack_ = 1
    _fields_ = [
        ("e_magic", ih.WORD),  # Magic number
        ("e_cblp", ih.WORD),  # Bytes on last page of file
        ("e_cp", ih.WORD),  # Pages in file
        ("e_crlc", ih.WORD),  # Relocations
        ("e_cparhdr", ih.WORD),  # Size of header in paragraphs
        ("e_minalloc", ih.WORD),  # Minimum extra paragraphs needed
        ("e_maxalloc", ih.WORD),  # Maximum extra paragraphs needed
        ("e_ss", ih.WORD),  # Initial (relative) SS value
        ("e_sp", ih.WORD),  # Initial SP value
        ("e_csum", ih.WORD),  # Checksum
        ("e_ip", ih.WORD),  # Initial IP value
        ("e_cs", ih.WORD),  # Initial (relative) CS value
        ("e_lfarlc", ih.WORD),  # File address of relocation table
        ("e_ovno", ih.WORD),  # Overlay number
        ("e_res", ih.WORD*4),  # Reserved words
        ("e_oemid", ih.WORD),  # OEM identifier (for e_oeminfo)
        ("e_oeminfo", ih.WORD),  # OEM information; e_oemid specific
        ("e_res2", ih.WORD*10),  # Reserved words
        ("e_lfanew", ih.LONG),  # File address of new exe header
    ]


class IMAGE_FILE_HEADER(c.Structure):
    _fields_ = [
        ("Machine", ih.WORD),
        ("NumberOfSections", ih.WORD),
        ("TimeDateStamp", ih.DWORD),
        ("PointerToSymbolTable", ih.DWORD),
        ("NumberOfSymbols", ih.DWORD),
        ("SizeOfOptionalHeader", ih.WORD),
        ("Characteristics", ih.WORD),
    ]


class IMAGE_DATA_DIRECTORY(c.Structure):
    _fields_ = [
        ("VirtualAddress", ih.DWORD),
        ("Size", ih.DWORD),
    ]


class IMAGE_OPTIONAL_HEADER32(c.Structure):
    _fields_ = [
        # Standard fields.
        ("Magic", ih.WORD),
        ("MajorLinkerVersion", ih.BYTE),
        ("MinorLinkerVersion", ih.BYTE),
        ("SizeOfCode", ih.DWORD),
        ("SizeOfInitializedData", ih.DWORD),
        ("SizeOfUninitializedData", ih.DWORD),
        ("AddressOfEntryPoint", ih.DWORD),
        ("BaseOfCode", ih.DWORD),
        ("BaseOfData", ih.DWORD),

        # NT additional fields.
        ("ImageBase", ih.DWORD),
        ("SectionAlignment", ih.DWORD),
        ("FileAlignment", ih.DWORD),
        ("MajorOperatingSystemVersion", ih.WORD),
        ("MinorOperatingSystemVersion", ih.WORD),
        ("MajorImageVersion", ih.WORD),
        ("MinorImageVersion", ih.WORD),
        ("MajorSubsystemVersion", ih.WORD),
        ("MinorSubsystemVersion", ih.WORD),
        ("Win32VersionValue", ih.DWORD),
        ("SizeOfImage", ih.DWORD),
        ("SizeOfHeaders", ih.DWORD),
        ("CheckSum", ih.DWORD),
        ("Subsystem", ih.WORD),
        ("DllCharacteristics", ih.WORD),
        ("SizeOfStackReserve", ih.DWORD),
        ("SizeOfStackCommit", ih.DWORD),
        ("SizeOfHeapReserve", ih.DWORD),
        ("SizeOfHeapCommit", ih.DWORD),
        ("LoaderFlags", ih.DWORD),
        ("NumberOfRvaAndSizes", ih.DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY*IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]


class IMAGE_OPTIONAL_HEADER64(c.Structure):
    _fields_ = [
        ("Magic", ih.WORD),
        ("MajorLinkerVersion", ih.BYTE),
        ("MinorLinkerVersion", ih.BYTE),
        ("SizeOfCode", ih.DWORD),
        ("SizeOfInitializedData", ih.DWORD),
        ("SizeOfUninitializedData", ih.DWORD),
        ("AddressOfEntryPoint", ih.DWORD),
        ("BaseOfCode", ih.DWORD),
        ("ImageBase", ih.ULONGLONG),
        ("SectionAlignment", ih.DWORD),
        ("FileAlignment", ih.DWORD),
        ("MajorOperatingSystemVersion", ih.WORD),
        ("MinorOperatingSystemVersion", ih.WORD),
        ("MajorImageVersion", ih.WORD),
        ("MinorImageVersion", ih.WORD),
        ("MajorSubsystemVersion", ih.WORD),
        ("MinorSubsystemVersion", ih.WORD),
        ("Win32VersionValue", ih.DWORD),
        ("SizeOfImage", ih.DWORD),
        ("SizeOfHeaders", ih.DWORD),
        ("CheckSum", ih.DWORD),
        ("Subsystem", ih.WORD),
        ("DllCharacteristics", ih.WORD),
        ("SizeOfStackReserve", ih.ULONGLONG),
        ("SizeOfStackCommit", ih.ULONGLONG),
        ("SizeOfHeapReserve", ih.ULONGLONG),
        ("SizeOfHeapCommit", ih.ULONGLONG),
        ("LoaderFlags", ih.DWORD),
        ("NumberOfRvaAndSizes", ih.DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY*IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]


class IMAGE_NT_HEADERS64(c.Structure):
    _fields_ = [
        ("Signature", ih.DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER64),
    ]


class IMAGE_NT_HEADERS32(c.Structure):
    _fields_ = [
        ("Signature", ih.DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER32),
    ]


class _M(c.Union):
    _fields_ = [
        ("PhysicalAddress", ih.DWORD),
        ("VirtualSize", ih.DWORD),
    ]


class IMAGE_SECTION_HEADER(c.Structure):
    _fields_ = [
        ("Name", ih.BYTE*IMAGE_SIZEOF_SHORT_NAME),
        ("Misc", _M),
        ("VirtualAddress", ih.DWORD),
        ("SizeOfRawData", ih.DWORD),
        ("PointerToRawData", ih.DWORD),
        ("PointerToRelocations", ih.DWORD),
        ("PointerToLinenumbers", ih.DWORD),
        ("NumberOfRelocations", ih.WORD),
        ("NumberOfLinenumbers", ih.WORD),
        ("Characteristics", ih.DWORD),
    ]


# DLL support.

# Export Format

class IMAGE_EXPORT_DIRCTORY(c.Structure):
    _fields_ = [
        ("Characteristics", ih.DWORD),
        ("TimeDateStamp", ih.DWORD),
        ("MajorVersion", ih.WORD),
        ("MinorVersion", ih.WORD),
        ("Name", ih.DWORD),
        ("Base", ih.DWORD),
        ("NumberOfFunctions", ih.DWORD),
        ("NumberOfNames", ih.DWORD),
        ("AddressOfFunctions", ih.DWORD),  # RVA from base of image
        ("AddressOfNames", ih.DWORD),  # RVA from base of image
        ("AddressOfNameOrdinals", ih.DWORD),  # RVA from base of image
    ]


# Import Format

class IMAGE_IMPORT_BY_NAME(c.Structure):
    _fields_ = [
        ("Hint", ih.WORD),
        ("Name", ih.BYTE*1),
    ]


class _U1_64(c.Union):
    _fields_ = [
        ("ForwarderString", ih.ULONGLONG),  # PBYTE
        ("Function", ih.ULONGLONG),  # PDWORD
        ("Ordinal", ih.ULONGLONG),
        ("AddressOfData", ih.ULONGLONG),  # PIMAGE_IMPORT_BY_NAME
    ]


class IMAGE_THUNK_DATA64(c.Structure):
    _pack_ = 8
    _fields_ = [
        ("u1", _U1_64),
    ]


class _U1_32(c.Union):
    _fields_ = [
        ("ForwarderString", ih.DWORD),  # PBYTE
        ("Function", ih.DWORD),  # PDWORD
        ("Ordinal", ih.DWORD),
        ("AddressOfData", ih.DWORD),  # PIMAGE_IMPORT_BY_NAME
    ]


class IMAGE_THUNK_DATA32(c.Structure):
    _pack_ = 4
    _fields_ = [
        ("u1", _U1_32),
    ]


class IMAGE_TLS_DIRECTORY64(c.Structure):
    _fields_ = [
        ("StartAddressOfRawData", ih.ULONGLONG),
        ("EndAddressOfRawData", ih.ULONGLONG),
        ("AddressOfIndex", ih.ULONGLONG),  # PDWORD
        ("AddressOfCallBacks", ih.ULONGLONG),  # PIMAGE_TLS_CALLBACK *;
        ("SizeOfZeroFill", ih.DWORD),
        ("Characteristics", ih.DWORD),
    ]


class IMAGE_TLS_DIRECTORY32(c.Structure):
    _fields_ = [
        ("StartAddressOfRawData", ih.DWORD),
        ("EndAddressOfRawData", ih.DWORD),
        ("AddressOfIndex", ih.DWORD),  # PDWORD
        ("AddressOfCallBacks", ih.DWORD),  # PIMAGE_TLS_CALLBACK *;
        ("SizeOfZeroFill", ih.DWORD),
        ("Characteristics", ih.DWORD),
    ]


class _D(c.Union):
    _fields_ = [
        ("Characteristics", ih.DWORD),  # 0 for terminating null import descriptor
        ("OriginalFirstThunk", ih.DWORD),  # RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    ]


class IMAGE_IMPORT_DESCRIPTOR(c.Structure):
    _fields_ = [
        ("DUMMYUNIONNAME", _D),
        ("TimeDateStamp", ih.DWORD),  # 0 if not bound,
                                   # -1 if bound, and real date\time stamp in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                   # O.W. date/time stamp of DLL bound to (Old BIND)
        ("ForwarderChain", ih.DWORD),  # -1 if no forwarders
        ("Name", ih.DWORD),
        ("FirstThunk", ih.DWORD),  # RVA to IAT (if bound this IAT has actual addresses)
    ]


# New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]

class IMAGE_BOUND_IMPORT_DESCRIPTOR(c.Structure):
    _fields_ = [
        ("TimeDateStamp", ih.DWORD),
        ("OffsetModuleName", ih.WORD),
        ("NumberOfModuleForwarderRefs", ih.WORD),
    ]


class IMAGE_BOUND_FORWARDER_REF(c.Structure):
    _fields_ = [
        ("TimeDateStamp", ih.DWORD),
        ("OffsetModuleName", ih.WORD),
        ("Reserved", ih.WORD),
    ]
