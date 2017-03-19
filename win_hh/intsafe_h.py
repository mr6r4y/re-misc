#-*- coding: utf-8 -*


__all__ = [

]


import ctypes


SHORT = ctypes.c_short
DWORD = ctypes.c_uint32
WORD = ctypes.c_ushort
LONG = ctypes.c_int32  # Using c_long and c_ulong on Windows and Linux 
                       # gives 4 and 8 bytes, so I specify the exact length
BYTE = ctypes.c_ubyte
__int64 = ctypes.c_longlong
ULONGLONG = __int64

