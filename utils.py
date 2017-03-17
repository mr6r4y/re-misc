#!/usr/bin/env python
#-*- coding: utf-8 -*


__all__ = [
    "iterate_till_null",
    "interpret_char_p",
    "cast",
    "cast_to_pointer",
    "get_offset",
    "bytes2str",
    "CastError",
]


import ctypes as c


class CastError(StandardError):
    pass


def iterate_till_null(c_buffer, offset, size):
    last_offset = offset
    count = 0
    current = c_buffer[last_offset:last_offset+size]

    while(current != "\x00"*size):
        last_offset = last_offset+size
        count += 1
        current = c_buffer[last_offset:last_offset+size]
        if(current == ""):
            return None, None

    return (last_offset, count)


def interpret_char_p(c_buffer, offset):
    if(c.sizeof(c_buffer) < offset):
        raise CastError("Size of buffer is not sufficient for char_p with offset 0x%X" % offset)
    try:
        s = cast_to_pointer(c_buffer, offset, c.c_char_p).value
    except Exception, err:
        raise CastError("Could not cast offset 0x%X to char_p: %s" % (offset, str(err)))

    return s


def cast(cast_from, offset, cast_to):
    return c.cast(c.byref(cast_from, offset), c.POINTER(cast_to)).contents


def cast_to_pointer(cast_from, offset, pointer_type):
    return c.cast(c.byref(cast_from, offset), pointer_type)


def get_offset(c_buffer, inside_item):
    return c.addressof(inside_item) - c.addressof(c_buffer)


def bytes2str(bytes):
    return "".join([chr(i) for i in bytes])


# |pf: pf[.k[.f[=v]]|[v]]|[n]|[0|cnt][fmt] [a0 a1 ...]
# | Format:
# |  b       byte (unsigned)
# |  B       resolve enum bitfield (see t?)
# |  c       char (signed byte)
# |  d       0x%%08x hexadecimal value (4 bytes) (see %%i and %%x)
# |  D       disassemble one opcode
# |  e       temporally swap endian
# |  E       resolve enum name (see t?)
# |  f       float value (4 bytes)
# |  i       %%i signed integer value (4 bytes) (see %%d and %%x)
# |  n       next char specifies size of signed value (1, 2, 4 or 8 byte(s))
# |  N       next char specifies size of unsigned value (1, 2, 4 or 8 byte(s))
# |  o       0x%%08o octal value (4 byte)
# |  p       pointer reference (2, 4 or 8 bytes)
# |  q       quadword (8 bytes)
# |  r       CPU register `pf r (eax)plop`
# |  s       32bit pointer to string (4 bytes)
# |  S       64bit pointer to string (8 bytes)
# |  t       UNIX timestamp (4 bytes)
# |  T       show Ten first bytes of buffer
# |  u       uleb128 (variable length)
# |  w       word (2 bytes unsigned short in hex)
# |  x       0x%%08x hex value and flag (fd @ addr) (see %%d and %%i)
# |  X       show formatted hexpairs
# |  z       \0 terminated string
# |  Z       \0 terminated wide string
# |  ?       data structure `pf ? (struct_name)example_name`
# |  *       next char is pointer (honors asm.bits)
# |  +       toggle show flags for each offset
# |  :       skip 4 bytes
# |  .       skip 1 byte

def struct2r2fmt(struct):
    # TO-DO: To think how it will work with more complex examples and paddings
    # TO-DO: This deserves a whole parsing class with recursion
    fmt_type = []
    fmt_names = []
    for f_name, f_type in struct._fields_:
        if f_type in [c.c_byte]:
            fmt_type.append('b')
        elif f_type in [c.c_char]:
            fmt_type.append('c')
        elif f_type in [c.c_char_p]:
            fmt_type.append('*')
        elif f_type in [c.c_double]:
            fmt_type.append('q')
        elif f_type in [c.c_longdouble]:
            fmt_type.append('q')
        elif f_type in [c.c_float]:
            fmt_type.append('f')
        elif f_type in [c.c_int]:
            fmt_type.append('x')
        elif f_type in [c.c_int8]:
            fmt_type.append('c')
        elif f_type in [c.c_int16]:
            fmt_type.append('w')
        elif f_type in [c.c_int32]:
            fmt_type.append('x')
        elif f_type in [c.c_int64]:
            fmt_type.append('q')
        elif f_type in [c.c_long]:
            fmt_type.append('x')
        elif f_type in [c.c_longlong]:
            fmt_type.append('q')
        elif f_type in [c.c_short]:
            fmt_type.append('w')
        elif f_type in [c.c_ubyte]:
            fmt_type.append('b')
        elif f_type in [c.c_uint]:
            fmt_type.append('x')
        elif f_type in [c.c_uint8]:
            fmt_type.append('c')
        elif f_type in [c.c_uint16]:
            fmt_type.append('w')
        elif f_type in [c.c_uint32]:
            fmt_type.append('x')
        elif f_type in [c.c_uint64]:
            fmt_type.append('q')
        elif f_type in [c.c_ulong]:
            fmt_type.append('x')
        elif f_type in [c.c_ulonglong]:
            fmt_type.append('q')
        elif f_type in [c.c_ushort]:
            fmt_type.append('w')
        elif f_type in [c.c_void_p]:
            fmt_type.append('*')
        elif f_type in [c.c_wchar]:
            fmt_type.append('w')
        elif f_type in [c.c_wchar_p]:
            fmt_type.append('*')
        elif f_type in [c.c_bool]:
            fmt_type.append('b')
        fmt_names.append(f_name)
    return "%s %s" % ("".join(fmt_type), " ".join(fmt_names))
