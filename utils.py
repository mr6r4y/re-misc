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


class NoSupportedType(StandardError):
    pass


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

def cstruct2r2fmt(struct):
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


## R2 Types
##-------------
## char
## char *
## int
## int16_t
## int32_t
## int64_t
## int8_t
## long
## long long
## short
## size_t
## uid_t
## uint16_t
## uint32_t
## uint64_t
## uint8_t
## unsigned char
## unsigned int
## unsigned short
## void *
def cstruct2td(struct):
    types = []
    for f_name, f_type in struct._fields_:
        if f_type in [c.c_byte]:
            t = 'char'
        elif f_type in [c.c_char]:
            t = 'char'
        elif f_type in [c.c_char_p]:
            t = 'char *'
        elif f_type in [c.c_double]:
            t = 'uint64_t'
        elif f_type in [c.c_longdouble]:
            raise NoSupportedType('Type %s is not supported' % str(f_type))
        elif f_type in [c.c_float]:
            t = 'uint32_t'
        elif f_type in [c.c_int]:
            t = 'int'
        elif f_type in [c.c_int8]:
            t = 'int8_t'
        elif f_type in [c.c_int16]:
            t = 'int16_t'
        elif f_type in [c.c_int32]:
            t = 'int32_t'
        elif f_type in [c.c_int64]:
            t = 'int64_t'
        elif f_type in [c.c_long]:
            t = 'long'
        elif f_type in [c.c_longlong]:
            t = 'long long'
        elif f_type in [c.c_short]:
            t = 'short'
        elif f_type in [c.c_ubyte]:
            t = 'unsigned char'
        elif f_type in [c.c_uint]:
            t = 'unsigned int'
        elif f_type in [c.c_uint8]:
            t = 'uint8_t'
        elif f_type in [c.c_uint16]:
            t = 'uint16_t'
        elif f_type in [c.c_uint32]:
            t = 'uint32_t'
        elif f_type in [c.c_uint64]:
            t = 'uint64_t'
        elif f_type in [c.c_ulong]:
            t = 'uint32_t'
        elif f_type in [c.c_ulonglong]:
            t = 'uint64_t'
        elif f_type in [c.c_ushort]:
            t = 'unsigned short'
        elif f_type in [c.c_void_p]:
            t = 'void *'
        elif f_type in [c.c_wchar]:
            t = ''
        elif f_type in [c.c_wchar_p]:
            t = 'void *'
        elif f_type in [c.c_bool]:
            t = 'char'
        else:
            raise NoSupportedType('Type %s is not supported' % str(f_type))
        types.append("%s %s" % (t, f_name))
    return '" td struct %s {%s};"' % (struct().__class__.__name__, ";".join(types))
