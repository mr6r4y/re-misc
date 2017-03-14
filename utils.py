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
