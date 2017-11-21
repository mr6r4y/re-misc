"""Enhance Python's disassembler."""

import types
from dis import *


_have_code = (types.MethodType, types.FunctionType, types.CodeType,
              types.ClassType, type)


def dis(x=None, begin_i=0, end_i=None):
    """Disassemble classes, methods, functions, or code.

    With no argument, disassemble the last traceback.

    """
    if x is None:
        distb()
        return
    if isinstance(x, types.InstanceType):
        x = x.__class__
    if hasattr(x, 'im_func'):
        x = x.im_func
    if hasattr(x, 'func_code'):
        x = x.func_code
    if hasattr(x, '__dict__'):
        items = x.__dict__.items()
        items.sort()
        d = {}
        for name, x1 in items:
            if isinstance(x1, _have_code):
                try:
                    d[name] = dis(x1)
                except TypeError, msg:
                    print "Sorry:", msg
                print
    elif hasattr(x, 'co_code'):
        return disassemble(x, begin_i, end_i)
    else:
        raise (TypeError,
               "don't know how to disassemble %s objects" % type(x).__name__)


def disassemble(co, begin_i=0, end_i=None):
    """Disassemble a code object."""

    code = co.co_code
    n = len(code)
    i = begin_i
    extended_arg = 0
    free = None
    while i < n:
        c = code[i]
        op = ord(c)

        ind = i
        opn = opname[op]
        op_arg = None
        op_extarg = None
        jmp_offset = None
        desc = None

        i = i + 1

        if op >= HAVE_ARGUMENT:
            oparg = ord(code[i]) + ord(code[i + 1]) * 256 + extended_arg

            op_arg = oparg

            extended_arg = 0

            i = i + 2

            if op == EXTENDED_ARG:
                extended_arg = oparg * 65536L
            op_extarg = extended_arg

            if op in hasconst and oparg < len(co.co_consts):
                desc = ('CO_CONSTS', co.co_consts[oparg])
            elif op in hasname and oparg < len(co.co_names):
                desc = ('CO_NAMES', co.co_names[oparg])
            elif op in hasjrel:
                desc = ('JREL', i + oparg)
                # eliminating dead code
                jmp_offset = i + oparg
                if opn in ("JUMP_FORWARD", ):
                    if jmp_offset > i and jmp_offset <= n:
                        i = jmp_offset
            elif op in hasjabs:
                desc = ('JABS', oparg)
                # eliminating dead code
                jmp_offset = oparg
                if opn in ("JUMP_ABSOLUTE", ):
                    if jmp_offset > i and jmp_offset <= n:
                        i = jmp_offset
            elif op in haslocal and oparg < len(co.co_varnames):
                desc = ('CO_VARNAMES', co.co_varnames[oparg])
            elif op in hascompare and oparg < len(cmp_op):
                desc = ('CMP_OP', cmp_op[oparg])
            elif op in hasfree:
                if free is None:
                    free = co.co_cellvars + co.co_freevars
                if oparg in free:
                    desc = ('FREEVARS', free[oparg])

        yield (ind, opn, op_arg, op_extarg, jmp_offset, desc)

        if end_i is not None and i >= end_i:
            break
