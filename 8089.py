#!/usr/bin/python3
# Intel 8089 Disassembler
# Copyright 2016 Eric Smith <spacewar@gmail.com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU General Public License
# as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import sys
from collections import namedtuple

from intelhex import IntelHex

Op = namedtuple('Op', ['mnem', 'form', 'bits', 'mask', 'fields'])

# where two operands are listed, first is source, second is dest
# Note ASM89 uses x86 assembler convention of dest, src
inst_set = [
    # LJMP is ADDBI with rrr=100 (TP), put earlier than ADDBI in table
    ['jmp',    [[()               , '10001000 00100000 jjjjjjjj']]],

    # LJMP is ADDI with rrr=100 (TP), put earlier than ADDI in table
    ['ljmp',   [[()               , '10010001 00100000 jjjjjjjj jjjjjjjj']]],
    
    ['mov',    [[('memo', 'reg')  , 'rrr00011 100000mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa1 100000mm'],
                [('reg',  'memo') , 'rrr00011 100001mm oooooooo'],
                [('reg',  'mem')  , 'rrr00aa1 100001mm'],
                [('memo', 'memo') , '00000011 100100mm oooooooo/00000011 110011mm oooooooo'],
                [('memo', 'mem')  , '00000011 100100mm oooooooo/00000aa1 110011mm'],
                [('mem',  'memo') , '00000aa1 100100mm/00000011 110011mm oooooooo'],
                [('mem',  'mem')  , '00000aa1 100100mm/00000aa1 110011mm']]],

    ['movb',   [[('memo', 'reg')  , 'rrr00010 100000mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa0 100000mm'],
                [('reg',  'memo') , 'rrr00010 100001mm oooooooo'],
                [('reg',  'mem')  , 'rrr00aa0 100001mm'],
                [('memo', 'memo') , '00000010 100100mm oooooooo/00000010 110011mm oooooooo'],
                [('memo', 'mem')  , '00000010 100100mm oooooooo/00000aa0 110011mm'],
                [('mem',  'memo') , '00000aa0 100100mm/00000010 110011mm oooooooo'],
                [('mem',  'mem')  , '00000aa0 100100mm/00000aa0 110011mm']]],

    ['movbi',  [[('i8',   'reg')  , 'rrr01000 00110000 iiiiiiii'],
                [('i8',   'memo') , '00001010 010011mm oooooooo iiiiiiii'],
                [('i8',   'mem')  , '00001aa0 010011mm iiiiiiii']]],

    ['movi',   [[('i16',  'reg')  , 'rrr10001 00110000 iiiiiiii iiiiiiii'],
                [('i16',  'memo') , '00010011 010011mm oooooooo iiiiiiii iiiiiiii'],
                [('i16',  'mem')  , '00010aa1 010011mm iiiiiiii iiiiiiii']]],

    ['movp',   [[('memo', 'preg') , 'ppp00011 100011mm oooooooo'],
                [('mem',  'preg') , 'ppp00aa1 100011mm'],
                [('preg', 'memo') , 'ppp00011 100110mm oooooooo'],
                [('preg', 'mem')  , 'ppp00aa1 100110mm']]],

    ['lpd' ,   [[('memo',)        , 'ppp00011 100010mm oooooooo'],
                [('mem',)         , 'ppp00aa1 100010mm']]],
    
    ['lpdi',   [[()               , 'ppp10001 00001000 iiiiiiii iiiiiiii ssssssss ssssssss']]],

    ['add',    [[('memo', 'reg')  , 'rrr00011 101000mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa1 101000mm'],
                [('reg',  'memo') , 'rrr00011 110100mm oooooooo'],
                [('reg',  'mem')  , 'rrr00aa1 110100mm']]],

    # ADDB encodings in 8089 assembler manual p3-12 have W bit wrong
    ['addb',   [[('memo', 'reg')  , 'rrr00010 101000mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa0 101000mm'],
                [('reg',  'memo') , 'rrr00010 110100mm oooooooo'],
                [('reg',  'mem')  , 'rrr00aa0 110100mm']]],

    ['addi',   [[('i16',  'reg')  , 'rrr10001 00100000 iiiiiiii iiiiiiii'],
                [('i16',  'memo') , '00010011 110000mm oooooooo iiiiiiii iiiiiiii'],
                [('i16',  'mem')  , '00010aa1 110000mm iiiiiiii iiiiiiii']]],

    ['addbi',  [[('i8',   'reg')  , 'rrr01000 00100000 iiiiiiii'],
                [('i8',   'memo') , '00001010 110000mm oooooooo iiiiiiii'],
                [('i8',   'mem')  , '00001aa0 110000mm iiiiiiii']]],

    ['inc',    [[('reg',)         , 'rrr00000 00111000'],
                [('memo',)        , '00000011 111010mm oooooooo'],
                [('mem',)         , '00000aa1 111010mm']]],

    ['incb',   [[('memo',)        , '00000010 111010mm oooooooo'],
                [('mem',)         , '00000aa0 111010mm']]],

    ['dec',    [[('reg',)         , 'rrr00000 00111100'],
                [('memo',)        , '00000011 111011mm oooooooo'],
                [('mem',)         , '00000aa1 111011mm']]],

    ['decb',   [[('memo',)        , '00000010 111011mm oooooooo'],
                [('mem',)         , '00000aa0 111011mm']]],

    ['and',    [[('memo', 'reg')  , 'rrr00011 101010mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa1 101010mm'],
                [('reg',  'memo') , 'rrr00011 110110mm oooooooo'],
                [('reg',  'mem')  , 'rrr00aa1 110110mm']]],

    ['andb',   [[('memo', 'reg')  , 'rrr00010 101010mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa0 101010mm'],
                [('reg',  'memo') , 'rrr00010 110110mm oooooooo'],
                [('reg',  'mem')  , 'rrr00aa0 110110mm']]],

    ['andi',   [[('i16',  'reg')  , 'rrr10001 00101000 iiiiiiii iiiiiiii'],
                [('i16',  'memo') , '00010011 110010mm oooooooo iiiiiiii iiiiiiii'],
                [('i16',  'mem')  , '00010aa1 110010mm iiiiiiii iiiiiiii']]],

    ['andbi',  [[('i8',   'reg')  , 'rrr01000 00101000 iiiiiiii'],
                [('i8',   'memo') , '00001010 110010mm oooooooo iiiiiiii'],
                [('i8',   'mem')  , '00001aa0 110010mm iiiiiiii']]],

    ['or',     [[('memo', 'reg')  , 'rrr00011 101001mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa1 101001mm'],
                [('reg',  'memo') , 'rrr00011 110101mm oooooooo'],
                [('reg',  'mem')  , 'rrr00aa1 110101mm']]],

    ['orb',    [[('memo', 'reg')  , 'rrr00010 101001mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa0 101001mm'],
                [('reg',  'memo') , 'rrr00010 110101mm oooooooo'],
                [('reg',  'mem')  , 'rrr00aa0 110101mm']]],

    ['ori',    [[('i16',  'reg')  , 'rrr10001 00100100 iiiiiiii iiiiiiii'],
                [('i16',  'memo') , '00010011 110001mm oooooooo iiiiiiii iiiiiiii'],
                [('i16',  'mem')  , '00010aa1 110001mm iiiiiiii iiiiiiii']]],

    ['orbi',   [[('i8',   'reg')  , 'rrr01000 00100100 iiiiiiii'],
                [('i8',   'memo') , '00001010 110001mm oooooooo iiiiiiii'],
                [('i8',   'mem')  , '00001aa0 110001mm iiiiiiii']]],

    ['not',    [[('reg',)         , 'rrr00000 00101100'],
                [('memo',)        , '00000011 110111mm oooooooo'],
                [('mem',)         , '00000aa1 110111mm'],
                [('memo', 'reg')  , 'rrr00011 101011mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa1 101011mm']]],

    ['notb',   [[('memo',)        , '00000010 110111mm oooooooo'],
                [('mem',)         , '00000aa0 110111mm'],
                [('memo', 'reg')  , 'rrr00010 101011mm oooooooo'],
                [('mem',  'reg')  , 'rrr00aa0 101011mm']]],

    ['setb',   [[('memo',)        , 'bbb00010 111101mm oooooooo'],
                [('mem',)         , 'bbb00aa0 111101mm']]],

    ['clr',    [[('memo',)        , 'bbb00010 111110mm oooooooo'],
                [('mem',)         , 'bbb00aa0 111110mm']]],

    ['call',   [[('memo',)        , '10001011 100111mm oooooooo jjjjjjjj'],
                [('mem',)         , '10001aa1 100111mm jjjjjjjj']]],

    ['lcall',  [[('memo',)        , '10010011 100111mm oooooooo jjjjjjjj jjjjjjjj'],
                [('mem',)         , '10010aa1 100111mm jjjjjjjj jjjjjjjj']]],

    ['jz',     [[('lab',  'reg')  , 'rrr01000 01000100 jjjjjjjj'],
                [('lab',  'memo') , '00001011 111001mm oooooooo jjjjjjjj'],
                [('lab',  'mem')  , '00001aa1 111001mm jjjjjjjj']]],

    ['ljz',    [[('lab',  'reg')  , 'rrr10000 01000100 jjjjjjjj jjjjjjjj'],
                [('lab',  'memo') , '00010011 111001mm oooooooo jjjjjjjj jjjjjjjj'],
                [('lab',  'mem')  , '00010aa1 111001mm jjjjjjjj jjjjjjjj']]],

    ['jzb',    [[('memo',)        , '00001010 111001mm oooooooo jjjjjjjj'],
                [('mem',)         , '00001aa0 111001mm jjjjjjjj']]],

    ['ljzb',   [[('memo',)        , '00010010 111001mm oooooooo jjjjjjjj jjjjjjjj'],
                [('mem',)         , '00010aa0 111001mm jjjjjjjj jjjjjjjj']]],

    ['jnz',    [[('lab',  'reg')  , 'rrr01000 01000000 jjjjjjjj'],
                [('lab',  'memo') , '00001011 111000mm oooooooo jjjjjjjj'],
                [('lab',  'mem')  , '00001aa1 111000mm jjjjjjjj']]],

    ['ljnz',   [[('lab',  'reg')  , 'rrr10000 01000000 jjjjjjjj jjjjjjjj'],
                [('lab',  'memo') , '00010011 111000mm oooooooo jjjjjjjj jjjjjjjj'],
                [('lab',  'mem')  , '00010aa1 111000mm jjjjjjjj jjjjjjjj']]],

    ['jnzb',   [[('memo',)        , '00001010 111000mm oooooooo jjjjjjjj'],
                [('mem',)         , '00001aa0 111000mm jjjjjjjj']]],

    ['ljnzb',  [[('memo',)        , '00010010 111000mm oooooooo jjjjjjjj jjjjjjjj'],
                [('mem',)         , '00010aa0 111000mm jjjjjjjj jjjjjjjj']]],

    ['jmce',   [[('memo',)        , '00001010 101100mm oooooooo jjjjjjjj'],
                [('mem',)         , '00001aa0 101100mm jjjjjjjj']]],

    ['ljmce',  [[('memo',)        , '00010010 101100mm oooooooo jjjjjjjj jjjjjjjj'],
                [('mem',)         , '00010aa0 101100mm jjjjjjjj jjjjjjjj']]],

    ['jmcne',  [[('memo',)        , '00001010 101101mm oooooooo jjjjjjjj'],
                [('mem',)         , '00001aa0 101101mm jjjjjjjj']]],

    ['ljmcne', [[('memo',)        , '00010010 101101mm oooooooo jjjjjjjj jjjjjjjj'],
                [('mem',)         , '00010aa0 101101mm jjjjjjjj jjjjjjjj']]],

    ['jbt',    [[('memo',)        , 'bbb01010 101111mm oooooooo jjjjjjjj'],
                [('mem',)         , 'bbb01aa0 101111mm jjjjjjjj']]],

    ['ljbt',   [[('memo',)        , 'bbb10010 101111mm oooooooo jjjjjjjj jjjjjjjj'],
                [('mem',)         , 'bbb10aa0 101111mm jjjjjjjj jjjjjjjj']]],

    ['jnbt',   [[('memo',)        , 'bbb01010 101110mm oooooooo jjjjjjjj'],
                [('mem',)         , 'bbb01aa0 101110mm jjjjjjjj']]],

    ['ljnbt',  [[('memo',)        , 'bbb10010 101110mm oooooooo jjjjjjjj jjjjjjjj'],
                [('mem',)         , 'bbb10aa0 101110mm jjjjjjjj jjjjjjjj']]],

    ['tsl',    [[('memo',)        , '00011010 100101mm oooooooo iiiiiiii jjjjjjjj'],
                [('mem',)         , '00011aa0 100101mm iiiiiiii jjjjjjjj']]],

    ['wid',    [[()               , '1sd00000 00000000']]],

    ['xfer',   [[()               , '01100000 00000000']]],

    ['sintr',  [[()               , '01000000 00000000']]],

    ['hlt',    [[()               , '00100000 01001000']]],

    ['nop',    [[()               , '00000000 00000000']]]
]


inst_by_opcode = { }


def byte_parse(bs, second_flag):
    b = 0
    m = 0
    f = { }
    for i in range(8):
        c = bs[7-i]
        if c == '0':
            m |= (1 << i)
        elif c == '1':
            b |= (1 << i)
            m |= (1 << i)
        else:
            if second_flag:
                c += '2'
            if c not in f:
                f[c] = 0
            f[c] |= (1 << i)
    return b, m, f

def encoding_parse(encoding):
    ep_debug = False
    if ep_debug:
        print('encoding', encoding)
    encoding = encoding.replace(' ', '')
    bits = []
    mask = []
    fields = { }
    second_flag = False
    i = 0
    while len(encoding):
        if encoding[0] == '/':
            encoding = encoding[1:]
            second_flag = True
            continue
        assert len(encoding) >= 8
        byte = encoding[0:8]
        encoding = encoding[8:]
        if ep_debug:
            print('byte', byte)
        b, m, f = byte_parse(byte, second_flag)
        if ep_debug:
            print('b: ', b, 'm:', m, 'f:', f)
        bits.append(b)
        mask.append(m)
        for k in f:
            if k not in fields:
                fields[k] = [0x00] * (i)
            fields[k].append(f[k])
        i += 1
    if ep_debug:
        print('fields before:', fields)
    for k in fields:
        if len(fields[k]) < i:
            fields[k] += [0x00] * (i - len(fields[k]))
    if ep_debug:
        print('fields after:', fields)
    return bits, mask, fields


def opcode_init():
    for mnem, details in inst_set:
        for form, encoding in details:
            bits, mask, fields = encoding_parse(encoding)
            opcode = bits[1] & 0xfc
            if opcode not in inst_by_opcode:
                inst_by_opcode[opcode] = []
            inst_by_opcode[opcode].append(Op(mnem, form, bits, mask, fields))
            #print(inst, form, "%02x" % opcode)


def opcode_table_print():
    print(inst_by_opcode[0])
    for opcode in sorted(inst_by_opcode.keys()):
        for mnem, form, bits, mask, fields in inst_by_opcode[opcode]:
            print("%02x:" % opcode, mnem, bits, mask, fields)



def extract_field(inst, op, f):
    v = 0
    for i in reversed(range(min(len(inst), len(op.fields[f])))):
        for j in reversed(range(8)):
            if op.fields[f][i] & (1 << j):
                v = (v << 1) | ((inst[i] >> j) & 1)
    return v
    

def opcode_match(fw, pc, op):
    fields = { }

    l = len(op.bits)
    inst = fw[pc:pc+l]

    for i in range(l):
        if inst[i] & op.mask[i] != op.bits[i] & op.mask[i]:
            return None, fields

    for f in op.fields:
        fields[f] = extract_field(inst, op, f)

    # 'j' jump target field is relative to address of next instruction
    if 'j' in fields:
        fields['j'] = (fields['j'] + pc + l) & 0xffff

    return len(op.bits), fields


class BadInstruction(Exception):
    pass


def opcode_search(fw, pc):
    opcode = fw[pc+1] & 0xfc
    if opcode not in inst_by_opcode:
        #print('addr %04x: opcode of inst %02x %02x not in table' % (pc, fw[pc], fw[pc+1]))
        raise BadInstruction
    for op in inst_by_opcode[opcode]:
        l, fields = opcode_match(fw, pc, op)
        if l is not None:
            return l, op, fields
    #print('addr %04x: inst %02x %02x not matched' % (pc, fw[pc], fw[pc+1]))
    raise BadInstruction

def ihex(v):
    s = '%xh' % v
    if s[0].isalpha():
        s = '0' + s
    return s

def disassemble_inst(fw, pc):
    try:
        length, op, fields = opcode_search(fw, pc)
    except BadInstruction:
        return 1, 'db     %s' % ihex(fw[pc]), {}

    s = '%-6s' % op.mnem
    for f in fields:
        s += ' %s:%x' % (f, fields[f])
    return length, s, fields

def pass1(fw, base, length):
    print('base:   %04x' % base)
    print('length: %04x' % length)
    symtab_by_value = {}
    pc = base
    while pc < base + length - 2:
        (inst_length, dis, fields) = disassemble_inst(fw, pc)
        if 'j' in fields:
            symtab_by_value[fields['j']] = 'x%04x' % fields['j']
        pc += inst_length
    return symtab_by_value

def pass2(fw, base, length,
          symtab_by_value, show_obj = False, output_file = sys.stdout):
    pc = base
    while pc < base + length - 2:
        s = ''
        (inst_length, dis, fields) = disassemble_inst(fw, pc)
        if show_obj:
            s += '%04x: '% pc
            for i in range(6):
                if (i < inst_length):
                    s += '%02x ' % fw[pc + i]
                else:
                    s += '   '
        if pc in symtab_by_value:
            label = symtab_by_value[pc] + ':'
        else:
            label = ''
        s += '%-8s%s' % (label, dis)
        pc += inst_length
        output_file.write(s + '\n')
    

def disassemble(fw, show_obj = False, output_file = sys.stdout,
                base = 0, length = 0x10000):
    symtab_by_value = pass1(fw, base, length)
    #symtab_by_name = { v: k for k, v in symtab_by_value.items() }
    pass2(fw, base, length, symtab_by_value, show_obj = show_obj, output_file = output_file)


def read_object(input, inputformat = 'binary', base = 0, length = None):
    if inputformat == 'binary':
        fwl = [f.read() for f in args.input]
    elif inputformat == 'hex':
        fwl = [IntelHex(f).read() for f in args.input]
    else:
        raise Exception('unknown input format')
    minl = min([len(f) for f in fwl])

    i = 0
    fw = bytearray(0x10000)
    for j in range(minl):
        for k in range(len(input)):
            try:
                fw[i] = fwl[k][j]
            except Exception as e:
                print(e)
                print('i: %d, j:%d, k:%d' % (i, j, k))
            i += 1
            if length is not None and i >= base + length:
                return fw
    return fw[:minl*len(input)]


# type function for argparse to support numeric arguments in hexadecimal
# ("0x" prefix) as well as decimal (no prefix)
def auto_int(x):
    return int(x, 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Disassembler for Intel 8089 I/O processor')

    parser.add_argument('-l', '--listing', action='store_true',
                        help = 'generate output in listing format')

    parser.add_argument('-b', '--base', type = auto_int, default = 0,
                        help = 'base address of image (default: %(default)x)')
    parser.add_argument('--length', type = auto_int,
                        help = 'length of image')

    fmt_group = parser.add_mutually_exclusive_group()
    fmt_group.add_argument('--binary', action='store_const',
                           dest='inputformat',
                           const='binary',
                           help = 'input file format is raw binary (default)')
    fmt_group.add_argument('--hex', action='store_const',
                           dest='inputformat',
                           const='hex',
                           help = 'input file format is Intel hex')
    
    parser.add_argument('input', type = argparse.FileType('rb'),
                        nargs = '+',
                        help = 'input file(s), multiple files will be interleaved (useful for separate even, odd files)')

    parser.add_argument('-o', '--output', type=argparse.FileType('w'),
                        default = sys.stdout,
                        help = 'disassembly output file')

    args = parser.parse_args()
    print(args)

    opcode_init()
    #opcode_table_print()

    if args.inputformat is None:
        args.inputformat = 'binary'

    fw = read_object(args.input, args.inputformat, base = args.base, length = args.length)
    if args.length is None:
        args.length = len(fw)
    print('args.base:   %04x' % args.base)
    print('args.length: %04x' % args.length)

    if args.base != 0:
        fw = bytearray(args.base) + fw

    disassemble(fw, show_obj = args.listing, output_file = args.output,
                base = args.base,
                length = args.length)
