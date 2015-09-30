#!/usr/bin/python3
from collections import namedtuple

Op = namedtuple('Op', ['mnem', 'form', 'bits', 'mask', 'fields'])

inst_set = {
    'MOV' :   { ('mem',  'reg')  : 'rrr00aa1 100000mm oooooooo',
                ('reg',  'mem')  : 'rrr00aa1 100001mm oooooooo',
                ('mem',  'mem')  : '00000aa1 100100mm oooooooo/00000aa1 110011mm oooooooo' },

    'MOVB' :  { ('mem',  'reg')  : 'rrr00aa0 100000mm oooooooo',
                ('reg',  'mem')  : 'rrr00aa0 100001mm oooooooo',
                ('mem',  'mem')  : '00000aa0 100100mm oooooooo/00000aa0 110011mm oooooooo' },

    'MOVBI' : { ('i8',   'reg')  : 'rrr01000 00110000 iiiiiiii',
                ('i8',   'mem')  : '00001aa0 010011mm oooooooo iiiiiiii' },

    'MOVI' :  { ('i16',  'reg')  : 'rrr10001 00110000 iiiiiiii iiiiiiii',
                ('i16',  'mem')  : '00010aa1 010011mm oooooooo iiiiiiii iiiiiiii' },

    'MOVP' :  { ('mem',  'preg') : 'ppp00aa1 100011mm oooooooo',
                ('preg', 'mem')  : 'ppp00aa1 100110mm oooooooo' },

    'LPD' :   { ()               : 'ppp00aa1 100010mm oooooooo' },
    
    'LPDI' :  { ()               : 'ppp10001 00001000 oooooooo oooooooo ssssssss ssssssss' },

    'ADD' :   { ('mem',  'reg')  : 'rrr00aa1 101000mm oooooooo',
                ('reg',  'mem')  : 'rrr00aa1 110100mm oooooooo' },

    'ADDB' :  { ('mem',  'reg')  : 'rrr00aa0 101000mm oooooooo',
                ('reg',  'mem')  : 'rrr00aa0 110100mm oooooooo' },

    'ADDI' :  { ('i16',  'reg')  : 'rrr10001 00100000 iiiiiiii iiiiiiii',
                ('i16',  'mem')  : '00010aa1 110000mm oooooooo iiiiiiii iiiiiiii' },

    'ADDBI' : { ('i8',   'reg')  : 'rrr01000 00100000 iiiiiiii',
                ('i8',   'mem')  : '00001aa0 110000mm oooooooo iiiiiiii' },

    'INC' :   { ('reg',)         : 'rrr00000 00111000',
                ('mem',)         : '00000aa1 111010mm oooooooo' },

    'INCB' :  { ()               : '00000aa0 111010mm oooooooo' },

    'DEC' :   { ('reg',)         : 'rrr00000 00111100',
                ('mem',)         : '00000aa1 111011mm oooooooo' },

    'DECB' :  { ()               : '00000aa0 111011mm oooooooo' },

    'AND' :   { ('mem',  'reg')  : 'rrr00aa1 101010mm oooooooo',
                ('reg',  'mem')  : 'rrr00aa1 110110mm oooooooo' },

    'ANDB' :  { ('mem',  'reg')  : 'rrr00aa0 101010mm oooooooo',
                ('reg',  'mem')  : 'rrr00aa0 110110mm oooooooo' },

    'ANDI' :  { ('i16',  'reg')  : 'rrr10001 00101000 iiiiiiii iiiiiiii',
                ('i16',  'mem')  : '00010aa1 110010mm oooooooo iiiiiiii iiiiiiii' },

    'ANDBI' : { ('i8',   'reg')  : 'rrr01000 00101000 iiiiiiii',
                ('i8',   'mem')  : '00001aa0 110010mm oooooooo iiiiiiii' },

    'OR' :    { ('mem',  'reg')  : 'rrr00aa1 101001mm oooooooo',
                ('reg',  'mem')  : 'rrr00aa1 110101mm oooooooo' },

    'ORB' :   { ('mem',  'reg')  : 'rrr00aa0 101001mm oooooooo',
                ('reg',  'mem')  : 'rrr00aa0 110101mm oooooooo' },

    'ORI' :   { ('i16',  'reg')  : 'rrr10001 00100100 iiiiiiii iiiiiiii',
                ('i16',  'mem')  : '00010aa1 110001mm oooooooo iiiiiiii iiiiiiii' },

    'ORBI' :  { ('i8',   'reg')  : 'rrr01000 00100100 iiiiiiii',
                ('i8',   'mem')  : '00001aa0 110001mm oooooooo iiiiiiii' },

    'NOT' :   { ('reg',)         : 'rrr00000 00101100',
                ('mem',)         : '00000aa1 110111mm oooooooo',
                ('mem',  'reg')  : 'rrr00aa1 101011mm oooooooo' },

    'NOTB' :  { ('mem',)         : '00000aa0 110111mm oooooooo',
                ('mem',  'reg')  : 'rrr00aa0 101011mm oooooooo' },

    'SETB' :  { ()               : 'bbb00aa0 111101mm oooooooo' },

    'CLR' :   { ()               : 'bbb00aa0 111110mm oooooooo' },

    'CALL' :  { ()               : '10001aa1 100111mm oooooooo dddddddd' },

    'LCALL' : { ()               : '10010aa1 100111mm oooooooo dddddddd dddddddd' },

    'JMP'   : { ()               : '10001000 00100000 dddddddd' },

    'LJMP'  : { ()               : '10010001 00100000 dddddddd dddddddd' },
    
    'JZ'    : { ('lab',  'reg')  : 'rrr01000 01000100 dddddddd',
                ('lab',  'mem')  : '00001aa1 111001mm oooooooo dddddddd' },

    'LJZ'   : { ('lab',  'reg')  : 'rrr10000 01000100 dddddddd dddddddd',
                ('lab',  'mem')  : '00010aa1 111001mm oooooooo dddddddd dddddddd' },

    'JZB'   : { ()               : '00001aa0 111001mm oooooooo dddddddd' },

    'LJZB'  : { ()               : '00010aa0 111001mm oooooooo dddddddd dddddddd' },

    'JNZ'   : { ('lab',  'reg')  : 'rrr01000 01000000 dddddddd',
                ('lab',  'mem')  : '00001aa1 111000mm oooooooo dddddddd' },

    'LJNZ'  : { ('lab',  'reg')  : 'rrr10000 01000000 dddddddd dddddddd',
                ('lab',  'mem')  : '00010aa1 111000mm oooooooo dddddddd dddddddd' },

    'JNZB'  : { ()               : '00001aa0 111000mm oooooooo dddddddd' },

    'LJNZB' : { ()               : '00010aa0 111000mm oooooooo dddddddd dddddddd' },

    'JMCE'  : { ()               : '00001aa0 101100mm oooooooo dddddddd' },

    'LJMCE' : { ()               : '00010aa0 101100mm oooooooo dddddddd dddddddd' },

    'JMCNE' : { ()               : '00001aa0 101101mm oooooooo dddddddd' },

    'LJMCNE': { ()               : '00010aa0 101101mm oooooooo dddddddd dddddddd' },

    'JBT'   : { ()               : 'bbb01aa0 101111mm oooooooo dddddddd' },

    'LJBT'  : { ()               : 'bbb10aa0 101111mm oooooooo dddddddd dddddddd' },

    'JNBT'  : { ()               : 'bbb01aa0 101110mm oooooooo dddddddd' },

    'LJNBT' : { ()               : 'bbb10aa0 101110mm oooooooo dddddddd dddddddd' },

    'TSL'   : { ()               : '00011aa0 100101mm oooooooo dddddddd dddddddd' },

    'WID'   : { ()               : '1sd00000 00000000' },

    'XFER'  : { ()               : '01100000 00000000' },

    'SINTR' : { ()               : '01000000 00000000' },

    'HLT'   : { ()               : '00100000 01001000' },

    'NOP'   : { ()               : '00000000 00000000' }
}


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
        b, m, f = byte_parse(byte, second_flag)
        bits.append(b)
        mask.append(m)
        for k in f:
            if k not in fields:
                fields[k] = [0x00] * (i+1)
            fields[k].append(f[k])
        i += 1
    for k in fields:
        if len(fields[k]) < i:
            fields[k] += [0x00] * (i - len(fields[k]))
    return bits, mask, fields


def opcode_init():
    for mnem, details in inst_set.items():
        for form, encoding in details.items():
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
    for i in range(min(len(inst), len(op.fields[f]))):
        for j in reversed(range(8)):
            if op.fields[f][i] & (1 << j):
                v = (v << 1) | ((inst[i] >> j) & 1)
    return v
    

def opcode_match(fw, pc):
    opcode = fw[pc+1] & 0xfc
    if opcode in inst_by_opcode:
        for op in inst_by_opcode[opcode]:
            for i in range(len(op.bits)):
                if fw[pc+i] & op.mask[i] != op.bits[i] & op.mask[i]:
                    continue
                length = len(op.bits)
                if 'a' in op.fields:
                    a = extract_field(fw[pc:pc+length], op, 'a')
                    if a != 1:
                        length -= 1 # no 8-bit offset field
                return length, op
    return 2, None  # XXX only guessing length - maybe guess better based on
                    # fields of first byte?


def disassemble(fw, pc):
    inst = fw[pc:pc+2]
    length, op = opcode_match(fw, pc)
    if op is None:
        return length, "??? %02x %02x" % (inst[0], inst[1])
    return length, op.mnem

def main(fn):
    opcode_init()
    opcode_table_print()

    with open(fn, 'rb') as f:
        fw = bytearray(f.read())

    pc = 0
    while pc < len(fw) - 2:
        (length, dis) = disassemble(fw, pc)
        print("%04x: %s" % (pc, dis))
        pc += length


if __name__ == '__main__':
    main('147931.bin')
