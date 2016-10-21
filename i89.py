#!/usr/bin/python3
# Intel 8089 definitions
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

from collections import namedtuple

class I89:

    __Op = namedtuple('Op', ['mnem', 'operands', 'bits', 'mask', 'fields'])

    # Follows Intel ASM89 assembler convention for operand ordering.
    # The destination operand precedes the source operand(s).
    __inst_set = [
        # JMP is ADDBI with rrr=100 (TP), put earlier than ADDBI in table
        ['jmp',    [[('jmp',)         , '10001000 00100000 jjjjjjjj']]],

        # LJMP is ADDI with rrr=100 (TP), put earlier than ADDI in table
        ['ljmp',   [[('jmp',)         , '10010001 00100000 jjjjjjjj jjjjjjjj']]],
    
        ['mov',    [[('reg',  'memo') , 'rrr00011 100000mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa1 100000mm'],
                    [('memo', 'reg')  , 'rrr00011 100001mm oooooooo'],
                    [('mem',  'reg')  , 'rrr00aa1 100001mm'],
                    [('memo2','memo') , '00000011 100100mm oooooooo/00000011 110011mm oooooooo'],
                    [('mem2', 'memo') , '00000011 100100mm oooooooo/00000aa1 110011mm'],
                    [('memo2','mem')  , '00000aa1 100100mm/00000011 110011mm oooooooo'],
                    [('mem2', 'mem')  , '00000aa1 100100mm/00000aa1 110011mm']]],

        ['movb',   [[('reg',  'memo') , 'rrr00010 100000mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa0 100000mm'],
                    [('memo', 'reg')  , 'rrr00010 100001mm oooooooo'],
                    [('mem',  'reg')  , 'rrr00aa0 100001mm'],
                    [('memo2','memo') , '00000010 100100mm oooooooo/00000010 110011mm oooooooo'],
                    [('mem2', 'memo') , '00000010 100100mm oooooooo/00000aa0 110011mm'],
                    [('memo2','mem')  , '00000aa0 100100mm/00000010 110011mm oooooooo'],
                    [('mem2', 'mem')  , '00000aa0 100100mm/00000aa0 110011mm']]],

        ['movbi',  [[('reg',  'imm')  , 'rrr01000 00110000 iiiiiiii'],
                    [('memo', 'imm')  , '00001010 010011mm oooooooo iiiiiiii'],
                    [('mem',  'imm')  , '00001aa0 010011mm iiiiiiii']]],

        ['movi',   [[('reg',  'imm')  , 'rrr10001 00110000 iiiiiiii iiiiiiii'],
                    [('memo', 'imm')  , '00010011 010011mm oooooooo iiiiiiii iiiiiiii'],
                    [('mem',  'imm')  , '00010aa1 010011mm iiiiiiii iiiiiiii']]],

        ['movp',   [[('preg', 'memo') , 'ppp00011 100011mm oooooooo'],
                    [('preg', 'mem')  , 'ppp00aa1 100011mm'],
                    [('memo', 'preg') , 'ppp00011 100110mm oooooooo'],
                    [('mem',  'preg') , 'ppp00aa1 100110mm']]],

        ['lpd' ,   [[('preg', 'memo',), 'ppp00011 100010mm oooooooo'],
                    [('preg', 'mem',) , 'ppp00aa1 100010mm']]],
    
        ['lpdi',   [[('preg', 'i32')  , 'ppp10001 00001000 iiiiiiii iiiiiiii ssssssss ssssssss']]],

        ['add',    [[('reg',  'memo') , 'rrr00011 101000mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa1 101000mm'],
                    [('memo', 'reg')  , 'rrr00011 110100mm oooooooo'],
                    [('mem',  'reg')  , 'rrr00aa1 110100mm']]],

        # ADDB encodings in 8089 assembler manual p3-12 have W bit wrong
        ['addb',   [[('reg',  'memo') , 'rrr00010 101000mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa0 101000mm'],
                    [('memo', 'reg')  , 'rrr00010 110100mm oooooooo'],
                    [('mem',  'reg')  , 'rrr00aa0 110100mm']]],

        ['addi',   [[('reg',  'imm')  , 'rrr10001 00100000 iiiiiiii iiiiiiii'],
                    [('memo', 'imm')  , '00010011 110000mm oooooooo iiiiiiii iiiiiiii'],
                    [('mem',  'imm')  , '00010aa1 110000mm iiiiiiii iiiiiiii']]],

        ['addbi',  [[('reg',  'imm')  , 'rrr01000 00100000 iiiiiiii'],
                    [('memo', 'imm')  , '00001010 110000mm oooooooo iiiiiiii'],
                    [('mem',  'imm')  , '00001aa0 110000mm iiiiiiii']]],

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

        ['and',    [[('reg',  'memo') , 'rrr00011 101010mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa1 101010mm'],
                    [('memo', 'reg')  , 'rrr00011 110110mm oooooooo'],
                    [('mem',  'reg')  , 'rrr00aa1 110110mm']]],

        ['andb',   [[('reg',  'memo') , 'rrr00010 101010mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa0 101010mm'],
                    [('memo', 'reg')  , 'rrr00010 110110mm oooooooo'],
                    [('mem',  'reg')  , 'rrr00aa0 110110mm']]],

        ['andi',   [[('reg',  'imm')  , 'rrr10001 00101000 iiiiiiii iiiiiiii'],
                    [('memo', 'imm')  , '00010011 110010mm oooooooo iiiiiiii iiiiiiii'],
                    [('mem',  'imm')  , '00010aa1 110010mm iiiiiiii iiiiiiii']]],

        ['andbi',  [[('reg',  'imm')  , 'rrr01000 00101000 iiiiiiii'],
                    [('memo', 'imm')  , '00001010 110010mm oooooooo iiiiiiii'],
                    [('mem',  'imm')  , '00001aa0 110010mm iiiiiiii']]],

        ['or',     [[('reg',  'memo') , 'rrr00011 101001mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa1 101001mm'],
                    [('memo', 'reg')  , 'rrr00011 110101mm oooooooo'],
                    [('mem',  'reg')  , 'rrr00aa1 110101mm']]],

        ['orb',    [[('reg',  'memo') , 'rrr00010 101001mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa0 101001mm'],
                    [('memo', 'reg')  , 'rrr00010 110101mm oooooooo'],
                    [('mem',  'reg')  , 'rrr00aa0 110101mm']]],

        ['ori',    [[('reg',  'imm')  , 'rrr10001 00100100 iiiiiiii iiiiiiii'],
                    [('memo', 'imm')  , '00010011 110001mm oooooooo iiiiiiii iiiiiiii'],
                    [('mem',  'imm')  , '00010aa1 110001mm iiiiiiii iiiiiiii']]],

        ['orbi',   [[('reg',  'imm')  , 'rrr01000 00100100 iiiiiiii'],
                    [('memo', 'imm')  , '00001010 110001mm oooooooo iiiiiiii'],
                    [('mem',  'imm')  , '00001aa0 110001mm iiiiiiii']]],

        ['not',    [[('reg',)         , 'rrr00000 00101100'],
                    [('memo',)        , '00000011 110111mm oooooooo'],
                    [('mem',)         , '00000aa1 110111mm'],
                    [('reg',  'memo') , 'rrr00011 101011mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa1 101011mm']]],

        ['notb',   [[('memo',)        , '00000010 110111mm oooooooo'],
                    [('mem',)         , '00000aa0 110111mm'],
                    [('reg',  'memo') , 'rrr00010 101011mm oooooooo'],
                    [('reg',  'mem')  , 'rrr00aa0 101011mm']]],

        ['setb',   [[('memo', 'bit')  , 'bbb00010 111101mm oooooooo'],
                    [('mem',  'bit')  , 'bbb00aa0 111101mm']]],

        ['clr',    [[('memo', 'bit')  , 'bbb00010 111110mm oooooooo'],
                    [('mem',  'bit')  , 'bbb00aa0 111110mm']]],

        ['call',   [[('memo', 'jmp')  , '10001011 100111mm oooooooo jjjjjjjj'],
                    [('mem',  'jmp')  , '10001aa1 100111mm jjjjjjjj']]],

        ['lcall',  [[('memo', 'jmp')  , '10010011 100111mm oooooooo jjjjjjjj jjjjjjjj'],
                    [('mem',  'jmp')  , '10010aa1 100111mm jjjjjjjj jjjjjjjj']]],

        ['jz',     [[('reg',  'jmp')  , 'rrr01000 01000100 jjjjjjjj'],
                    [('memo', 'jmp')  , '00001011 111001mm oooooooo jjjjjjjj'],
                    [('mem',  'jmp')  , '00001aa1 111001mm jjjjjjjj']]],

        ['ljz',    [[('reg',  'jmp')  , 'rrr10000 01000100 jjjjjjjj jjjjjjjj'],
                    [('memo', 'jmp')  , '00010011 111001mm oooooooo jjjjjjjj jjjjjjjj'],
                    [('mem',  'jmp')  , '00010aa1 111001mm jjjjjjjj jjjjjjjj']]],

        ['jzb',    [[('memo', 'jmp')  , '00001010 111001mm oooooooo jjjjjjjj'],
                    [('mem',  'jmp')  , '00001aa0 111001mm jjjjjjjj']]],

        ['ljzb',   [[('memo', 'jmp')  , '00010010 111001mm oooooooo jjjjjjjj jjjjjjjj'],
                    [('mem',  'jmp')  , '00010aa0 111001mm jjjjjjjj jjjjjjjj']]],

        ['jnz',    [[('reg',  'jmp')  , 'rrr01000 01000000 jjjjjjjj'],
                    [('memo', 'jmp')  , '00001011 111000mm oooooooo jjjjjjjj'],
                    [('mem',  'jmp')  , '00001aa1 111000mm jjjjjjjj']]],

        ['ljnz',   [[('reg',  'jmp')  , 'rrr10000 01000000 jjjjjjjj jjjjjjjj'],
                    [('memo', 'jmp')  , '00010011 111000mm oooooooo jjjjjjjj jjjjjjjj'],
                    [('mem',  'jmp')  , '00010aa1 111000mm jjjjjjjj jjjjjjjj']]],

        ['jnzb',   [[('memo', 'jmp')  , '00001010 111000mm oooooooo jjjjjjjj'],
                    [('mem',  'jmp')  , '00001aa0 111000mm jjjjjjjj']]],

        ['ljnzb',  [[('memo', 'jmp')  , '00010010 111000mm oooooooo jjjjjjjj jjjjjjjj'],
                    [('mem',  'jmp')  , '00010aa0 111000mm jjjjjjjj jjjjjjjj']]],

        ['jmce',   [[('memo', 'jmp')  , '00001010 101100mm oooooooo jjjjjjjj'],
                    [('mem',  'jmp')  , '00001aa0 101100mm jjjjjjjj']]],

        ['ljmce',  [[('memo', 'jmp')  , '00010010 101100mm oooooooo jjjjjjjj jjjjjjjj'],
                    [('mem',  'jmp')  , '00010aa0 101100mm jjjjjjjj jjjjjjjj']]],

        ['jmcne',  [[('memo', 'jmp')  , '00001010 101101mm oooooooo jjjjjjjj'],
                    [('mem',  'jmp')  , '00001aa0 101101mm jjjjjjjj']]],

        ['ljmcne', [[('memo', 'jmp')  , '00010010 101101mm oooooooo jjjjjjjj jjjjjjjj'],
                    [('mem',  'jmp')  , '00010aa0 101101mm jjjjjjjj jjjjjjjj']]],

        ['jbt',    [[('memo', 'bit', 'jmp'), 'bbb01010 101111mm oooooooo jjjjjjjj'],
                    [('mem',  'bit', 'jmp'), 'bbb01aa0 101111mm jjjjjjjj']]],

        ['ljbt',   [[('memo', 'bit', 'jmp'), 'bbb10010 101111mm oooooooo jjjjjjjj jjjjjjjj'],
                    [('mem',  'bit', 'jmp'), 'bbb10aa0 101111mm jjjjjjjj jjjjjjjj']]],

        ['jnbt',   [[('memo', 'bit', 'jmp'), 'bbb01010 101110mm oooooooo jjjjjjjj'],
                    [('mem',  'bit', 'jmp'), 'bbb01aa0 101110mm jjjjjjjj']]],

        ['ljnbt',  [[('memo', 'bit', 'jmp'), 'bbb10010 101110mm oooooooo jjjjjjjj jjjjjjjj'],
                    [('mem',  'bit', 'jmp'), 'bbb10aa0 101110mm jjjjjjjj jjjjjjjj']]],

        ['tsl',    [[('memo', 'imm', 'jmp'), '00011010 100101mm oooooooo iiiiiiii jjjjjjjj'],
                    [('mem',  'imm', 'jmp'), '00011aa0 100101mm iiiiiiii jjjjjjjj']]],

        ['wid',    [[('wids', 'widd') , '1sd00000 00000000']]],

        ['xfer',   [[()               , '01100000 00000000']]],

        ['sintr',  [[()               , '01000000 00000000']]],

        ['hlt',    [[()               , '00100000 01001000']]],

        ['nop',    [[()               , '00000000 00000000']]]
    ]

    # GA, GB, GC, TP are 20-bit pointer registers w/ tag bit,
    #                    legal for r or p field
    #        tag = 0 for 20-bit system address, 1 for 16-bit local address
    #        LPD, LPDI set tag to zero (system)
    #        MOV, MOVB, MOVI, MOVBI sign extend to 20 bits and set tag to
    #                    one (local)
    #        MOVP stores, loads full pointer including tag bit
    # BC, IX, CC, MC are 16-bit registers, only legal for r field
    reg = [ 'ga', 'gb', 'gc', 'bc', 'tp', 'ix', 'cc', 'mc']

    m_reg = ['ga', 'gb', 'gc', 'pp']

    @staticmethod
    def __byte_parse(bs, second_flag):
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

    @staticmethod
    def __encoding_parse(encoding):
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
            b, m, f = I89.__byte_parse(byte, second_flag)
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


    def __opcode_init(self):
        for mnem, details in self.__inst_set:
            for operands, encoding in details:
                bits, mask, fields = self.__encoding_parse(encoding)
                opcode = bits[1] & 0xfc
                if opcode not in self.__inst_by_opcode:
                    self.__inst_by_opcode[opcode] = []
                self.__inst_by_opcode[opcode].append(self.__Op(mnem, operands, bits, mask, fields))
                #print(inst, operands, "%02x" % opcode)


    def _opcode_table_print(self):
        for opcode in sorted(self.__inst_by_opcode.keys()):
            for mnem, operands, bits, mask, fields in self.__inst_by_opcode[opcode]:
                print("%02x:" % opcode, mnem, operands, bits, mask, fields)



    @staticmethod
    def __extract_field(inst, op, f):
        width = 0
        v = 0
        for i in reversed(range(min(len(inst), len(op.fields[f])))):
            for j in reversed(range(8)):
                if op.fields[f][i] & (1 << j):
                    v = (v << 1) | ((inst[i] >> j) & 1)
                    width += 1
        if width == 8 and v > 127 and (f == 'i' or f == 'j'):
            v += (65536 - 256)
        return v


    def __opcode_match(self, fw, pc, op):
        fields = { }

        l = len(op.bits)
        inst = fw[pc:pc+l]

        for i in range(l):
            if inst[i] & op.mask[i] != op.bits[i] & op.mask[i]:
                return None, fields

        for f in op.fields:
            fields[f] = self.__extract_field(inst, op, f)

        # 'j' jump target field is relative to address of next instruction
        if 'j' in op.fields:
            fields['j'] = (fields['j'] + pc + l) & 0xffff

        return len(op.bits), fields


    class BadInstruction(Exception):
        pass


    def opcode_search(self, fw, pc):
        opcode = fw[pc+1] & 0xfc
        if opcode not in self.__inst_by_opcode:
            #print('addr %04x: opcode of inst %02x %02x not in table' % (pc, fw[pc], fw[pc+1]))
            raise I89.BadInstruction
        for op in self.__inst_by_opcode[opcode]:
            l, fields = self.__opcode_match(fw, pc, op)
            if l is not None:
                return l, op, fields
        #print('addr %04x: inst %02x %02x not matched' % (pc, fw[pc], fw[pc+1]))
        raise I89.BadInstruction

    @staticmethod
    def ihex(v):
        s = '%xh' % v
        if s[0].isalpha():
            s = '0' + s
        return s

    def __dis_mem_operand(self, fields, pos = 1):
        suffix = ['', '', '2']
        mode   = fields['a' + suffix[pos]]
        mreg   = fields['m' + suffix[pos]]
        del fields['a' + suffix[pos]], fields ['m' + suffix[pos]]
        s = '[' + self.m_reg[mreg]
        if mode == 0:
            return  s + ']'
        elif mode == 1:
            offset = fields['o' + suffix[pos]]
            del fields['o' + suffix[pos]]
            return s + '].' + self.ihex(offset)
        elif mode == 2:
            return s + '+ix]'
        else:  # mode == 3
            return s + '+ix+]'
            

    def disassemble_inst(self, fw, pc, symtab_by_value = {}, disassemble_operands = True):
        try:
            length, op, fields = self.opcode_search(fw, pc)
        except I89.BadInstruction:
            return 1, 'db      ', '%s' % self.ihex(fw[pc]), {}

        s = '%-6s' % op.mnem
        operands = []

        if disassemble_operands:
            ftemp = fields.copy()
            for operand in op.operands:
                if operand == 'jmp':
                    target = ftemp['j']
                    del ftemp['j']
                    if target in symtab_by_value:
                        value = symtab_by_value[target]
                    else:
                        value = self.ihex(target)
                elif operand == 'reg':
                    value = self.reg[ftemp['r']]
                    del ftemp['r']
                elif operand == 'preg':
                    p = ftemp['p']
                    del ftemp['p']
                    value = self.reg[p]
                    if value not in ['ga', 'gb', 'gc', 'tp']:
                        value += '_bad'
                elif operand == 'bit':
                    value = '%d' % ftemp['b']
                    del ftemp['b']
                elif operand == 'memo':
                    ftemp ['a'] = 1
                    value = self.__dis_mem_operand(ftemp)
                elif operand == 'mem':
                    value = self.__dis_mem_operand(ftemp)
                elif operand == 'memo2':
                    ftemp ['a2'] = 1
                    value = self.__dis_mem_operand(ftemp, 2)
                elif operand == 'mem2':
                    value = self.__dis_mem_operand(ftemp, 2)
                elif operand == 'imm':
                    value = self.ihex(ftemp['i'])
                    del ftemp['i']
                elif operand == 'i32':
                    value = self.ihex(ftemp['s']) + ':' + self.ihex(ftemp['i'])
                    del ftemp['s'], ftemp['i']
                elif operand == 'wids':
                    value = str([8, 16][ftemp['s']])
                    del ftemp['s']
                elif operand == 'widd':
                    value = str([8, 16][ftemp['d']])
                    del ftemp['d']
                else:
                    raise NotImplementedError('operand type ' + operand)
                operands.append(value)
            if ftemp:
                raise NotImplementedError('leftover fields: ' + str(ftemp))

        return length, s, ','.join(operands), fields

    def __init__(self):
        self.__inst_by_opcode = { }
        self.__opcode_init()

if __name__ == '__main__':
    i89 = I89()
    i89._opcode_table_print()
