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

from enum import Enum


OperandClass = Enum('OperandClass', ['reg',
                                     'numeric',
                                     'mem_ref',
                                     'mem_ref_offset'])


# operand type
# defined outside the I89 class and with very short name because
# it will be used a lot in the __inst_set class attribute of I89
OT = Enum('OT', ['reg',          # general register (all 8)
                 'preg',         # limited subset of reg
                 'jmp',          # branch target
                 'imm',          # immediate value, 8 or 16 bit
                 'i32',          # LPDI segment, offset
                 'bit',          # bit number, 0..7
                 'wids', 'widd', # 8 or 16
                 'mem',  'mem2', # mem ref w/o offset
                 'memo', 'memo2' # mem ref w/ offset
                ])


def bit_count(v):
    return bin(v).count('1')


class BitField:
    def __init__(self, byte_count = 0):
        self.width = 0  # width of the field within the instruction
        self.mask = bytearray(byte_count)

    def __repr__(self):
        return 'BitField(width = %d, mask = %s' % (self.width, str(self.mask))

    def append(self, mask_byte):
        self.mask.append(mask_byte)
        self.width += bit_count(mask_byte)

    def pad_length(self, length):
        if len(self.mask) < length:
            self.mask += bytearray(length - len(self.mask))

    def insert(self, bits, value):
        assert isinstance(value, int)
        for i in range(len(bits)):
            for b in [1 << j for j in range(8)]:
                if self.mask[i] & b:
                    if value & 1:
                        bits[i] |= b
                    value >>= 1
        #assert value == 0  # XXX causes negative 8-bit immediates to fail
        

# An instruction form is a variant of an instruction that takes
# specific operand types.
class Form:
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
            b, m, f = Form.__byte_parse(byte, second_flag)
            if ep_debug:
                print('b: ', b, 'm:', m, 'f:', f)
            bits.append(b)
            mask.append(m)
            for k in f:
                if k not in fields:
                    fields[k] = BitField(len(bits)-1)
                fields[k].append(f[k])
        if ep_debug:
            print('fields before:', fields)
        for k in fields:
            fields[k].pad_length(len(bits))
        if ep_debug:
            print('fields after:', fields)
        return bits, mask, fields

    def __init__(self, operands, encoding):
        self.operands = operands
        self.encoding = encoding
        self.bits, self.mask, self.fields = Form.__encoding_parse(encoding)

    def __len__(self):
        return len(self.bits)

    def insert_fields(self, fields):
        bits = bytearray(self.bits)
        assert set(self.fields.keys()) == set(fields.keys())
        for k, bitfield in self.fields.items():
            bitfield.insert(bits, fields[k])
        return bits
        


# An instruction has a single mnemonic, but possibly multiple
# forms.
class Inst:
    def __init__(self, mnem, *forms):
        self.mnem = mnem
        self.forms = forms


class I89:
    class UnknownMnemonic(Exception):
        def __init__(self, mnem):
            super().__init__('unknown mnemonic "%s"' % mnem)

    class NoMatchingForm(Exception):
        def __init__(self):
            super().__init__('no matching form')

    class OperandOutOfRange(Exception):
        def __init__(self):
            super().__init__('operand out of range')


    # Follows Intel ASM89 assembler convention for operand ordering.
    # The destination operand precedes the source operand(s).
    __inst_set = [
        # JMP is ADDBI with rrr=100 (TP), put earlier than ADDBI in table
        Inst('jmp',   Form((OT.jmp,)          , '10001000 00100000 jjjjjjjj')),

        # LJMP is ADDI with rrr=100 (TP), put earlier than ADDI in table
        Inst('ljmp',  Form((OT.jmp,)          , '10010001 00100000 jjjjjjjj jjjjjjjj')),

        Inst('mov',   Form((OT.reg,  OT.memo) , 'rrr00011 100000mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa1 100000mm'),
                      Form((OT.memo, OT.reg)  , 'rrr00011 100001mm oooooooo'),
                      Form((OT.mem,  OT.reg)  , 'rrr00aa1 100001mm'),
                      Form((OT.memo2,OT.memo) , '00000011 100100mm oooooooo/00000011 110011mm oooooooo'),
                      Form((OT.mem2, OT.memo) , '00000011 100100mm oooooooo/00000aa1 110011mm'),
                      Form((OT.memo2,OT.mem)  , '00000aa1 100100mm/00000011 110011mm oooooooo'),
                      Form((OT.mem2, OT.mem)  , '00000aa1 100100mm/00000aa1 110011mm')),

        Inst('movb',  Form((OT.reg,  OT.memo) , 'rrr00010 100000mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa0 100000mm'),
                      Form((OT.memo, OT.reg)  , 'rrr00010 100001mm oooooooo'),
                      Form((OT.mem,  OT.reg)  , 'rrr00aa0 100001mm'),
                      Form((OT.memo2,OT.memo) , '00000010 100100mm oooooooo/00000010 110011mm oooooooo'),
                      Form((OT.mem2, OT.memo) , '00000010 100100mm oooooooo/00000aa0 110011mm'),
                      Form((OT.memo2,OT.mem)  , '00000aa0 100100mm/00000010 110011mm oooooooo'),
                      Form((OT.mem2, OT.mem)  , '00000aa0 100100mm/00000aa0 110011mm')),

        Inst('movbi', Form((OT.reg,  OT.imm)  , 'rrr01000 00110000 iiiiiiii'),
                      Form((OT.memo, OT.imm)  , '00001010 010011mm oooooooo iiiiiiii'),
                      Form((OT.mem,  OT.imm)  , '00001aa0 010011mm iiiiiiii')),

        Inst('movi',  Form((OT.reg,  OT.imm)  , 'rrr10001 00110000 iiiiiiii iiiiiiii'),
                      Form((OT.memo, OT.imm)  , '00010011 010011mm oooooooo iiiiiiii iiiiiiii'),
                      Form((OT.mem,  OT.imm)  , '00010aa1 010011mm iiiiiiii iiiiiiii')),

        Inst('movp',  Form((OT.preg, OT.memo) , 'ppp00011 100011mm oooooooo'),
                      Form((OT.preg, OT.mem)  , 'ppp00aa1 100011mm'),
                      Form((OT.memo, OT.preg) , 'ppp00011 100110mm oooooooo'),
                      Form((OT.mem,  OT.preg) , 'ppp00aa1 100110mm')),

        Inst('lpd' ,  Form((OT.preg, OT.memo,), 'ppp00011 100010mm oooooooo'),
                      Form((OT.preg, OT.mem,) , 'ppp00aa1 100010mm')),
    
        Inst('lpdi',  Form((OT.preg, OT.i32)  , 'ppp10001 00001000 iiiiiiii iiiiiiii ssssssss ssssssss')),

        Inst('add',   Form((OT.reg,  OT.memo) , 'rrr00011 101000mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa1 101000mm'),
                      Form((OT.memo, OT.reg)  , 'rrr00011 110100mm oooooooo'),
                      Form((OT.mem,  OT.reg)  , 'rrr00aa1 110100mm')),

        # ADDB encodings in 8089 assembler manual p3-12 have W bit wrong
        Inst('addb',  Form((OT.reg,  OT.memo) , 'rrr00010 101000mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa0 101000mm'),
                      Form((OT.memo, OT.reg)  , 'rrr00010 110100mm oooooooo'),
                      Form((OT.mem,  OT.reg)  , 'rrr00aa0 110100mm')),

        Inst('addi',  Form((OT.reg,  OT.imm)  , 'rrr10001 00100000 iiiiiiii iiiiiiii'),
                      Form((OT.memo, OT.imm)  , '00010011 110000mm oooooooo iiiiiiii iiiiiiii'),
                      Form((OT.mem,  OT.imm)  , '00010aa1 110000mm iiiiiiii iiiiiiii')),

        Inst('addbi', Form((OT.reg,  OT.imm)  , 'rrr01000 00100000 iiiiiiii'),
                      Form((OT.memo, OT.imm)  , '00001010 110000mm oooooooo iiiiiiii'),
                      Form((OT.mem,  OT.imm)  , '00001aa0 110000mm iiiiiiii')),

        Inst('inc',   Form((OT.reg,)          , 'rrr00000 00111000'),
                      Form((OT.memo,)         , '00000011 111010mm oooooooo'),
                      Form((OT.mem,)          , '00000aa1 111010mm')),

        Inst('incb',  Form((OT.memo,)         , '00000010 111010mm oooooooo'),
                      Form((OT.mem,)          , '00000aa0 111010mm')),

        Inst('dec',   Form((OT.reg,)          , 'rrr00000 00111100'),
                      Form((OT.memo,)         , '00000011 111011mm oooooooo'),
                      Form((OT.mem,)          , '00000aa1 111011mm')),

        Inst('decb',  Form((OT.memo,)         , '00000010 111011mm oooooooo'),
                      Form((OT.mem,)          , '00000aa0 111011mm')),

        Inst('and',   Form((OT.reg,  OT.memo) , 'rrr00011 101010mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa1 101010mm'),
                      Form((OT.memo, OT.reg)  , 'rrr00011 110110mm oooooooo'),
                      Form((OT.mem,  OT.reg)  , 'rrr00aa1 110110mm')),

        Inst('andb',  Form((OT.reg,  OT.memo) , 'rrr00010 101010mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa0 101010mm'),
                      Form((OT.memo, OT.reg)  , 'rrr00010 110110mm oooooooo'),
                      Form((OT.mem,  OT.reg)  , 'rrr00aa0 110110mm')),

        Inst('andi',  Form((OT.reg,  OT.imm)  , 'rrr10001 00101000 iiiiiiii iiiiiiii'),
                      Form((OT.memo, OT.imm)  , '00010011 110010mm oooooooo iiiiiiii iiiiiiii'),
                      Form((OT.mem,  OT.imm)  , '00010aa1 110010mm iiiiiiii iiiiiiii')),

        Inst('andbi', Form((OT.reg,  OT.imm)  , 'rrr01000 00101000 iiiiiiii'),
                      Form((OT.memo, OT.imm)  , '00001010 110010mm oooooooo iiiiiiii'),
                      Form((OT.mem,  OT.imm)  , '00001aa0 110010mm iiiiiiii')),

        Inst('or',    Form((OT.reg,  OT.memo) , 'rrr00011 101001mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa1 101001mm'),
                      Form((OT.memo, OT.reg)  , 'rrr00011 110101mm oooooooo'),
                      Form((OT.mem,  OT.reg)  , 'rrr00aa1 110101mm')),

        Inst('orb',   Form((OT.reg,  OT.memo) , 'rrr00010 101001mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa0 101001mm'),
                      Form((OT.memo, OT.reg)  , 'rrr00010 110101mm oooooooo'),
                      Form((OT.mem,  OT.reg)  , 'rrr00aa0 110101mm')),

        Inst('ori',   Form((OT.reg,  OT.imm)  , 'rrr10001 00100100 iiiiiiii iiiiiiii'),
                      Form((OT.memo, OT.imm)  , '00010011 110001mm oooooooo iiiiiiii iiiiiiii'),
                      Form((OT.mem,  OT.imm)  , '00010aa1 110001mm iiiiiiii iiiiiiii')),

        Inst('orbi',  Form((OT.reg,  OT.imm)  , 'rrr01000 00100100 iiiiiiii'),
                      Form((OT.memo, OT.imm)  , '00001010 110001mm oooooooo iiiiiiii'),
                      Form((OT.mem,  OT.imm)  , '00001aa0 110001mm iiiiiiii')),

        Inst('not',   Form((OT.reg,)          , 'rrr00000 00101100'),
                      Form((OT.memo,)         , '00000011 110111mm oooooooo'),
                      Form((OT.mem,)          , '00000aa1 110111mm'),
                      Form((OT.reg,  OT.memo) , 'rrr00011 101011mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa1 101011mm')),

        Inst('notb',  Form((OT.memo,)         , '00000010 110111mm oooooooo'),
                      Form((OT.mem,)          , '00000aa0 110111mm'),
                      Form((OT.reg,  OT.memo) , 'rrr00010 101011mm oooooooo'),
                      Form((OT.reg,  OT.mem)  , 'rrr00aa0 101011mm')),

        Inst('setb',  Form((OT.memo, OT.bit)  , 'bbb00010 111101mm oooooooo'),
                      Form((OT.mem,  OT.bit)  , 'bbb00aa0 111101mm')),

        Inst('clr',   Form((OT.memo, OT.bit)  , 'bbb00010 111110mm oooooooo'),
                      Form((OT.mem,  OT.bit)  , 'bbb00aa0 111110mm')),

        Inst('call',  Form((OT.memo, OT.jmp)  , '10001011 100111mm oooooooo jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '10001aa1 100111mm jjjjjjjj')),

        Inst('lcall', Form((OT.memo, OT.jmp)  , '10010011 100111mm oooooooo jjjjjjjj jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '10010aa1 100111mm jjjjjjjj jjjjjjjj')),

        Inst('jz',    Form((OT.reg,  OT.jmp)  , 'rrr01000 01000100 jjjjjjjj'),
                      Form((OT.memo, OT.jmp)  , '00001011 111001mm oooooooo jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00001aa1 111001mm jjjjjjjj')),

        Inst('ljz',   Form((OT.reg,  OT.jmp)  , 'rrr10000 01000100 jjjjjjjj jjjjjjjj'),
                      Form((OT.memo, OT.jmp)  , '00010011 111001mm oooooooo jjjjjjjj jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00010aa1 111001mm jjjjjjjj jjjjjjjj')),

        Inst('jzb',   Form((OT.memo, OT.jmp)  , '00001010 111001mm oooooooo jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00001aa0 111001mm jjjjjjjj')),

        Inst('ljzb',  Form((OT.memo, OT.jmp)  , '00010010 111001mm oooooooo jjjjjjjj jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00010aa0 111001mm jjjjjjjj jjjjjjjj')),

        Inst('jnz',   Form((OT.reg,  OT.jmp)  , 'rrr01000 01000000 jjjjjjjj'),
                      Form((OT.memo, OT.jmp)  , '00001011 111000mm oooooooo jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00001aa1 111000mm jjjjjjjj')),

        Inst('ljnz',  Form((OT.reg,  OT.jmp)  , 'rrr10000 01000000 jjjjjjjj jjjjjjjj'),
                      Form((OT.memo, OT.jmp)  , '00010011 111000mm oooooooo jjjjjjjj jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00010aa1 111000mm jjjjjjjj jjjjjjjj')),

        Inst('jnzb',  Form((OT.memo, OT.jmp)  , '00001010 111000mm oooooooo jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00001aa0 111000mm jjjjjjjj')),

        Inst('ljnzb', Form((OT.memo, OT.jmp)  , '00010010 111000mm oooooooo jjjjjjjj jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00010aa0 111000mm jjjjjjjj jjjjjjjj')),

        Inst('jmce',  Form((OT.memo, OT.jmp)  , '00001010 101100mm oooooooo jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00001aa0 101100mm jjjjjjjj')),

        Inst('ljmce', Form((OT.memo, OT.jmp)  , '00010010 101100mm oooooooo jjjjjjjj jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00010aa0 101100mm jjjjjjjj jjjjjjjj')),

        Inst('jmcne', Form((OT.memo, OT.jmp)  , '00001010 101101mm oooooooo jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00001aa0 101101mm jjjjjjjj')),

        Inst('ljmcne',Form((OT.memo, OT.jmp)  , '00010010 101101mm oooooooo jjjjjjjj jjjjjjjj'),
                      Form((OT.mem,  OT.jmp)  , '00010aa0 101101mm jjjjjjjj jjjjjjjj')),

        Inst('jbt',   Form((OT.memo, OT.bit, OT.jmp), 'bbb01010 101111mm oooooooo jjjjjjjj'),
                      Form((OT.mem,  OT.bit, OT.jmp), 'bbb01aa0 101111mm jjjjjjjj')),

        Inst('ljbt',  Form((OT.memo, OT.bit, OT.jmp), 'bbb10010 101111mm oooooooo jjjjjjjj jjjjjjjj'),
                      Form((OT.mem,  OT.bit, OT.jmp), 'bbb10aa0 101111mm jjjjjjjj jjjjjjjj')),

        Inst('jnbt',  Form((OT.memo, OT.bit, OT.jmp), 'bbb01010 101110mm oooooooo jjjjjjjj'),
                      Form((OT.mem,  OT.bit, OT.jmp), 'bbb01aa0 101110mm jjjjjjjj')),

        Inst('ljnbt', Form((OT.memo, OT.bit, OT.jmp), 'bbb10010 101110mm oooooooo jjjjjjjj jjjjjjjj'),
                      Form((OT.mem,  OT.bit, OT.jmp), 'bbb10aa0 101110mm jjjjjjjj jjjjjjjj')),

        Inst('tsl',   Form((OT.memo, OT.imm, OT.jmp), '00011010 100101mm oooooooo iiiiiiii jjjjjjjj'),
                      Form((OT.mem,  OT.imm, OT.jmp), '00011aa0 100101mm iiiiiiii jjjjjjjj')),

        Inst('wid',   Form((OT.wids, OT.widd) , '1sd00000 00000000')),

        Inst('xfer',  Form(()                 , '01100000 00000000')),

        Inst('sintr', Form(()                 , '01000000 00000000')),

        Inst('hlt',   Form(()                 , '00100000 01001000')),

        Inst('nop',   Form(()                 , '00000000 00000000'))
    ]

    # GA, GB, GC, TP are 20-bit pointer registers w/ tag bit,
    #                    legal for r or p field
    #        tag = 0 for 20-bit system address, 1 for 16-bit local address
    #        LPD, LPDI set tag to zero (system)
    #        MOV, MOVB, MOVI, MOVBI sign extend to 20 bits and set tag to
    #                    one (local)
    #        MOVP stores, loads full pointer including tag bit
    # BC, IX, CC, MC are 16-bit registers, only legal for rrr field,
    # but not for the ppp field

    # Reg used for rrr or ppp field
    class Reg(Enum):
        ga = 0
        gb = 1
        gc = 2
        bc = 3
        tp = 4
        ix = 5
        cc = 6
        mc = 7
        
    # AReg used for aa field, as part of memory addressing
    class AReg(Enum):
        ga = 0
        gb = 1
        gc = 2
        pp = 3


    class MemoryReference:
        def __init__(self, base_reg, indexed = False, auto_increment = False, offset = None):
            super().__init__()
            if isinstance(base_reg, I89.AReg):
                self.base_reg = base_reg
            else:
                self.base_reg = I89.AReg[base_reg]
            self.offset = offset
            if indexed == False:
                assert auto_increment is False
                if offset is None:
                    self.mode = 0
                else:
                    self.mode = 1
            else:
                assert offset is None
                if auto_increment is False:
                    self.mode = 2
                else:
                    self.mode = 3


    def __opcode_init(self):
        self.__inst_by_opcode = { }
        self.__inst_by_mnemonic = { }
        for inst in self.__inst_set:
            if inst.mnem not in self.__inst_by_mnemonic:
                self.__inst_by_mnemonic[inst.mnem] = inst
            for form in inst.forms:
                #print(inst.mnem, form.operands, form.fields)
                opcode = form.bits[1] & 0xfc
                if opcode not in self.__inst_by_opcode:
                    self.__inst_by_opcode[opcode] = []
                self.__inst_by_opcode[opcode].append(Inst(inst.mnem, form))


    def _opcode_table_print(self):
        for opcode in sorted(self.__inst_by_opcode.keys()):
            for mnem, operands, bits, mask, fields in self.__inst_by_opcode[opcode]:
                print("%02x:" % opcode, mnem, operands, bits, mask, fields)


    @staticmethod
    def __extract_field(inst, fields, f):
        width = 0
        v = 0
        for i in reversed(range(min(len(inst), len(fields[f].mask)))):
            for j in reversed(range(8)):
                if fields[f].mask[i] & (1 << j):
                    v = (v << 1) | ((inst[i] >> j) & 1)
                    width += 1
        if width == 8 and v > 127 and (f == 'i' or f == 'j'):
            v += (65536 - 256)
        return v


    def __opcode_match(self, fw, pc, op):
        form = op.forms[0]
        fields = { }

        l = len(form)
        inst = fw[pc:pc+l]

        for i in range(l):
            if inst[i] & form.mask[i] != form.bits[i] & form.mask[i]:
                return None, fields

        for f in form.fields:
            fields[f] = self.__extract_field(inst, form.fields, f)

        # 'j' jump target field is relative to address of next instruction
        if 'j' in form.fields:
            fields['j'] = (fields['j'] + pc + l) & 0xffff

        return len(form), fields


    class BadInstruction(Exception):
        pass


    def mnemonic_search(self, mnemonic):
        if mnemonic not in self.__inst_by_mnemonic:
            return None
        return self.__inst_by_mnemonic[mnemonic]


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
        s = '[' + self.AReg(mreg).name
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
            for operand in op.forms[0].operands:
                if operand == OT.jmp:
                    target = ftemp['j']
                    del ftemp['j']
                    if target in symtab_by_value:
                        value = symtab_by_value[target]
                    else:
                        value = self.ihex(target)
                elif operand == OT.reg:
                    value = self.Reg(ftemp['r']).name
                    del ftemp['r']
                elif operand == OT.preg:
                    p = ftemp['p']
                    del ftemp['p']
                    value = self.Reg(p).name
                    if value not in ['ga', 'gb', 'gc', 'tp']:
                        value += '_bad'
                elif operand == OT.bit:
                    value = '%d' % ftemp['b']
                    del ftemp['b']
                elif operand == OT.memo:
                    ftemp ['a'] = 1
                    value = self.__dis_mem_operand(ftemp)
                elif operand == OT.mem:
                    value = self.__dis_mem_operand(ftemp)
                elif operand == OT.memo2:
                    ftemp ['a2'] = 1
                    value = self.__dis_mem_operand(ftemp, 2)
                elif operand == OT.mem2:
                    value = self.__dis_mem_operand(ftemp, 2)
                elif operand == OT.imm:
                    value = self.ihex(ftemp['i'])
                    del ftemp['i']
                elif operand == OT.i32:
                    value = self.ihex(ftemp['s']) + ':' + self.ihex(ftemp['i'])
                    del ftemp['s'], ftemp['i']
                elif operand == OT.wids:
                    value = str([8, 16][ftemp['s']])
                    del ftemp['s']
                elif operand == OT.widd:
                    value = str([8, 16][ftemp['d']])
                    del ftemp['d']
                else:
                    raise NotImplementedError('operand type ' + operand)
                operands.append(value)
            if ftemp:
                raise NotImplementedError('leftover fields: ' + str(ftemp))

        return length, s, ','.join(operands), fields


    def __get_operand_class(self, operand):
        if isinstance(operand, I89.MemoryReference):
            if operand.mode == 1:
                return OperandClass.mem_ref_offset
            else:
                return OperandClass.mem_ref
        if isinstance(operand, I89.Reg):
            return OperandClass.reg
        if type(operand) is str and operand in I89.Reg.__members__:
            return OperandClass.reg
        if isinstance(operand, int):
            return OperandClass.numeric
        return None
        

    __operand_class_by_type = { OT.reg:   OperandClass.reg,
                                OT.preg:  OperandClass.reg,
                                OT.jmp:   OperandClass.numeric,
                                OT.imm:   OperandClass.numeric,
                                OT.i32:   OperandClass.numeric,
                                OT.bit:   OperandClass.numeric,
                                OT.wids:  OperandClass.numeric,
                                OT.widd:  OperandClass.numeric,
                                OT.mem:   OperandClass.mem_ref,
                                OT.mem2:  OperandClass.mem_ref,
                                OT.memo:  OperandClass.mem_ref_offset,
                                OT.memo2: OperandClass.mem_ref_offset }


    def __operand_types_match(self, operand_classes, operand_types):
        if len(operand_classes) != len(operand_types):
            return False
        for i in range(len(operand_classes)):
            if self.__operand_class_by_type[operand_types[i]] != operand_classes[i]:
                return False
        return True


    def __check_range(self, value, r):
        if value not in r:
            raise I89.OperandOutOfRange()

    def __width_bit(self, s):
        if s == 8:
            return 0
        elif s == 16:
            return 0
        else:
            raise I89.OperandOutOfRange()

    def __assemble_operand(self, operand, operand_type):
        if operand_type == OT.reg:
            if isinstance(operand, I89.Reg):
                return { 'r': operand.value }
            elif isinstance(operand, str):
                return { 'r': I89.Reg[operand].value }
        elif operand_type == OT.preg:
            if isinstance(operand, I89.Reg):
                return { 'p': operand.value }
            elif isinstance(operand, str):
                return { 'p': I89.Reg[operand].value }
        elif operand_type == OT.jmp:
            return { 'j': operand }  # will need to be converted to PC-relative
        elif operand_type == OT.imm:
            return { 'i': operand }
        elif operand_type == OT.i32:
            return { 'i': operand & 0xffff, 's': operand >> 16}
        elif operand_type == OT.bit:
            self.__check_range(operand, range(0, 8))
            return { 'b': operand }
        elif operand_type == OT.wids:
            return { 's': self.__width_bit(operand) }
        elif operand_type == OT.widd:
            return { 'd': self.__width_bit(operand) }
        elif operand_type == OT.mem:
            return { 'a': operand.mode, 'm': operand.base_reg.value }
        elif operand_type == OT.mem2:
            return { 'a2': operand.mode, 'm2': operand.base_reg.value }
        elif operand_type == OT.memo:
            self.__check_range(operand.offset, range(0, 256))
            return { 'm': operand.base_reg.value, 'o': operand.offset }
        elif operand_type == OT.memo2:
            self.__check_range(operand.offset, range(0, 256))
            return { 'm2': operand.base_reg.value, 'o2': operand.offset }
        else:
            raise Unimplemented("can't assemble operand")


    # pc is used to compute relative branch targets                       
    # inst can be:
    #   Inst (return value from mnemonic_search)
    #   mnemonic (string)
    # each operand can be:
    #   I89.reg or register name (str)   reg, preg
    #   integer                          jmp, imm, i32, bit, wids, widd
    #   I89.MemoryReference              mem, memo, mem2, memo2
    def assemble_instruction(self, pc, inst, operands):
        if not isinstance(inst, Inst):
            inst = self.mnemonic_search(inst)
            if inst is None:
                raise I89.UnknownMnemonic(inst)
        operand_classes = [self.__get_operand_class(operand) for operand in operands]
        for form in inst.forms:
            if self.__operand_types_match(operand_classes, form.operands):
                break
        else:
            raise I89.NoMatchingForm()
        fields = { }
        for i in range(len(operands)):
            fields.update(self.__assemble_operand(operands[i], form.operands[i]))
        if 'j' in fields:
            fields['j'] = (fields['j'] - (pc + len(form))) & 0xffff  # PC relative branch targets
        return form.insert_fields(fields)

    def __init__(self):
        self.__opcode_init()

if __name__ == '__main__':
    i89 = I89()
    i89._opcode_table_print()
