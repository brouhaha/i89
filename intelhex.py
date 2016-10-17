#!/usr/bin/python3
# Intel hex file reader
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

class IntelHex:

    class BadChecksum(Exception):
        pass

    class UnknownRecordType(Exception):
        pass
    
    class Discontiguous(Exception):
        pass
    
    def __init__(self, f):
        if type(f) is str:
            self.f = open(f, 'rb')
        else:
            self.f = f
        self.b = []
        self.rn = 0
        self.expected_addr = None
        self.ba_index = 0
        self.ba = bytearray(65536)

    def get_bytes(self, count):
        s = self.f.read(2*count)
        if len(s) != 2*count:
            raise EOFError()
        return bytearray([int(s[2*i:2*i+2], 16) for i in range(count)])

    def get_ui8(self):
        return self.get_bytes(1)[0]
    
    def get_ui16(self):
        b = self.get_bytes(2)
        return (b[0] << 8) + b[1]
        

    def get_colon(self):
        while True:
            b = self.f.read(1)
            if len(b) == 0:
                raise EOFError()
            if b[0] == 0x3a:
                return
        


    def get_record(self):
        self.get_colon()
        self.rn += 1
        data_length = self.get_ui8()
        addr = self.get_ui16()
        rec_type = self.get_ui8()
        data = self.get_bytes(data_length)
        expected_checksum = (((data_length +
                               ((addr >> 8) & 0xff) +
                               (addr & 0xff) +
                               rec_type +
                               sum(data)) ^ 0xff) + 1) & 0xff
        checksum = self.get_ui8()
        if checksum != expected_checksum:
            raise IntelHex.BadChecksum('Bad checksum for record #%d' % self.rn)
        if rec_type == 0x00:  # data
            if self.expected_addr is not None and self.expected_addr != addr:
                raise IntelHex.Discontiguous('Unexpected address for data record #%d' % self.rn)
            self.ba[self.ba_index:self.ba_index+data_length] = data
            self.expected_addr = addr + data_length
            self.ba_index += data_length

        elif rec_type == 0x01:  # end of file
            raise EOFError()  # end of file
        else:
            raise IntelHex.UnknownRecordType('Unknown record type %02x for record #%d', (rec_type, self.rn))
        return True


    def read(self):
        l = []
        try:
            while True:
                self.get_record()
        except EOFError as e:
            pass

        return self.ba

