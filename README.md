# i89 - Assembler and Disassembler for Intel 8089 I/O processor

Copyright 2016 Eric Smith <spacewar@gmail.com>

i89 development is hosted at the
[i89 Github repository](https://github.com/brouhaha/i89/).

## Introduction

From roughly 1980 to 1985, Intel made the
[8089](https://en.wikipedia.org/wiki/Intel_8089),
an I/O processor intended for use with the 8086 and 8088
microprocessors. The 8089 is in a sense a fancy two-channel DMA
controller, and is intended to be used in a manner similar to
mainframe data channels.  The 8089 has an instruction set optimized
for data transfers, and is not suited to general-purpose computation.
The 8089 never saw widespread deployment, but was used in some Intel
Multibus disk controllers, including the iSBC 215 and iSBC 220.

Contrary to a claim in the Wikipedia article, the 8089 is not a
coprocessor. While it is designed such that it can be tightly coupled
(electrically) with an 8086 or 8088, each channel of the 8089 executes
its own instruction using its own program counter ("TP" register), and
does not monitor or interpret any instructions from the 8086/8088
program.

Intel offered the ASM89 assembler, which ran on the
[ISIS-II operating system](https://en.wikipedia.org/wiki/ISIS_(operating_system))
on the MDS 800, Series II, III, IV, and iPDS development
systems, in conjunction with the LINK86 linker and LOC86 locator. It
is now rather difficult to obtain a copy of ASM89.

i89 provides limited cross-development capabilities for the 8089,
including a disassembler and assembler, which should work on any host
platform that provides
[Python](https://www.python.org/) 3.4 or later.

i89 was developed to support reverse-engineering and modification of
the firmware of the Intel iSBC 215 family of disk controllers, and
consequently some features that would be of use for general purpose
8089 support are not present. Limitations are described in sections
below.

The examples of command lines given below do not show the path to the
executable, nor, for operating systems that require it, the explicit
specification of the Python interpreter.


## Disassembler usage:

The disi89 disassembler can accept either raw binary input files
(default), or
[Intel hex format](https://en.wikipedia.org/wiki/Intel_HEX)
input files if the "`--hex`" option is given
on the command line.  If other file formats are needed, the srec_cat
utility of [srecord](http://srecord.sourceforge.net/) is recommended.

If multiple input files are provided, they are interleaved. This is
particularly useful with exactly two input files, in which case the
first file provides the even bytes, and the second file provides the
odd bytes.

The "`-l`" option causes the disassembler output to be generated in
a format similar to an assembler listing file, with the address and
object code for each disassembled instruction to the left of the
disassembled instruction.

Examples:

* `disi89 -l --hex u87.hex u88.hex >isbc215.dis`

  Disassembles from two Intel hex files, interleaving them, and
  generates output in the form of a listing.

* `disi89 isbc215.bin >isbc215.asm`

  Disassembles from a single binary file, and
  generates output in the form of assembly source.

## Assembler usage:

The assembler takes as a command line argument, the filename of the
source file to be assembled.  The "`-o` *hexfile*" and "`-l` *listfile*"
options may be used to designate the object code and listing output
files, respectively; if not provided, the output is not generated.

The assembler generates output in Intel hex format; if other file
formats are needed, including raw binary, the srec_cat utilitiy of
[srecord](http://srecord.sourceforge.net/) is recommended.

Example:

* `asi89 isbc215.asm -o isbc215.hex -l isbc215.lst`

  Assembles a source file, producing an Intel hex object file and
  a listing file


## Limitations of disi89 disassembler:

* only handles 16-bit address space


## Limitations of asi89 assembler:

* error checking is poor; source code errors cause a Python exception
* only handles 16-bit address space
* only the db, dw, ds, equ, and struc/ends directives are supported
* there is no support for use of a linker; only absolute
  hex output is provided
* listing file format doesn't match ASM89
* no symbol cross-reference is provided


## Enhancements of asi89 assembler relative to Intel ASM89 documentation:

* added `FILL <addr>, <value>` directive, which fills space between current
  location and `<addr>` with the byte `<value>`
* expression evaluation supports parenthesis, multiplication, division,
  bitwise and, or, and negation, and logical shifts.


## License information for pyparsing.py:

i89 includes pyparsing.py by Paul T. McGuire. See the top of the
pyparsing.py source file for copyright and licensing of that file.


## License information for files other than pyparsing.py:

This program is free software: you can redistribute it and/or modify
it under the terms of version 3 of the GNU General Public License
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
