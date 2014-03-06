#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/proc/utils.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import ctypes
import os
import sys
from struct import pack, unpack

def architecture_is_32bit(arch):
	return bool(arch in ['i386', 'i686', 'x86'])

def architecture_is_64bit(arch):
	return bool(arch in ['AMD64', 'x86_64'])

def align_down(number, alignment = 16):
	return number - (number % alignment)

def align_up(number, alignment = 16):
	if (number % alignment):
		return number + (alignment - (number % alignment))
	else:
		return number

def make_call(*args):
	if len(args) == 2:
		offset = args[1] - args[0]
	else:
		offset = args[0]
	return '\xe8' + (pack('I', offset - 5))

def make_jmp(*args):
	if len(args) == 2:
		offset = args[1] - args[0]
	else:
		offset = args[0]
	return '\xe9' + (pack('i', offset - 5))

def print_hexdump(data, address = 0):
	x = str(data)
	l = len(x)
	i = 0
	address_format_string = "{0:04x}    "
	if (address + len(data)) > 0xffff:
		address_format_string = "{0:08x}    "
		if (address + len(data)) > 0xffffffff:
			address_format_string = "{0:016x}    "
	while i < l:
		sys.stdout.write(address_format_string.format(address + i))
		for j in range(16):
			if i+j < l:
				sys.stdout.write("%02X " % ord(x[i+j]))
			else:
				sys.stdout.write("   ")
			if j%16 == 7:
				sys.stdout.write(" ")
		sys.stdout.write("  ")
		r = ""
		for j in x[i:i+16]:
			j = ord(j)
			if (j < 32) or (j >= 127):
				r = r + "."
			else:
				r = r + chr(j)
		sys.stdout.write(r + os.linesep)
		i += 16
	sys.stdout.flush()

def struct_pack(structure):
	return ctypes.string_at(ctypes.byref(structure), ctypes.sizeof(structure))

def struct_unpack(structure, raw_data):
	if not isinstance(structure, ctypes.Structure):
		structure = structure()
	ctypes.memmove(ctypes.byref(structure), raw_data, ctypes.sizeof(structure))
	return structure
