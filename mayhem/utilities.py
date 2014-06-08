#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  mayhem/utilities.py
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
	"""
	Check if the architecture specified in *arch* is 32-bit.

	:param str arch: The value to check.
	:rtype: bool
	"""
	return bool(arch.lower() in ['i386', 'i686', 'x86'])

def architecture_is_64bit(arch):
	"""
	Check if the architecture specified in *arch* is 64-bit.

	:param str arch: The value to check.
	:rtype: bool
	"""
	return bool(arch.lower() in ['amd64', 'x86_64'])

def align_down(number, alignment=16):
	"""
	Subtract from *number* so it is divisible by *alignment*.

	:param int number: The value to decrease.
	:param int alignment: The value to make *number* divisible by.
	:return: The modified value.
	:rtype: int
	"""
	return number - (number % alignment)

def align_up(number, alignment=16):
	"""
	Add to *number* so it is divisible by *alignment*.

	:param int number: The value to increase.
	:param int alignment: The value to make *number* divisible by.
	:return: The modified value.
	:rtype: int
	"""
	if (number % alignment):
		return number + (alignment - (number % alignment))
	else:
		return number

def eval_number(number):
	"""
	Evaluate a numerical expressions in different string formats indicating
	base.

	:param str number: The string to evaluate.
	:return: The converted value.
	:rtype: int
	"""
	if number.startswith('0b'):
		return int(number[2:], 2)
	elif number.startswith('0x'):
		return int(number[2:], 16)
	elif number.startswith('0'):
		return int(number, 8)
	elif number.isdigit():
		return int(number)
	else:
		raise ValueError('unknown numerical value: \'' + number + '\'')

def print_hexdump(data, address=0):
	"""
	Print data to stdout in a visually pleasant hex format.

	:param str data: The data to print.
	:param int address: The base address to display for *data*.
	"""
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
			if i + j < l:
				sys.stdout.write("{0:02X} ".format(ord(x[i + j])))
			else:
				sys.stdout.write("   ")
			if j % 16 == 7:
				sys.stdout.write(" ")
		sys.stdout.write("  ")
		r = ""
		for j in x[i:i + 16]:
			j = ord(j)
			if (j < 32) or (j >= 127):
				r = r + "."
			else:
				r = r + chr(j)
		sys.stdout.write(r + os.linesep)
		i += 16
	sys.stdout.flush()

def struct_pack(structure):
	"""
	Pack a :py:class:`ctypes.Structure` object and convert it to a packed string.

	:param structure: The structure instance to convert
	:type structure: :py:class:`ctypes.Structure`
	:return: The structure instance converted to a string.
	:rtype: str
	"""
	return ctypes.string_at(ctypes.byref(structure), ctypes.sizeof(structure))

def struct_unpack(structure, raw_data):
	"""
	Convert *raw_data* to an instance of *structure*.

	:param structure: The structure that describes *raw_data*.
	:type structure: :py:class:`ctypes.Structure`
	:param str raw_data: The binary string which contains the structures data.
	:return: A new instance of *structure*.
	:rtype: :py:class:`ctypes.Structure`
	"""
	if not isinstance(structure, ctypes.Structure):
		structure = structure()
	ctypes.memmove(ctypes.byref(structure), raw_data, ctypes.sizeof(structure))
	return structure
