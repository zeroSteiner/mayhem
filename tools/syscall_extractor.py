#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  syscall_extractor.py
#
#  Copyright 2015 Spencer McIntyre <zeroSteiner@gmail.com>
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
#  * Neither the name of the  nor the names of its
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

import collections
import os
import struct
import sys

import pefile
import tabulate

try:
	import jarvis
except ImportError:
	print('missing requirement jarvis, https://gist.github.com/zeroSteiner/7920683')
	os._exit(0)

__version__ = '1.0'

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_X86_64 = 0x8664

Syscall = collections.namedtuple('Syscall', ('number', 'rva', 'name', 'ordinal'))

def pe_format_version_str(pe):
	pe.parse_data_directories()
	if not hasattr(pe, 'VS_FIXEDFILEINFO'):
		return
	version_info = []
	version_info.append((pe.VS_FIXEDFILEINFO.FileVersionMS & 0xffff0000) >> 16)
	version_info.append(pe.VS_FIXEDFILEINFO.FileVersionMS & 0xffff)
	version_info.append((pe.VS_FIXEDFILEINFO.FileVersionLS & 0xffff0000) >> 16)
	version_info.append(pe.VS_FIXEDFILEINFO.FileVersionLS & 0xffff)
	version_info = map(str, version_info)
	return '.'.join(version_info)

def get_i386_syscall(stub):
	if len(stub) != 15:
		return None
	if not stub.startswith('\xb8'):
		return None
	if stub[5:12] != '\xba\x00\x03\xfe\x7f\xff\x12':
		return None
	if not stub[12] in ('\xc2', '\xc3'):
		return None
	return struct.unpack('I', stub[1:5])[0]

def get_x86_64_syscall(stub):
	if len(stub) != 11:
		return None
	if not stub.startswith('\x4c\x8b\xd1\xb8'):
		return None
	if not stub.endswith('\x0f\x05\xc3'):
		return None
	return struct.unpack('I', stub[4:8])[0]

def extract_syscalls(jar, file_name):
	pe = pefile.PE(file_name)
	jar.print_status("scanning {0} ({1})".format(file_name, pe_format_version_str(pe)))
	if not pe.is_dll:
		jar.print_status('file is not a dll')
		return
	machine = pe.NT_HEADERS.FILE_HEADER.Machine
	if machine == IMAGE_FILE_MACHINE_I386:
		extractor = get_i386_syscall
		stub_length = 15
	elif machine == IMAGE_FILE_MACHINE_X86_64:
		extractor = get_x86_64_syscall
		stub_length = 11
	else:
		jar.print_status("not a supported machine type (0x{0:02x})".format(machine))
		return
	jar.vprint_status('detected file as: ' + ('i386' if machine == IMAGE_FILE_MACHINE_I386 else 'x86-64'))
	syscalls = []
	pe.parse_data_directories()
	for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
		stub = pe.get_data(exp.address, stub_length)
		syscall_number = extractor(stub)
		if syscall_number is None:
			continue
		syscalls.append(Syscall(syscall_number, pe.OPTIONAL_HEADER.ImageBase + exp.address, exp.name, exp.ordinal))
	return syscalls

def main():
	jar = jarvis.Jarvis()
	parser = jar.build_argparser('PE File Syscall Extractor', version=__version__)
	parser.add_argument('pe_files', nargs='+', help='pe files to extract syscall numbers from')
	args = parser.parse_args()

	syscalls = []
	for pe_file in args.pe_files:
		syscalls.extend(extract_syscalls(jar, os.path.abspath(pe_file)) or [])
	jar.print_good("found {0:,} syscalls".format(len(syscalls)))
	syscalls = ((syscall[0], hex(syscall[1]), syscall[2], syscall[3]) for syscall in syscalls)
	print(tabulate.tabulate(syscalls, headers=('Number', 'RVA', 'Name', 'Ordinal')))

	return 0

if __name__ == '__main__':
	sys.exit(main())
