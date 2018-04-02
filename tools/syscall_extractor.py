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

import argparse
import collections
import copy
import json
import os
import struct
import sys
sys.path.insert(1, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pefile
import tabulate

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
	if len(stub) < 18:
		return None
	if not stub.startswith(b'\xb8'):
		return None
	if stub[5:12] == b'\xba\x00\x03\xfe\x7f\xff\x12' and stub[12] in (b'\xc2', b'\xc3'):
		return struct.unpack('I', stub[1:5])[0]
	if stub[5:18] == b'\xe8\x03\x00\x00\x00\xc2\x08\x00\x8b\xd4\x0f\x34\xc3':
		return struct.unpack('I', stub[1:5])[0]
	return None

def get_x86_64_syscall(stub):
	if len(stub) != 11:
		return None
	if not stub.startswith(b'\x4c\x8b\xd1\xb8'):
		return None
	if not stub.endswith(b'\x0f\x05\xc3'):
		return None
	return struct.unpack('I', stub[4:8])[0]

def extract_syscalls(file_name):
	pe = pefile.PE(file_name)
	file_version = pe_format_version_str(pe)
	print("[*] Scanning {0} ({1})".format(file_name, file_version))
	if not pe.is_dll:
		print('[-] File is not a DLL')
		return
	machine = pe.NT_HEADERS.FILE_HEADER.Machine
	if machine == IMAGE_FILE_MACHINE_I386:
		extractor = get_i386_syscall
		stub_length = 18
	elif machine == IMAGE_FILE_MACHINE_X86_64:
		extractor = get_x86_64_syscall
		stub_length = 11
	else:
		print("[-] Not a supported machine type (0x{0:02x})".format(machine))
		return
	arch_name = ('i386' if machine == IMAGE_FILE_MACHINE_I386 else 'x86-64')
	print('[*] Detected file as: ' + arch_name)
	syscalls = []
	pe.parse_data_directories()
	if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
		return
	for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
		stub = pe.get_data(exp.address, stub_length)
		syscall_number = extractor(stub)
		if syscall_number is None:
			continue
		syscalls.append(Syscall(syscall_number, pe.OPTIONAL_HEADER.ImageBase + exp.address, exp.name, exp.ordinal))
	metadata = dict(file_name=os.path.basename(file_name), version=file_version, architecture=arch_name)
	return dict(metadata=metadata, syscalls=syscalls)

def main():
	output_formats = copy.copy(tabulate.tabulate_formats)
	output_formats.append('json')
	parser = argparse.ArgumentParser(description='syscall_extractor: Extract syscalls from a Windows PE file', conflict_handler='resolve')
	parser.add_argument('-f', '--format', dest='output_format', default='simple', choices=output_formats, help='output format')
	parser.add_argument('pe_files', nargs='+', help='pe files to extract syscall numbers from')
	args = parser.parse_args()

	parsed_files = []
	for pe_file in args.pe_files:
		parsed_files.append(extract_syscalls(os.path.abspath(pe_file)))
	parsed_files = list(pe_file for pe_file in parsed_files if pe_file)
	print("[+] Found {0:,} syscalls".format(sum(len(pe_file['syscalls']) for pe_file in parsed_files)))

	if args.output_format == 'json':
		print(json.dumps(parsed_files, sort_keys=True, indent=2, separators=(',', ': ')))
	else:
		syscalls = []
		for pe_file in parsed_files:
			syscalls.extend(pe_file['syscalls'])
		syscalls = ((syscall[0], hex(syscall[1]), syscall[2], syscall[3]) for syscall in syscalls)
		print(tabulate.tabulate(syscalls, headers=('Number', 'RVA', 'Name', 'Ordinal'), tablefmt=args.output_format))
	return 0

if __name__ == '__main__':
	sys.exit(main())
