#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  tools/memgrep.py
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

import argparse
import os
import sys
sys.path.insert(1, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mayhem.proc import ProcessError
from mayhem.proc.native import NativeProcess
from mayhem.utilities import align_down, align_up, print_hexdump

def main():
	parser = argparse.ArgumentParser(description='memgrep: memory search utility', conflict_handler='resolve')
	parser.add_argument('pid', action='store', type=int, help='process to control')
	parser.add_argument('search_data', action='store', help='data to search for')
	parser.add_argument('-e', '--encoding', default='utf-8', help='the encoding of search_data')
	arguments = parser.parse_args()

	search_data = arguments.search_data.encode(arguments.encoding)
	if len(search_data) < 4:
		print('[-] searching for less than 4 bytes will yield too many results')
		return 0

	process_h = NativeProcess(pid=arguments.pid)
	print("[*] searching {0} regions of memory".format(len(process_h.maps)))

	num_matches = 0
	num_skips = 0
	num_errors = 0

	for mem_region in process_h.maps.values():
		print("[*] searching 0x{0:08x} - 0x{1:08x} (0x{2:08x} bytes)".format(mem_region.addr_low, mem_region.addr_high, mem_region.size))
		if not mem_region.is_readable:
			print("[-] skipped unreadable region at 0x{0:08x}".format(mem_region.addr_low))
			num_skips += 1
			continue
		try:
			data = process_h.read_memory(mem_region.addr_low, mem_region.size)
		except ProcessError as error:
			print("[-] encountered {0} while reading at 0x{1:08x}".format(error.__class__.__name__, mem_region.addr_low))
			num_errors += 1
			continue
		cursor = data.find(search_data)
		while cursor != -1:
			data_slice = data[align_down(cursor):align_up(cursor + len(search_data))]
			low_addr = align_down(mem_region.addr_low + align_down(cursor))
			print("[+] found match at 0x{0:08x}".format(mem_region.addr_low + cursor))
			num_matches += 1
			print_hexdump(data_slice, low_addr)
			cursor = data.find(search_data, cursor + 1)

	process_h.close()
	print("[*] summary - matches: {0} errors: {1} skipped regions: {2}".format(num_matches, num_errors, num_skips))

if __name__ == '__main__':
	main()
