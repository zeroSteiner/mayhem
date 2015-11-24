#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  tools/syringe.py
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
import sys
sys.path.append('..')

from mayhem.proc import ProcessError
from mayhem.proc.native import NativeProcess
from mayhem.utilities import align_up, architecture_is_32bit, architecture_is_64bit

def main():
	parser = argparse.ArgumentParser(
		description='syringe: library & shellcode injection utility',
		conflict_handler='resolve',
		epilog='The PID argument can be specified as -1 to inject into the context of the syringe process.'
	)
	parser.add_argument('-l', '--load', dest='library', action='store', help='load the library in the target process')
	shellcode_group = parser.add_mutually_exclusive_group()
	shellcode_group.add_argument('-i', '--inject', dest='shellcode', action='store', help='inject code into the process')
	shellcode_group.add_argument('-f', '--inject-file', dest='shellcode_file', type=argparse.FileType('rb'), help='inject code from a file into the process')
	parser.add_argument('-d', '--decode', dest='decode', action='store', choices=('b64', 'hex', 'raw'), default='b64', help='decode the shellcode prior to execution')
	parser.add_argument('pid', action='store', type=int, help='process to control')
	arguments = parser.parse_args()

	try:
		process_h = NativeProcess(pid=arguments.pid)
	except ProcessError as error:
		print("[-] {0}".format(error.msg))
		return
	print("[+] Opened a handle to pid: {0}".format(arguments.pid))

	if arguments.library:
		try:
			lib_h = process_h.load_library(arguments.library)
		except ProcessError as error:
			print("[-] {0}".format(error.msg))
		else:
			print("[+] Loaded {0} with handle 0x{1:08x}".format(arguments.library, lib_h))

	if arguments.shellcode or arguments.shellcode_file:
		if arguments.shellcode:
			shellcode = arguments.shellcode
		else:
			shellcode = arguments.shellcode_file.read()
			arguments.shellcode_file.close()
		if arguments.decode == 'b64':
			shellcode = shellcode.decode('base64')
		elif arguments.decode == 'hex':
			shellcode = shellcode.decode('hex')
		stub = "" # no stub by default
		if architecture_is_32bit(process_h.arch):
			stub = "\x8b\x44\x24\x04" # mov eax,[esp+4]
		elif architecture_is_64bit(process_h.arch):
			stub = "\x48\x8b\x44\x24\x08" # mov rax,[rsp+8]

		shellcode_sz = align_up(len(stub + shellcode), 1024)
		address = process_h.allocate(size=shellcode_sz, address=0)
		print("[+] Allocated {0} bytes at 0x{1:08x}".format(shellcode_sz, address))
		process_h.protect(address, size=shellcode_sz)
		process_h.write_memory(address, stub + shellcode)
		thread_id = process_h.start_thread(address, (address + len(stub)))
		print("[+] Started thread at 0x{0:08x}".format(address))
		print("[*] Waiting for thread to complete...")
		try:
			process_h.join_thread(thread_id)
			print("[+] Thread completed")
		except ProcessError as err:
			print("[-] {0} {1}".format(err.__class__.__name__, err.msg))

	process_h.close()

if __name__ == '__main__':
	main()
