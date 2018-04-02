#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  tools/win_syscall.py
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
import code
import json
import os
import platform
import sys
sys.path.insert(1, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import mayhem.exploit.windows as windows

def main():
	parser = argparse.ArgumentParser(description='win_syscall: Windows native system call utility', conflict_handler='resolve')
	parser.add_argument('-f', '--file', dest='syscall_file', action='store', type=argparse.FileType('r'), help='json file to load syscall data from')
	parser.add_argument('-o', '--os', dest='os_name', action='store', help='the windows version to load syscall data for')
	arguments = parser.parse_args()

	if platform.system() != 'Windows':
		print("[-] Incompatible platform '{0}'".format(platform.system()))
		return

	syscall_map = None
	if arguments.syscall_file and arguments.os_name:
		syscall_map = json.load(arguments.syscall_file)
		if not arguments.os_name in syscall_map:
			print("[-] Invalid os name '{0}'".format(arguments.os_name))
			return
		syscall_map = [arguments.os_name]
		print("[+] Loaded {0} syscall symbols".format(len(syscall_map)))
	syscall = windows.WindowsX86Syscall(syscall_map)
	print("[+] Allocated syscall stub at 0x{0:08x}".format(syscall.address))

	console = code.InteractiveConsole(dict(syscall=syscall))
	console.interact()

if __name__ == '__main__':
	main()
