#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  tools/python_injector.py
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
import ctypes.util
import os
import sys
sys.path.insert(1, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from argparse import ArgumentParser

from mayhem.proc import ProcessError
from mayhem.proc.native import NativeProcess
from mayhem.utilities import align_up, architecture_is_32bit, architecture_is_64bit

def main():
	parser = ArgumentParser(description='python_injector: inject python code into a process', conflict_handler='resolve')
	parser.add_argument('shellcode', action='store', help='python code to inject into the process')
	parser.add_argument('pid', action='store', type=int, help='process to inject into')
	arguments = parser.parse_args()

	if not sys.platform.startswith('win'):
		print('[-] This tool is only available on Windows')
		return

	# get a handle the the process
	try:
		process_h = NativeProcess(pid=arguments.pid)
	except ProcessError as error:
		print("[-] {0}".format(error.msg))
		return
	print("[+] Opened a handle to pid: {0}".format(arguments.pid))

	# find and inject the python library
	python_lib = "python{0}{1}.dll".format(sys.version_info.major, sys.version_info.minor)
	python_lib = ctypes.util.find_library(python_lib)
	if python_lib:
		print("[*] Found Python library at: {0}".format(python_lib))
	else:
		print('[-] Failed to find the Python library')
		return

	print('[*] Injecting Python into the process...')
	try:
		python_lib_h = process_h.load_library(python_lib)
	except ProcessError as error:
		print("[-] {0}".format(error.msg))
		return
	else:
		print("[+] Loaded {0} with handle 0x{1:08x}".format(python_lib, python_lib_h))

	# resolve the necessary functions
	k32 = ctypes.windll.kernel32
	local_handle = k32.GetModuleHandleA(python_lib)
	py_initialize_ex = python_lib_h + (k32.GetProcAddress(local_handle, 'Py_InitializeEx') - local_handle)
	py_run_simple_string = python_lib_h + (k32.GetProcAddress(local_handle, 'PyRun_SimpleString') - local_handle)
	print('[*] Resolved address:')
	print("  - Py_InitializeEx:    0x{0:08x}".format(py_initialize_ex))
	print("  - PyRun_SimpleString: 0x{0:08x}".format(py_run_simple_string))

	# call remote functions to initialize and run via remote threads
	thread_h = process_h.start_thread(py_initialize_ex, 0)
	process_h.join_thread(thread_h)

	shellcode = arguments.shellcode
	shellcode_addr = process_h.allocate(size=align_up(len(shellcode)), permissions='PAGE_READWRITE')
	process_h.write_memory(shellcode_addr, shellcode)
	thread_h = process_h.start_thread(py_run_simple_string, shellcode_addr)
	process_h.join_thread(thread_h)

	process_h.close()

if __name__ == '__main__':
	main()
