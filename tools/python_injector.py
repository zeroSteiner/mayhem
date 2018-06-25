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

import argparse
import ctypes
import ctypes.util
import os
import sys
sys.path.insert(1, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mayhem import utilities
from mayhem.datatypes import windows as wintypes
from mayhem.proc import ProcessError
from mayhem.proc.windows import WindowsProcess
from mayhem.windll import kernel32 as m_k32

INVALID_HANDLE_VALUE =  -1
PIPE_ACCESS_DUPLEX =    0x00000003
PIPE_TYPE_MESSAGE =     0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_NAME = 'mayhem'

INJECTION_STUB_TEMPLATE = r"""
import codecs
import ctypes
import runpy
import sys
import traceback

pipe = open(r'\\.\\pipe\{pipe_name}', 'w+b', 0)
sys.argv = ['']
sys.stderr = sys.stdout = codecs.getwriter('utf-8')(pipe)

try:
    runpy.run_path('{path}', run_name='__mayhem__')
except:
    traceback.print_exc()
pipe.close()

ctypes.windll.kernel32.ExitThread(0)
"""
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_IO_PENDING = 997
ERROR_PIPE_CONNECTED = 535
ERROR_BROKEN_PIPE = 109

def _escape(path):
	escaped_path = path.replace('\\', '\\\\')
	return escaped_path.replace('\'', '\\\'')

def _wait_overlapped_io(overlapped, timeout=-1):
	result = m_k32.WaitForSingleObject(overlapped.hEvent, timeout) == WAIT_OBJECT_0
	m_k32.CloseHandle(overlapped.hEvent)
	return result

class NamedPipeClient(object):
	def __init__(self, handle, buffer_size=4096):
		self.handle = handle
		self.buffer_size = buffer_size

	def read(self):
		ctarray = (ctypes.c_byte * self.buffer_size)()
		bytes_read = wintypes.DWORD(0)

		overlapped = wintypes.OVERLAPPED()
		overlapped.hEvent = m_k32.CreateEventW(None, True, False, None)
		if m_k32.ReadFile(self.handle, ctypes.byref(ctarray), self.buffer_size, ctypes.byref(bytes_read), ctypes.byref(overlapped)):
			return utilities.ctarray_to_bytes(ctarray)[:bytes_read.value]
		error = m_k32.GetLastError()
		if error == ERROR_IO_PENDING and _wait_overlapped_io(overlapped):
			return utilities.ctarray_to_bytes(ctarray)[:overlapped.InternalHigh]
		if error == ERROR_BROKEN_PIPE:
			return None
		raise ctypes.WinError()

	def close(self):
		m_k32.CloseHandle(self.handle)

	@classmethod
	def from_named_pipe(cls, name, buffer_size=4096, default_timeout=100, max_instances=5):
		handle = m_k32.CreateNamedPipeW(
			'\\\\.\\pipe\\' + name,                     # _In_     LPCTSTR               lpName
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,  # _In_     DWORD                 dwOpenMode
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,  # _In_     DWORD                 dwPipeMode
			max_instances,                              # _In_     DWORD                 nMaxInstances
			buffer_size,                                # _In_     DWORD                 nInBufferSize
			buffer_size,                                # _In_     DWORD                 nOutBufferSize
			default_timeout,                            # _In_     DWORD                 nDefaultTimeout
			None                                        # _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
		)
		if handle == INVALID_HANDLE_VALUE:
			raise ctypes.WinError()

		success = lambda: cls(handle, buffer_size=buffer_size)
		overlapped = wintypes.OVERLAPPED()
		overlapped.hEvent = m_k32.CreateEventW(None, True, False, None)
		if m_k32.ConnectNamedPipe(handle, ctypes.byref(overlapped)):
			m_k32.CloseHandle(overlapped.hEvent)
			return success()
		error = m_k32.GetLastError()
		if error == ERROR_IO_PENDING and _wait_overlapped_io(overlapped, default_timeout):
			m_k32.CloseHandle(overlapped.hEvent)
			return success()
		m_k32.CloseHandle(overlapped.hEvent)
		if error == ERROR_PIPE_CONNECTED:
			return success()
		m_k32.CloseHandle(handle)
		raise ctypes.WinError()

def main():
	parser = argparse.ArgumentParser(description='python_injector: inject python code into a process', conflict_handler='resolve')
	parser.add_argument('script_path', action='store', help='python script to inject into the process')
	parser.add_argument('pid', action='store', type=int, help='process to inject into')
	parser.epilog = 'The __name__ variable will be set to "__mayhem__".'
	arguments = parser.parse_args()

	if not sys.platform.startswith('win'):
		print('[-] This tool is only available on Windows')
		return

	# get a handle the the process
	try:
		process_h = WindowsProcess(pid=arguments.pid)
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
	local_handle = m_k32.GetModuleHandleW(python_lib)
	py_initialize_ex = python_lib_h + (m_k32.GetProcAddress(local_handle, b'Py_InitializeEx') - local_handle)
	py_run_simple_string = python_lib_h + (m_k32.GetProcAddress(local_handle, b'PyRun_SimpleString') - local_handle)
	print('[*] Resolved addresses:')
	print("  - Py_InitializeEx:    0x{0:08x}".format(py_initialize_ex))
	print("  - PyRun_SimpleString: 0x{0:08x}".format(py_run_simple_string))

	# call remote functions to initialize and run via remote threads
	thread_h = process_h.start_thread(py_initialize_ex, 0)
	process_h.join_thread(thread_h)
	print('[*] Initialized Python in the host process')

	print("[*] Waiting for client to connect on \\\\.\\pipe\\{0}".format(PIPE_NAME))
	injection_stub = INJECTION_STUB_TEMPLATE
	injection_stub = injection_stub.format(
		path=_escape(os.path.abspath(arguments.script_path)),
		pipe_name=PIPE_NAME
	)
	injection_stub = injection_stub.encode('utf-8') + b'\x00'

	alloced_addr = process_h.allocate(size=utilities.align_up(len(injection_stub)), permissions='PAGE_READWRITE')
	process_h.write_memory(alloced_addr, injection_stub)
	thread_h = process_h.start_thread(py_run_simple_string, alloced_addr)
	client = NamedPipeClient.from_named_pipe(PIPE_NAME)
	print('[*] Client connected on named pipe')
	while True:
		message = client.read()
		if message is None:
			break
		sys.stdout.write(message.decode('utf-8'))
	client.close()
	process_h.join_thread(thread_h)
	process_h.close()

if __name__ == '__main__':
	main()
